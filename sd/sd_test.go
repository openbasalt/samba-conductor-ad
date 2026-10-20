package sd

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-ad/sid"
)

// The fixtures in testdata were produced by Samba's own encoder (the
// Python bindings: samba.descriptor.get_domain_descriptor for the domain
// head, security.descriptor.from_sddl plus ndr_pack for an OU with the
// Reset Password delegation the lab seeds on OU=People), and the .sddl
// files are Samba's as_sddl() of the same bytes. They check this parser
// against an independent encoder.

const (
	domainSID   = "S-1-5-21-2127521184-1604012920-1887927527"
	helpdeskSID = domainSID + "-1105"
	userClass   = "bf967aba-0de6-11d0-a285-00aa003049e2"
	resetPwd    = "00299570-246d-11d0-a768-00aa006e0529"
)

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	h, err := os.ReadFile("testdata/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(h)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// wantSDDL is Samba's rendering without the SACL, which Parse skips.
func wantSDDL(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".sddl")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSpace(string(b))
	if before, _, ok := strings.Cut(s, ")S:"); ok {
		s = before + ")"
	}
	return s
}

func TestSambaFixtures(t *testing.T) {
	for _, name := range []string{"domain_head", "ou_people"} {
		t.Run(name, func(t *testing.T) {
			d, err := Parse(readFixture(t, name))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := d.SDDL(), wantSDDL(t, name); got != want {
				t.Fatalf("SDDL mismatch\n got %s\nwant %s", got, want)
			}
		})
	}
}

func TestDomainHeadFixture(t *testing.T) {
	d, err := Parse(readFixture(t, "domain_head"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Owner.String() != "S-1-5-32-544" || d.Group.String() != "S-1-5-32-544" {
		t.Fatalf("owner %s group %s", d.Owner, d.Group)
	}
	if d.Control&ControlSACLPresent == 0 {
		t.Fatal("the fixture carries a SACL; it must be skipped, not missing")
	}
	if d.DACL == nil || len(d.DACL.ACEs) != 53 {
		t.Fatalf("DACL: %+v", d.DACL)
	}
	writers := map[string]bool{}
	for i := range d.DACL.ACEs {
		a := &d.DACL.ACEs[i]
		if !a.Known {
			t.Fatalf("ACE %d not decoded: %x", i, a.Raw)
		}
		if a.GrantsMoreThanRead() {
			writers[SIDString(a.Trustee)] = true
		}
	}
	// Pre-Windows 2000 (RU) and Everyone (WD) only read; Authenticated
	// Users holds extended rights restricted to an object type.
	for _, s := range []string{"RU", "WD"} {
		if writers[s] {
			t.Errorf("%s should only read", s)
		}
	}
	for _, s := range []string{"BA", "SY", "AU", "PS", domainSID + "-512", domainSID + "-519"} {
		if !writers[s] {
			t.Errorf("%s should hold more than read", s)
		}
	}
}

func TestOUFixture(t *testing.T) {
	d, err := Parse(readFixture(t, "ou_people"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Owner.String() != domainSID+"-512" {
		t.Fatalf("owner %s", d.Owner)
	}
	a := d.DACL.ACEs[0]
	want := ACE{
		Type: AceTypeAccessAllowedObject, Flags: AceFlagContainerInherit | AceFlagInheritOnly,
		Mask: DSControlAccess, Trustee: sid.MustParse(helpdeskSID),
		ObjectType: resetPwd, InheritedObjectType: userClass, Known: true, Raw: a.Raw,
	}
	if !reflect.DeepEqual(a, want) {
		t.Fatalf("got %+v\nwant %+v", a, want)
	}
	if !a.GrantsMoreThanRead() || !a.InheritOnly() || a.Inherited() || !a.IsObject() {
		t.Fatal("flags of the delegation ACE")
	}
	if got := a.SDDL(); got != "(OA;CIIO;CR;"+resetPwd+";"+userClass+";"+helpdeskSID+")" {
		t.Fatalf("ACE SDDL %s", got)
	}
	last := d.DACL.ACEs[len(d.DACL.ACEs)-1]
	if !last.Inherited() || last.GrantsMoreThanRead() || SIDString(last.Trustee) != "RU" {
		t.Fatalf("last ACE %s", last.SDDL())
	}
}

// encode is a test-only encoder of self-relative descriptors. sacl, when
// set, is written verbatim as the SACL.
func encode(d *Descriptor, sacl []byte) []byte {
	out := make([]byte, headerSize)
	out[0] = d.Revision
	binary.LittleEndian.PutUint16(out[2:], d.Control)
	put := func(at int, data []byte) {
		binary.LittleEndian.PutUint32(out[at:], uint32(len(out)))
		out = append(out, data...)
	}
	if !d.Owner.IsZero() {
		put(4, d.Owner.Bytes())
	}
	if !d.Group.IsZero() {
		put(8, d.Group.Bytes())
	}
	if sacl != nil {
		put(12, sacl)
	}
	if d.DACL != nil {
		put(16, encodeACL(d.DACL))
	}
	return out
}

func encodeACL(acl *ACL) []byte {
	var body []byte
	for i := range acl.ACEs {
		body = append(body, encodeACE(&acl.ACEs[i])...)
	}
	h := make([]byte, aclHeaderSize)
	h[0] = acl.Revision
	binary.LittleEndian.PutUint16(h[2:], uint16(aclHeaderSize+len(body)))
	binary.LittleEndian.PutUint16(h[4:], uint16(len(acl.ACEs)))
	return append(h, body...)
}

func encodeACE(a *ACE) []byte {
	if !a.Known {
		return a.Raw
	}
	b := []byte{byte(a.Type), a.Flags, 0, 0}
	b = binary.LittleEndian.AppendUint32(b, a.Mask)
	if a.Type == AceTypeAccessAllowedObject || a.Type == AceTypeAccessDeniedObject {
		var flags uint32
		var guids []byte
		if a.ObjectType != "" {
			flags |= objectTypePresent
			g, _ := sid.ParseGUID(a.ObjectType)
			guids = append(guids, g[:]...)
		}
		if a.InheritedObjectType != "" {
			flags |= inheritedObjectTypePresent
			g, _ := sid.ParseGUID(a.InheritedObjectType)
			guids = append(guids, g[:]...)
		}
		b = binary.LittleEndian.AppendUint32(b, flags)
		b = append(b, guids...)
	}
	b = append(b, a.Trustee.Bytes()...)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

// withoutRaw clears Raw on decoded ACEs, so expected values can be written
// without it.
func withoutRaw(d *Descriptor) *Descriptor {
	if d.DACL == nil {
		return d
	}
	c := *d
	acl := *d.DACL
	acl.ACEs = append([]ACE(nil), acl.ACEs...)
	for i := range acl.ACEs {
		if acl.ACEs[i].Known {
			acl.ACEs[i].Raw = nil
		}
	}
	c.DACL = &acl
	return &c
}

func TestRoundTrip(t *testing.T) {
	da := sid.MustParse(domainSID + "-512")
	hd := sid.MustParse(helpdeskSID)
	sr := ControlSelfRelative
	unknown := []byte{0x11, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0x10, 0x00, 0x30, 0, 0}
	cases := []struct {
		name string
		d    *Descriptor
		sacl []byte
		sddl string
	}{
		{"owner only", &Descriptor{Revision: 1, Control: sr, Owner: da}, nil, "O:" + domainSID + "-512"},
		{"null DACL", &Descriptor{Revision: 1, Control: sr | ControlDACLPresent, Owner: da}, nil,
			"O:" + domainSID + "-512D:NO_ACCESS_CONTROL"},
		{"empty DACL", &Descriptor{Revision: 1, Control: sr | ControlDACLPresent | ControlDACLProtected, Owner: da, Group: da,
			DACL: &ACL{Revision: 4, ACEs: []ACE{}}}, nil, "O:" + domainSID + "-512G:" + domainSID + "-512D:P"},
		{"allow and deny", &Descriptor{Revision: 1, Control: sr | ControlDACLPresent | ControlDACLAutoInherited, Owner: sid.MustParse("S-1-5-32-544"),
			DACL: &ACL{Revision: 2, ACEs: []ACE{
				{Type: AceTypeAccessDenied, Mask: DSDeleteTree | Delete, Trustee: sid.Everyone, Known: true},
				{Type: AceTypeAccessAllowed, Flags: AceFlagContainerInherit, Mask: GenericAll, Trustee: da, Known: true},
				{Type: AceTypeAccessAllowed, Mask: DSList | DSReadProp | ReadControl, Trustee: sid.AuthenticatedUsers, Known: true},
			}}}, nil, "O:BAD:AI(D;;DTSD;;;WD)(A;CI;GA;;;" + domainSID + "-512)(A;;LCRPRC;;;AU)"},
		{"object ACEs", &Descriptor{Revision: 1, Control: sr | ControlDACLPresent,
			DACL: &ACL{Revision: 4, ACEs: []ACE{
				{Type: AceTypeAccessAllowedObject, Flags: AceFlagContainerInherit | AceFlagInheritOnly, Mask: DSWriteProp,
					Trustee: hd, ObjectType: "28630ebf-41d5-11d1-a9c1-0000f80367c1", InheritedObjectType: userClass, Known: true},
				{Type: AceTypeAccessAllowedObject, Mask: DSReadProp, Trustee: sid.MustParse("S-1-5-32-554"),
					InheritedObjectType: userClass, Known: true},
				{Type: AceTypeAccessDeniedObject, Mask: DSControlAccess, Trustee: sid.Everyone, ObjectType: resetPwd, Known: true},
			}}}, nil, "D:(OA;CIIO;WP;28630ebf-41d5-11d1-a9c1-0000f80367c1;" + userClass + ";" + helpdeskSID + ")" +
			"(OA;;RP;;" + userClass + ";RU)(OD;;CR;" + resetPwd + ";;WD)"},
		{"unknown ACE kept raw", &Descriptor{Revision: 1, Control: sr | ControlDACLPresent,
			DACL: &ACL{Revision: 4, ACEs: []ACE{
				{Type: 0x11, Raw: unknown},
				{Type: AceTypeAccessAllowed, Mask: Synchronize | DSList, Trustee: sid.MustParse("S-1-5-18"), Known: true},
			}}}, nil, "D:(" + hex.EncodeToString(unknown) + ")(A;;0x100004;;;SY)"},
		{"SACL skipped", &Descriptor{Revision: 1, Control: sr | ControlDACLPresent | ControlSACLPresent, Owner: da,
			DACL: &ACL{Revision: 4, ACEs: []ACE{{Type: AceTypeAccessAllowed, Mask: GenericRead, Trustee: sid.Everyone, Known: true}}}},
			[]byte{0x04, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00}, // a SACL claiming 5 ACEs in 0 bytes: never read
			"O:" + domainSID + "-512D:(A;;GR;;;WD)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(encode(tc.d, tc.sacl))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(withoutRaw(got), withoutRaw(tc.d)) {
				t.Fatalf("got %+v\nwant %+v", got, tc.d)
			}
			if s := got.SDDL(); s != tc.sddl {
				t.Fatalf("SDDL %s\nwant %s", s, tc.sddl)
			}
		})
	}
}

func TestGrantsMoreThanRead(t *testing.T) {
	cases := []struct {
		typ  AceType
		mask uint32
		want bool
	}{
		{AceTypeAccessAllowed, DSList | DSReadProp | DSListObject | ReadControl | GenericRead, false},
		{AceTypeAccessAllowedObject, DSReadProp, false},
		{AceTypeAccessAllowed, DSWriteProp, true},
		{AceTypeAccessAllowedObject, DSControlAccess, true},
		{AceTypeAccessAllowed, DSSelf, true},
		{AceTypeAccessAllowed, WriteDAC, true},
		{AceTypeAccessAllowed, WriteOwner, true},
		{AceTypeAccessAllowed, GenericAll, true},
		{AceTypeAccessAllowed, GenericWrite, true},
		{AceTypeAccessAllowed, DSCreateChild, true},
		{AceTypeAccessAllowed, Synchronize, true},
		{AceTypeAccessDenied, GenericAll, false},
		{AceTypeAccessDeniedObject, DSControlAccess, false},
	}
	for _, tc := range cases {
		a := ACE{Type: tc.typ, Mask: tc.mask, Known: true}
		if got := a.GrantsMoreThanRead(); got != tc.want {
			t.Errorf("type %d mask %#x: got %v", tc.typ, tc.mask, got)
		}
	}
	unknown := ACE{Type: 0x09, Mask: GenericAll}
	if unknown.GrantsMoreThanRead() {
		t.Error("an undecoded ACE is not an allow entry")
	}
}

func TestMaskString(t *testing.T) {
	// Expected values are Samba's renderings of the same masks.
	for mask, want := range map[uint32]string{
		0xF01FF:    "CCDCLCSWRPWPDTLOCRSDRCWDWO",
		0x10000000: "GA",
		0xE0000000: "GXGWGR",
		0x00100000: "0x100000",
		0x00100004: "0x100004",
		0x000F003F: "CCDCLCSWRPWPSDRCWDWO",
	} {
		if got := MaskString(mask); got != want {
			t.Errorf("%#x: got %s want %s", mask, got, want)
		}
	}
}

func TestMalformed(t *testing.T) {
	ok := readFixture(t, "ou_people")
	// Every truncation of a valid descriptor fails cleanly.
	for n := range len(ok) {
		if _, err := Parse(ok[:n]); err == nil {
			t.Fatalf("truncated to %d bytes: accepted", n)
		} else if !errors.Is(err, ErrMalformed) {
			t.Fatalf("truncated to %d bytes: %v is not ErrMalformed", n, err)
		}
	}
	mutate := func(f func(b []byte)) []byte {
		b := append([]byte(nil), ok...)
		f(b)
		return b
	}
	dacl := int(binary.LittleEndian.Uint32(ok[16:]))
	cases := map[string][]byte{
		"revision 2":           mutate(func(b []byte) { b[0] = 2 }),
		"not self-relative":    mutate(func(b []byte) { b[3] &^= 0x80 }),
		"owner beyond end":     mutate(func(b []byte) { binary.LittleEndian.PutUint32(b[4:], uint32(len(b)-4)) }),
		"owner offset huge":    mutate(func(b []byte) { binary.LittleEndian.PutUint32(b[4:], 0xFFFFFFFF) }),
		"group bad revision":   mutate(func(b []byte) { b[binary.LittleEndian.Uint32(b[8:])] = 7 }),
		"DACL offset huge":     mutate(func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0xFFFFFFF0) }),
		"ACL size too big":     mutate(func(b []byte) { binary.LittleEndian.PutUint16(b[dacl+2:], 0xFFFF) }),
		"ACL size too small":   mutate(func(b []byte) { binary.LittleEndian.PutUint16(b[dacl+2:], 4) }),
		"too many ACEs":        mutate(func(b []byte) { binary.LittleEndian.PutUint16(b[dacl+4:], 0xFFFF) }),
		"ACE size zero":        mutate(func(b []byte) { binary.LittleEndian.PutUint16(b[dacl+8+2:], 0) }),
		"ACE size beyond ACL":  mutate(func(b []byte) { binary.LittleEndian.PutUint16(b[dacl+8+2:], 0x7FFF) }),
		"object ACE too short": mutate(func(b []byte) { binary.LittleEndian.PutUint16(b[dacl+8+2:], 8) }),
		"trustee too long":     mutate(func(b []byte) { b[dacl+8+12+32+1] = 15 }),
	}
	for name, b := range cases {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(readFixture(f, "domain_head"))
	f.Add(readFixture(f, "ou_people"))
	f.Add(encode(&Descriptor{Revision: 1, Control: ControlSelfRelative | ControlDACLPresent}, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := Parse(b)
		if err != nil {
			return
		}
		s := d.SDDL()
		// Re-encoding what was parsed must parse to the same descriptor.
		again, err := Parse(encode(d, nil))
		if err != nil {
			t.Fatalf("re-encoded descriptor rejected: %v", err)
		}
		if again.SDDL() != s {
			t.Fatalf("round trip changed the SDDL\n%s\n%s", s, again.SDDL())
		}
	})
}
