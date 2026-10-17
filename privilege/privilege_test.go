package privilege

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sd"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

const (
	base      = "DC=example,DC=com"
	domainStr = "S-1-5-21-1-2-3"
	userClass = "bf967aba-0de6-11d0-a285-00aa003049e2"
	resetPwd  = "00299570-246d-11d0-a768-00aa006e0529"
	changePwd = "ab721a53-1e2f-11d0-9819-00aa0040529b"
	gpoDN     = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System," + base
)

// fakeObj is one object of the in-memory directory.
type fakeObj struct {
	dn         string
	sid        sid.SID
	class      string
	adminCount bool
	primaryRID uint32
	members    []string
	sd         *sd.Descriptor
}

// fakeDir is an in-memory directory implementing the directory interface
// with AD's semantics: member holds direct members only, primary group
// membership is only in primaryGroupID, tokenGroups is transitive and
// includes the primary group.
type fakeDir struct {
	domain sid.SID
	objs   map[string]*fakeObj
}

func key(dn string) string { return escape.NormalizeDN(dn) }

func newFake() *fakeDir {
	return &fakeDir{domain: sid.MustParse(domainStr), objs: map[string]*fakeObj{}}
}

func (f *fakeDir) add(o *fakeObj) *fakeObj {
	f.objs[key(o.dn)] = o
	return o
}

func (f *fakeDir) rid(r uint32) sid.SID {
	s, err := f.domain.WithRID(r)
	if err != nil {
		panic(err)
	}
	return s
}

func (f *fakeDir) get(dn string) (*fakeObj, error) {
	o, ok := f.objs[key(dn)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ad.ErrNotFound, dn)
	}
	return o, nil
}

func (o *fakeObj) view() object {
	return object{DN: o.dn, SID: o.sid, Group: o.class == "group", AdminCount: o.adminCount}
}

func (f *fakeDir) baseDN() string { return base }

func (f *fakeDir) domainSID(context.Context) (sid.SID, error) { return f.domain, nil }

func (f *fakeDir) findBySID(_ context.Context, s sid.SID) (string, error) {
	for _, o := range f.objs {
		if o.sid.Equal(s) {
			return o.dn, nil
		}
	}
	return "", fmt.Errorf("%w: SID %s", ad.ErrNotFound, s)
}

func (f *fakeDir) object(_ context.Context, dn string) (object, error) {
	o, err := f.get(dn)
	if err != nil {
		return object{}, err
	}
	return o.view(), nil
}

func (f *fakeDir) directMembers(_ context.Context, groupDN string) ([]string, error) {
	g, err := f.get(groupDN)
	if err != nil {
		return nil, err
	}
	return g.members, nil
}

func (f *fakeDir) primaryGroupMembers(_ context.Context, rids []uint32) ([]object, error) {
	var out []object
	for _, o := range f.objs {
		if o.primaryRID != 0 && slices.Contains(rids, o.primaryRID) {
			out = append(out, o.view())
		}
	}
	return out, nil
}

func (f *fakeDir) adminCountObjects(context.Context) ([]object, error) {
	var out []object
	for _, o := range f.objs {
		if o.adminCount {
			out = append(out, o.view())
		}
	}
	return out, nil
}

func (f *fakeDir) descriptor(_ context.Context, dn string) (*sd.Descriptor, error) {
	o, err := f.get(dn)
	if err != nil {
		return nil, err
	}
	if o.sd == nil {
		return nil, fmt.Errorf("%w: %s", ad.ErrNoSecurityDescriptor, dn)
	}
	return o.sd, nil
}

func (f *fakeDir) descriptorsByClass(_ context.Context, b, class string) ([]securedObject, error) {
	if _, err := f.get(b); err != nil {
		return nil, err
	}
	var out []securedObject
	for k, o := range f.objs {
		if o.class != class || (k != key(b) && !strings.HasSuffix(k, ","+key(b))) {
			continue
		}
		if o.sd == nil {
			return nil, fmt.Errorf("%w: %s", ad.ErrNoSecurityDescriptor, o.dn)
		}
		out = append(out, securedObject{DN: o.dn, SD: o.sd})
	}
	return out, nil
}

func (f *fakeDir) tokenGroups(_ context.Context, dn string) ([]sid.SID, error) {
	start, err := f.get(dn)
	if err != nil {
		return nil, err
	}
	in := map[string]bool{}
	var out []sid.SID
	frontier := []*fakeObj{start}
	for len(frontier) > 0 {
		cur := frontier[0]
		frontier = frontier[1:]
		for _, g := range f.objs {
			if g.class != "group" || in[key(g.dn)] {
				continue
			}
			rid, _ := g.sid.RID()
			direct := slices.ContainsFunc(g.members, func(m string) bool { return key(m) == key(cur.dn) })
			if direct || (cur.primaryRID != 0 && cur.primaryRID == rid) {
				in[key(g.dn)] = true
				out = append(out, g.sid)
				frontier = append(frontier, g)
			}
		}
	}
	return out, nil
}

// Descriptor helpers.

func allow(mask uint32, trustee sid.SID) sd.ACE {
	return sd.ACE{Type: sd.AceTypeAccessAllowed, Mask: mask, Trustee: trustee, Known: true}
}

func objAllow(flags byte, mask uint32, objectType, inherited string, trustee sid.SID) sd.ACE {
	return sd.ACE{Type: sd.AceTypeAccessAllowedObject, Flags: flags, Mask: mask, Trustee: trustee,
		ObjectType: objectType, InheritedObjectType: inherited, Known: true}
}

func descriptor(owner sid.SID, aces ...sd.ACE) *sd.Descriptor {
	return &sd.Descriptor{Revision: 1, Control: sd.ControlSelfRelative | sd.ControlDACLPresent,
		Owner: owner, Group: owner, DACL: &sd.ACL{Revision: 4, ACEs: aces}}
}

var (
	self       = sid.MustParse("S-1-5-10")
	system     = sid.MustParse("S-1-5-18")
	creatorOwn = sid.MustParse("S-1-3-0")
	edc        = sid.MustParse("S-1-5-9")
	preWin2000 = sid.MustParse("S-1-5-32-554")
	anonymous  = sid.MustParse("S-1-5-7")
	fullDS     = sd.DSCreateChild | sd.DSDeleteChild | sd.DSList | sd.DSSelf | sd.DSReadProp | sd.DSWriteProp |
		sd.DSDeleteTree | sd.DSListObject | sd.DSControlAccess | sd.Delete | sd.ReadControl | sd.WriteDAC | sd.WriteOwner
	readOnly = sd.DSList | sd.DSReadProp | sd.DSListObject | sd.ReadControl
)

// lab is a small domain modelled on the lab's seeded data.
type lab struct {
	*fakeDir
	da, helpdesk, tier0, role sid.SID
	peopleACE                 sd.ACE
}

func user(f *fakeDir, name string, rid uint32, ou string) *fakeObj {
	return f.add(&fakeObj{dn: "CN=" + name + "," + ou, sid: f.rid(rid), class: "user", primaryRID: sid.RIDDomainUsers})
}

func newLab() *lab {
	f := newFake()
	l := &lab{fakeDir: f, da: f.rid(512), helpdesk: f.rid(1105), tier0: f.rid(1200), role: f.rid(1400)}
	people := "OU=People," + base
	special := "OU=Special," + base
	groups := "OU=Groups," + base

	f.add(&fakeObj{dn: base, sid: f.domain, class: "domainDNS", sd: descriptor(sid.BuiltinAdministrators,
		allow(fullDS, l.da),
		allow(fullDS, system),
		allow(readOnly, sid.AuthenticatedUsers),
		allow(sd.DSReadProp, sid.Everyone),
		allow(sd.DSReadProp|sd.ReadControl, preWin2000),
		objAllow(0, sd.DSControlAccess, "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5", "", sid.AuthenticatedUsers),
		objAllow(0, sd.DSControlAccess, "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2", "", edc),
		objAllow(sd.AceFlagContainerInherit|sd.AceFlagInheritOnly, sd.DSWriteProp,
			"ea1b7b93-5e48-46d5-bc6c-4df4fda78a35", "bf967a86-0de6-11d0-a285-00aa003049e2", self),
		objAllow(sd.AceFlagContainerInherit|sd.AceFlagInheritOnly, sd.DSSelf,
			"9b026da6-0d3c-465c-8bee-5199d7165cba", "bf967a86-0de6-11d0-a285-00aa003049e2", creatorOwn),
	)})
	f.add(&fakeObj{dn: "CN=System," + base, class: "container"})
	f.add(&fakeObj{dn: "CN=Policies,CN=System," + base, class: "container"})
	f.add(&fakeObj{dn: "CN=AdminSDHolder,CN=System," + base, class: "container", sd: descriptor(l.da,
		allow(fullDS, l.da),
		allow(readOnly, sid.AuthenticatedUsers),
		objAllow(0, sd.DSControlAccess, changePwd, "", sid.Everyone),
		objAllow(0, sd.DSControlAccess, changePwd, "", self),
	)})
	l.peopleACE = objAllow(sd.AceFlagContainerInherit|sd.AceFlagInheritOnly, sd.DSControlAccess, resetPwd, userClass, l.helpdesk)
	f.add(&fakeObj{dn: people, class: "organizationalUnit", sd: descriptor(l.da,
		l.peopleACE,
		allow(fullDS, l.da),
		allow(readOnly, sid.AuthenticatedUsers),
		allow(readOnly, edc),
	)})
	f.add(&fakeObj{dn: special, class: "organizationalUnit", sd: descriptor(l.da, allow(fullDS, l.da))})
	f.add(&fakeObj{dn: groups, class: "organizationalUnit", sd: descriptor(l.da, allow(fullDS, l.da))})

	gpoOwner := user(f, "gpo.owner", 1300, special)
	f.add(&fakeObj{dn: gpoDN, class: "groupPolicyContainer", sd: descriptor(gpoOwner.sid,
		allow(fullDS, l.da),
		objAllow(sd.AceFlagContainerInherit, sd.DSControlAccess, "edacfd8f-ffb3-11d1-b41d-00a0c968f939", "", sid.AuthenticatedUsers),
	)})

	labAdmin := user(f, "lab.admin", 1101, special)
	helpdeskUser := user(f, "helpdesk.user", 1102, special)
	user(f, "normal.user", 1103, special)
	nested := user(f, "nested.admin", 1104, special)
	primary := user(f, "primary.admin", 1106, special)
	primary.primaryRID = 1200
	stale := user(f, "stale.admin", 1107, special)
	stale.adminCount = true
	extra := user(f, "extra.user", 1108, special)
	staffer := user(f, "staff.user", 1109, people)

	f.add(&fakeObj{dn: "CN=Tier0," + groups, sid: l.tier0, class: "group", members: []string{nested.dn}})
	f.add(&fakeObj{dn: "CN=Domain Admins,CN=Users," + base, sid: l.da, class: "group",
		members: []string{labAdmin.dn, "CN=Tier0," + groups}})
	f.add(&fakeObj{dn: "CN=Administrators,CN=Builtin," + base, sid: sid.BuiltinAdministrators, class: "group",
		members: []string{"CN=Domain Admins,CN=Users," + base}})
	f.add(&fakeObj{dn: "CN=Helpdesk," + groups, sid: l.helpdesk, class: "group", members: []string{helpdeskUser.dn}})
	f.add(&fakeObj{dn: "CN=Conductor Admins," + groups, sid: l.role, class: "group", members: []string{extra.dn}})
	f.add(&fakeObj{dn: "CN=Staff," + groups, sid: f.rid(1500), class: "group", members: []string{staffer.dn, "CN=normal.user," + special}})
	f.add(&fakeObj{dn: "CN=Domain Users,CN=Users," + base, sid: f.rid(513), class: "group"})
	return l
}

func TestPrivileged(t *testing.T) {
	l := newLab()
	ctx := context.Background()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	x, err := build(ctx, l, Options{ExtraGroupSIDs: []sid.SID{l.role}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !x.BuiltAt().Equal(now) {
		t.Fatalf("BuiltAt %v", x.BuiltAt())
	}
	special := ",OU=Special," + base
	ace := l.peopleACE
	daGroup := []Reason{{KindGroup, sid.BuiltinAdministrators.String()}, {KindGroup, l.da.String()},
		{KindOwner, "OU=People," + base}, {KindACL, base + ": " + allow(fullDS, l.da).SDDL()}}
	cases := []struct {
		dn    string
		want  []Reason
		exact bool
	}{
		{"CN=lab.admin" + special, daGroup, false},
		{"CN=nested.admin" + special, daGroup, false},
		{"CN=primary.admin" + special, daGroup, false},
		{"CN=stale.admin" + special, []Reason{{KindAdminCount, "CN=stale.admin" + special}}, true},
		{"CN=helpdesk.user" + special, []Reason{{KindACL, "OU=People," + base + ": " + ace.SDDL()}}, true},
		{"CN=gpo.owner" + special, []Reason{{KindOwner, gpoDN}}, true},
		{"CN=extra.user" + special, []Reason{{KindGroup, l.role.String()}}, true},
		{"CN=normal.user" + special, nil, true},
		{"CN=staff.user,OU=People," + base, nil, true},
	}
	for _, tc := range cases {
		got, err := x.privileged(ctx, l, tc.dn)
		if err != nil {
			t.Fatal(err)
		}
		if !containsAll(got, tc.want) || (tc.exact && len(got) != len(tc.want)) {
			t.Errorf("%s:\n got %v\nwant %v (exact %v)", tc.dn, got, tc.want, tc.exact)
		}
	}
	want := "OU=People," + base + ": (OA;CIIO;CR;" + resetPwd + ";" + userClass + ";" + l.helpdesk.String() + ")"
	if got := x.PrivilegedSID(l.helpdesk); !reflect.DeepEqual(got, []Reason{{KindACL, want}}) {
		t.Errorf("Helpdesk group: %v", got)
	}
	// Members are indexed by SID too, without a directory lookup.
	if got := x.PrivilegedSID(l.rid(1102)); len(got) != 1 || got[0].Kind != KindACL {
		t.Errorf("helpdesk.user by SID: %v", got)
	}
	if got := x.PrivilegedSID(l.rid(1106)); len(got) == 0 {
		t.Error("primary-group member of a nested group missing from the index")
	}
	if got := x.PrivilegedSID(l.rid(1103)); got != nil {
		t.Errorf("normal.user by SID: %v", got)
	}
	if got := sidStrings(x.TrusteeSIDs()); !reflect.DeepEqual(got, sortedStrings(
		sid.BuiltinAdministrators.String(), l.da.String(), l.helpdesk.String(), l.rid(1300).String())) {
		t.Errorf("TrusteeSIDs %v", got)
	}
}

func containsAll(a, b []Reason) bool {
	for _, r := range b {
		if !slices.Contains(a, r) {
			return false
		}
	}
	return true
}

func sidStrings(s []sid.SID) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = v.String()
	}
	return out
}

func sortedStrings(v ...string) []string {
	slices.Sort(v)
	return v
}

func TestPrivilegedRereadsTheObject(t *testing.T) {
	l := newLab()
	ctx := context.Background()
	x, err := build(ctx, l, Options{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dn := "CN=normal.user,OU=Special," + base
	if got, _ := x.privileged(ctx, l, dn); got != nil {
		t.Fatalf("before: %v", got)
	}
	// Changes after the build are seen: adminCount and a new membership.
	l.objs[key(dn)].adminCount = true
	helpdesk := l.objs[key("CN=Helpdesk,OU=Groups,"+base)]
	helpdesk.members = append(helpdesk.members, dn)
	got, err := x.privileged(ctx, l, dn)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, r := range got {
		kinds[r.Kind] = true
	}
	if !kinds[KindAdminCount] || !kinds[KindACL] {
		t.Fatalf("after: %v", got)
	}
	if _, err := x.privileged(ctx, l, "CN=nobody,"+base); !errors.Is(err, ad.ErrNotFound) {
		t.Fatalf("missing object: %v", err)
	}
}

func TestExemptTrustees(t *testing.T) {
	someProp := "28630ebf-41d5-11d1-a9c1-0000f80367c1"
	cases := []struct {
		name     string
		ace      sd.ACE
		reported bool
	}{
		{"SELF", allow(fullDS, self), false},
		{"CREATOR OWNER", allow(sd.GenericAll, creatorOwn), false},
		{"SYSTEM", allow(sd.GenericAll, system), false},
		{"ENTERPRISE DOMAIN CONTROLLERS", allow(sd.DSControlAccess, edc), false},
		{"Pre-Windows 2000", allow(sd.DSWriteProp, preWin2000), false},
		{"Anonymous", allow(sd.DSWriteProp, anonymous), false},
		{"Everyone restricted to a property", objAllow(0, sd.DSWriteProp, someProp, "", sid.Everyone), false},
		{"Authenticated Users restricted to a right", objAllow(0, sd.DSControlAccess, changePwd, "", sid.AuthenticatedUsers), false},
		{"Everyone unrestricted", allow(sd.DSWriteProp, sid.Everyone), true},
		{"Authenticated Users unrestricted", allow(sd.GenericWrite, sid.AuthenticatedUsers), true},
		{"Authenticated Users, inherited type only", objAllow(sd.AceFlagContainerInherit|sd.AceFlagInheritOnly,
			sd.DSWriteProp, "", userClass, sid.AuthenticatedUsers), true},
		{"Everyone reads", allow(readOnly|sd.GenericRead, sid.Everyone), false},
		{"deny is never a grant", sd.ACE{Type: sd.AceTypeAccessDenied, Mask: sd.GenericAll, Trustee: sid.MustParse(domainStr + "-1103"), Known: true}, false},
		{"domain user", allow(sd.WriteDAC, sid.MustParse(domainStr+"-1103")), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.add(&fakeObj{dn: base, sid: f.domain, class: "domainDNS", sd: descriptor(system, tc.ace)})
			x, err := build(context.Background(), f, Options{}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			got := x.PrivilegedSID(tc.ace.Trustee)
			if reported := len(got) > 0; reported != tc.reported {
				t.Fatalf("reported %v (%v), want %v", reported, got, tc.reported)
			}
			if tc.reported && (got[0].Kind != KindACL || got[0].Detail != base+": "+tc.ace.SDDL()) {
				t.Fatalf("reason %v", got)
			}
		})
	}
}

func TestNullDACLAndOwners(t *testing.T) {
	f := newFake()
	f.add(&fakeObj{dn: base, sid: f.domain, class: "domainDNS", sd: descriptor(system)})
	f.add(&fakeObj{dn: "OU=Open," + base, class: "organizationalUnit",
		sd: &sd.Descriptor{Revision: 1, Control: sd.ControlSelfRelative | sd.ControlDACLPresent, Owner: sid.Everyone}})
	x, err := build(context.Background(), f, Options{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := x.PrivilegedSID(sid.Everyone)
	want := []Reason{{KindOwner, "OU=Open," + base}, {KindACL, "OU=Open," + base + ": D:NO_ACCESS_CONTROL"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if x.PrivilegedSID(system) != nil {
		t.Fatal("SYSTEM as owner is normal")
	}
}

func TestBuildFailsClosed(t *testing.T) {
	l := newLab()
	l.objs[key("OU=Groups,"+base)].sd = nil
	if _, err := build(context.Background(), l, Options{}, time.Now()); !errors.Is(err, ad.ErrNoSecurityDescriptor) {
		t.Fatalf("unreadable OU descriptor: %v", err)
	}
	l = newLab()
	l.objs[key(base)].sd = nil
	if _, err := build(context.Background(), l, Options{}, time.Now()); !errors.Is(err, ad.ErrNoSecurityDescriptor) {
		t.Fatalf("unreadable domain head: %v", err)
	}
	// Optional containers may be missing: no AdminSDHolder, no Policies.
	l = newLab()
	delete(l.objs, key("CN=AdminSDHolder,CN=System,"+base))
	delete(l.objs, key("CN=Policies,CN=System,"+base))
	delete(l.objs, key(gpoDN))
	if _, err := build(context.Background(), l, Options{}, time.Now()); err != nil {
		t.Fatalf("missing optional containers: %v", err)
	}
}

func TestMissingGroupsIndexOnlyTheSID(t *testing.T) {
	f := newFake()
	f.add(&fakeObj{dn: base, sid: f.domain, class: "domainDNS", sd: descriptor(system)})
	ghost := f.rid(4242)
	x, err := build(context.Background(), f, Options{ExtraGroupSIDs: []sid.SID{ghost}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := x.PrivilegedSID(ghost); !reflect.DeepEqual(got, []Reason{{KindGroup, ghost.String()}}) {
		t.Fatalf("got %v", got)
	}
	// The well-known groups are indexed even when the directory has none.
	if x.PrivilegedSID(f.rid(sid.RIDSchemaAdmins)) == nil || x.Len() != 12 {
		t.Fatalf("well-known groups: %d SIDs", x.Len())
	}
}
