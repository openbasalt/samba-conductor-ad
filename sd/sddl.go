package sd

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/openbasalt/samba-conductor-ad/sid"
)

// sidAliases are the SDDL two-letter aliases of SIDs that mean the same in
// every domain (MS-DTYP 2.5.1.1). Domain-relative aliases (DA, DU, EA...)
// are not used: a descriptor does not say which domain it belongs to, so
// domain SIDs are rendered in full.
var sidAliases = map[string]string{
	"S-1-1-0":            "WD",
	"S-1-3-0":            "CO",
	"S-1-3-1":            "CG",
	"S-1-3-4":            "OW",
	"S-1-5-2":            "NU",
	"S-1-5-4":            "IU",
	"S-1-5-6":            "SU",
	"S-1-5-7":            "AN",
	"S-1-5-9":            "ED",
	"S-1-5-10":           "PS",
	"S-1-5-11":           "AU",
	"S-1-5-12":           "RC",
	"S-1-5-18":           "SY",
	"S-1-5-19":           "LS",
	"S-1-5-20":           "NS",
	"S-1-5-33":           "WR",
	"S-1-5-32-544":       "BA",
	"S-1-5-32-545":       "BU",
	"S-1-5-32-546":       "BG",
	"S-1-5-32-547":       "PU",
	"S-1-5-32-548":       "AO",
	"S-1-5-32-549":       "SO",
	"S-1-5-32-550":       "PO",
	"S-1-5-32-551":       "BO",
	"S-1-5-32-552":       "RE",
	"S-1-5-32-554":       "RU",
	"S-1-5-32-555":       "RD",
	"S-1-5-32-556":       "NO",
	"S-1-5-32-558":       "MU",
	"S-1-5-32-559":       "LU",
	"S-1-5-32-568":       "IS",
	"S-1-5-32-569":       "CY",
	"S-1-5-32-573":       "ER",
	"S-1-5-32-574":       "CD",
	"S-1-5-32-575":       "RA",
	"S-1-5-32-576":       "ES",
	"S-1-5-32-577":       "MS",
	"S-1-5-32-578":       "HA",
	"S-1-5-32-579":       "AA",
	"S-1-5-32-580":       "RM",
	"S-1-5-84-0-0-0-0-0": "UD",
	"S-1-15-2-1":         "AC",
	"S-1-16-4096":        "LW",
	"S-1-16-8192":        "ME",
	"S-1-16-8448":        "MP",
	"S-1-16-12288":       "HI",
	"S-1-16-16384":       "SI",
	"S-1-18-1":           "AS",
	"S-1-18-2":           "SS",
}

// rightAliases in the order Samba and Windows render them (ascending bit).
var rightAliases = []struct {
	alias string
	bit   uint32
}{
	{"CC", DSCreateChild}, {"DC", DSDeleteChild}, {"LC", DSList}, {"SW", DSSelf},
	{"RP", DSReadProp}, {"WP", DSWriteProp}, {"DT", DSDeleteTree}, {"LO", DSListObject},
	{"CR", DSControlAccess}, {"SD", Delete}, {"RC", ReadControl}, {"WD", WriteDAC},
	{"WO", WriteOwner}, {"GA", GenericAll}, {"GX", GenericExecute}, {"GW", GenericWrite},
	{"GR", GenericRead},
}

var aceFlagAliases = []struct {
	alias string
	bit   byte
}{
	{"OI", AceFlagObjectInherit}, {"CI", AceFlagContainerInherit}, {"NP", AceFlagNoPropagate},
	{"IO", AceFlagInheritOnly}, {"ID", AceFlagInherited}, {"SA", AceFlagSuccessfulAccess},
	{"FA", AceFlagFailedAccess},
}

// SIDString renders a SID as its SDDL alias when it has one that holds in
// every domain, otherwise in the S-1-... form.
func SIDString(s sid.SID) string {
	str := s.String()
	if a, ok := sidAliases[str]; ok {
		return a
	}
	return str
}

// SDDL renders the owner, group and DACL in SDDL (MS-DTYP 2.5.1), for
// previews, audit details and tests. The SACL is never rendered. ACEs of
// types this package does not decode are rendered as the hex of their raw
// bytes in parentheses.
func (d *Descriptor) SDDL() string {
	var sb strings.Builder
	if !d.Owner.IsZero() {
		sb.WriteString("O:")
		sb.WriteString(SIDString(d.Owner))
	}
	if !d.Group.IsZero() {
		sb.WriteString("G:")
		sb.WriteString(SIDString(d.Group))
	}
	switch {
	case d.NullDACL():
		sb.WriteString("D:NO_ACCESS_CONTROL")
	case d.DACL != nil:
		sb.WriteString("D:")
		if d.Control&ControlDACLProtected != 0 {
			sb.WriteString("P")
		}
		if d.Control&ControlDACLAutoInheritReq != 0 {
			sb.WriteString("AR")
		}
		if d.Control&ControlDACLAutoInherited != 0 {
			sb.WriteString("AI")
		}
		for i := range d.DACL.ACEs {
			sb.WriteString(d.DACL.ACEs[i].SDDL())
		}
	}
	return sb.String()
}

// SDDL renders one ACE in SDDL: "(type;flags;rights;object;inherited;sid)".
func (a ACE) SDDL() string {
	if !a.Known {
		return "(" + hex.EncodeToString(a.Raw) + ")"
	}
	var sb strings.Builder
	sb.WriteByte('(')
	switch a.Type {
	case AceTypeAccessAllowed:
		sb.WriteString("A")
	case AceTypeAccessDenied:
		sb.WriteString("D")
	case AceTypeAccessAllowedObject:
		sb.WriteString("OA")
	case AceTypeAccessDeniedObject:
		sb.WriteString("OD")
	}
	sb.WriteByte(';')
	for _, f := range aceFlagAliases {
		if a.Flags&f.bit != 0 {
			sb.WriteString(f.alias)
		}
	}
	sb.WriteByte(';')
	sb.WriteString(MaskString(a.Mask))
	sb.WriteByte(';')
	sb.WriteString(a.ObjectType)
	sb.WriteByte(';')
	sb.WriteString(a.InheritedObjectType)
	sb.WriteByte(';')
	sb.WriteString(SIDString(a.Trustee))
	sb.WriteByte(')')
	return sb.String()
}

// MaskString renders an access mask with the SDDL right aliases, or in hex
// ("0x100004") when it holds a bit that has no alias.
func MaskString(mask uint32) string {
	var sb strings.Builder
	rest := mask
	for _, r := range rightAliases {
		if mask&r.bit != 0 {
			sb.WriteString(r.alias)
			rest &^= r.bit
		}
	}
	if rest != 0 {
		return "0x" + strconv.FormatUint(uint64(mask), 16)
	}
	return sb.String()
}
