// Package sid decodes and formats Windows security identifiers (SIDs) and
// GUIDs as stored by Active Directory, and names the well-known RIDs.
//
// Authorization decisions must match groups by SID, never by name or by a
// substring of a DN: names can be renamed or spoofed with lookalike DNs, SIDs
// cannot.
package sid

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Well-known relative identifiers inside a domain (MS-DTYP 2.4.2.4).
const (
	RIDAdministrator              uint32 = 500
	RIDGuest                      uint32 = 501
	RIDKrbtgt                     uint32 = 502
	RIDDomainAdmins               uint32 = 512
	RIDDomainUsers                uint32 = 513
	RIDDomainGuests               uint32 = 514
	RIDDomainComputers            uint32 = 515
	RIDDomainControllers          uint32 = 516
	RIDCertPublishers             uint32 = 517
	RIDSchemaAdmins               uint32 = 518
	RIDEnterpriseAdmins           uint32 = 519
	RIDGroupPolicyCreatorOwners   uint32 = 520
	RIDReadOnlyDomainControllers  uint32 = 521
	RIDCloneableDomainControllers uint32 = 522
	RIDProtectedUsers             uint32 = 525
	RIDKeyAdmins                  uint32 = 526
	RIDEnterpriseKeyAdmins        uint32 = 527
)

// Well-known SIDs of the BUILTIN domain (S-1-5-32-x).
var (
	BuiltinAdministrators   = MustParse("S-1-5-32-544")
	BuiltinUsers            = MustParse("S-1-5-32-545")
	BuiltinAccountOperators = MustParse("S-1-5-32-548")
	BuiltinServerOperators  = MustParse("S-1-5-32-549")
	BuiltinPrintOperators   = MustParse("S-1-5-32-550")
	BuiltinBackupOperators  = MustParse("S-1-5-32-551")
	AuthenticatedUsers      = MustParse("S-1-5-11")
	Everyone                = MustParse("S-1-1-0")
)

// ErrInvalid is returned for malformed SIDs.
var ErrInvalid = errors.New("sid: invalid SID")

const maxSubAuthorities = 15

// SID is a security identifier. The zero value is invalid.
type SID struct {
	Revision     byte
	Authority    uint64 // 48-bit identifier authority
	SubAuthority []uint32
}

// FromBytes decodes the binary form (as in objectSid or tokenGroups).
func FromBytes(b []byte) (SID, error) {
	if len(b) < 8 {
		return SID{}, fmt.Errorf("%w: %d bytes", ErrInvalid, len(b))
	}
	n := int(b[1])
	if b[0] != 1 || n > maxSubAuthorities || len(b) != 8+4*n {
		return SID{}, fmt.Errorf("%w: revision %d, %d sub-authorities, %d bytes", ErrInvalid, b[0], n, len(b))
	}
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	s := SID{Revision: 1, Authority: auth, SubAuthority: make([]uint32, n)}
	for i := 0; i < n; i++ {
		s.SubAuthority[i] = binary.LittleEndian.Uint32(b[8+4*i:])
	}
	return s, nil
}

// Parse decodes the string form "S-1-5-21-...".
func Parse(s string) (SID, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || (parts[0] != "S" && parts[0] != "s") || parts[1] != "1" {
		return SID{}, fmt.Errorf("%w: %q", ErrInvalid, s)
	}
	auth, err := parseUint(parts[2], 1<<48-1)
	if err != nil {
		return SID{}, fmt.Errorf("%w: authority in %q", ErrInvalid, s)
	}
	subs := parts[3:]
	if len(subs) > maxSubAuthorities {
		return SID{}, fmt.Errorf("%w: too many sub-authorities in %q", ErrInvalid, s)
	}
	out := SID{Revision: 1, Authority: auth, SubAuthority: make([]uint32, len(subs))}
	for i, p := range subs {
		v, err := parseUint(p, 1<<32-1)
		if err != nil {
			return SID{}, fmt.Errorf("%w: sub-authority %q in %q", ErrInvalid, p, s)
		}
		out.SubAuthority[i] = uint32(v)
	}
	return out, nil
}

func parseUint(s string, maxValue uint64) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, ErrInvalid
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v > maxValue {
		return 0, ErrInvalid
	}
	return v, nil
}

// MustParse is Parse for constants; it panics on error.
func MustParse(s string) SID {
	v, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

// IsZero reports whether s is the zero (invalid) value.
func (s SID) IsZero() bool { return s.Revision == 0 }

// String renders "S-1-<authority>-<sub>-...".
func (s SID) String() string {
	if s.IsZero() {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("S-1-")
	sb.WriteString(strconv.FormatUint(s.Authority, 10))
	for _, v := range s.SubAuthority {
		sb.WriteByte('-')
		sb.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return sb.String()
}

// Bytes renders the binary form, suitable for an objectSid filter.
func (s SID) Bytes() []byte {
	b := make([]byte, 8+4*len(s.SubAuthority))
	b[0] = 1
	b[1] = byte(len(s.SubAuthority))
	for i := 0; i < 6; i++ {
		b[2+i] = byte(s.Authority >> (8 * (5 - i)))
	}
	for i, v := range s.SubAuthority {
		binary.LittleEndian.PutUint32(b[8+4*i:], v)
	}
	return b
}

// Equal compares two SIDs.
func (s SID) Equal(o SID) bool {
	if s.Revision != o.Revision || s.Authority != o.Authority || len(s.SubAuthority) != len(o.SubAuthority) {
		return false
	}
	for i := range s.SubAuthority {
		if s.SubAuthority[i] != o.SubAuthority[i] {
			return false
		}
	}
	return true
}

// IsDomainAccount reports whether s has the shape of an account in an AD
// domain: S-1-5-21-a-b-c-RID.
func (s SID) IsDomainAccount() bool {
	return s.Authority == 5 && len(s.SubAuthority) == 5 && s.SubAuthority[0] == 21
}

// RID returns the last sub-authority of a domain account SID.
func (s SID) RID() (uint32, bool) {
	if !s.IsDomainAccount() {
		return 0, false
	}
	return s.SubAuthority[4], true
}

// Domain returns the domain SID of a domain account SID (without the RID).
func (s SID) Domain() (SID, bool) {
	if !s.IsDomainAccount() {
		return SID{}, false
	}
	return SID{Revision: 1, Authority: 5, SubAuthority: append([]uint32(nil), s.SubAuthority[:4]...)}, true
}

// WithRID builds the SID of an account in domain s (which must be a domain
// SID: S-1-5-21-a-b-c).
func (s SID) WithRID(rid uint32) (SID, error) {
	if s.Authority != 5 || len(s.SubAuthority) != 4 || s.SubAuthority[0] != 21 {
		return SID{}, fmt.Errorf("%w: %s is not a domain SID", ErrInvalid, s)
	}
	return SID{Revision: 1, Authority: 5, SubAuthority: append(append([]uint32(nil), s.SubAuthority...), rid)}, nil
}

// Contains reports whether want is in the list.
func Contains(list []SID, want SID) bool {
	for _, s := range list {
		if s.Equal(want) {
			return true
		}
	}
	return false
}
