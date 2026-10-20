// Package sd parses Windows security descriptors as Active Directory
// returns them in nTSecurityDescriptor: the self-relative
// SECURITY_DESCRIPTOR of MS-DTYP 2.4.6 with its owner, group and DACL.
// The SACL is skipped (reading it needs a right service accounts do not
// have; see the SD flags control in the ad package).
//
// Parsing is bounds-checked: truncated or inconsistent input is an error,
// never a panic.
package sd

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/openbasalt/samba-conductor-ad/sid"
)

// Parts of a descriptor requested with the LDAP_SERVER_SD_FLAGS_OID control
// (MS-ADTS 3.1.1.3.4.1.11), combined with OR.
const (
	FlagOwner uint32 = 0x1
	FlagGroup uint32 = 0x2
	FlagDACL  uint32 = 0x4
	FlagSACL  uint32 = 0x8
)

// Control flags of a security descriptor (MS-DTYP 2.4.6).
const (
	ControlOwnerDefaulted     uint16 = 0x0001
	ControlGroupDefaulted     uint16 = 0x0002
	ControlDACLPresent        uint16 = 0x0004
	ControlDACLDefaulted      uint16 = 0x0008
	ControlSACLPresent        uint16 = 0x0010
	ControlSACLDefaulted      uint16 = 0x0020
	ControlDACLTrusted        uint16 = 0x0040
	ControlServerSecurity     uint16 = 0x0080
	ControlDACLAutoInheritReq uint16 = 0x0100
	ControlSACLAutoInheritReq uint16 = 0x0200
	ControlDACLAutoInherited  uint16 = 0x0400
	ControlSACLAutoInherited  uint16 = 0x0800
	ControlDACLProtected      uint16 = 0x1000
	ControlSACLProtected      uint16 = 0x2000
	ControlRMControlValid     uint16 = 0x4000
	ControlSelfRelative       uint16 = 0x8000
)

// AceType is the type byte of an ACE header (MS-DTYP 2.4.4.1).
type AceType byte

// ACE types decoded by this package. Any other type is kept with its raw
// bytes and ACE.Known false.
const (
	AceTypeAccessAllowed       AceType = 0x00
	AceTypeAccessDenied        AceType = 0x01
	AceTypeAccessAllowedObject AceType = 0x05
	AceTypeAccessDeniedObject  AceType = 0x06
)

// ACE flags (MS-DTYP 2.4.4.1).
const (
	AceFlagObjectInherit    byte = 0x01
	AceFlagContainerInherit byte = 0x02
	AceFlagNoPropagate      byte = 0x04
	AceFlagInheritOnly      byte = 0x08
	AceFlagInherited        byte = 0x10
	AceFlagSuccessfulAccess byte = 0x40
	AceFlagFailedAccess     byte = 0x80
)

// Access mask bits for directory objects (MS-ADTS 5.1.3.2, MS-DTYP 2.4.3).
// The MS names are in the comments.
const (
	DSCreateChild        uint32 = 0x00000001 // ADS_RIGHT_DS_CREATE_CHILD (CC)
	DSDeleteChild        uint32 = 0x00000002 // ADS_RIGHT_DS_DELETE_CHILD (DC)
	DSList               uint32 = 0x00000004 // ADS_RIGHT_ACTRL_DS_LIST (LC)
	DSSelf               uint32 = 0x00000008 // ADS_RIGHT_DS_SELF, validated write (SW)
	DSReadProp           uint32 = 0x00000010 // ADS_RIGHT_DS_READ_PROP (RP)
	DSWriteProp          uint32 = 0x00000020 // ADS_RIGHT_DS_WRITE_PROP (WP)
	DSDeleteTree         uint32 = 0x00000040 // ADS_RIGHT_DS_DELETE_TREE (DT)
	DSListObject         uint32 = 0x00000080 // ADS_RIGHT_DS_LIST_OBJECT (LO)
	DSControlAccess      uint32 = 0x00000100 // ADS_RIGHT_DS_CONTROL_ACCESS, extended right (CR)
	Delete               uint32 = 0x00010000 // DELETE (SD)
	ReadControl          uint32 = 0x00020000 // READ_CONTROL (RC)
	WriteDAC             uint32 = 0x00040000 // WRITE_DAC (WD)
	WriteOwner           uint32 = 0x00080000 // WRITE_OWNER (WO)
	Synchronize          uint32 = 0x00100000 // SYNCHRONIZE
	AccessSystemSecurity uint32 = 0x01000000 // ACCESS_SYSTEM_SECURITY
	MaximumAllowed       uint32 = 0x02000000 // MAXIMUM_ALLOWED
	GenericAll           uint32 = 0x10000000 // GENERIC_ALL (GA)
	GenericExecute       uint32 = 0x20000000 // GENERIC_EXECUTE (GX)
	GenericWrite         uint32 = 0x40000000 // GENERIC_WRITE (GW)
	GenericRead          uint32 = 0x80000000 // GENERIC_READ (GR)
)

// readOnlyMask holds the rights that only read: list, read property, list
// object, read control and generic read.
const readOnlyMask = DSList | DSReadProp | DSListObject | ReadControl | GenericRead

// Object ACE flags telling which GUIDs follow the mask (MS-DTYP 2.4.4.3).
const (
	objectTypePresent          uint32 = 0x1
	inheritedObjectTypePresent uint32 = 0x2
)

// ErrMalformed is returned (wrapped) for any descriptor that cannot be
// parsed: truncated, out-of-bounds offsets or sizes, invalid SIDs.
var ErrMalformed = errors.New("sd: malformed security descriptor")

// Descriptor is a parsed security descriptor. The SACL is not parsed.
type Descriptor struct {
	Revision byte
	Control  uint16
	// Owner and Group are the zero SID when absent.
	Owner sid.SID
	Group sid.SID
	// DACL is nil when the descriptor carries no DACL. See NullDACL.
	DACL *ACL
}

// ACL is a parsed access control list.
type ACL struct {
	Revision byte
	ACEs     []ACE
}

// ACE is one access control entry. For the decoded types (Known true)
// Mask and Trustee are set and, for object ACEs, ObjectType and
// InheritedObjectType when the entry carries them. Other types keep only
// Type, Flags and Raw.
type ACE struct {
	Type  AceType
	Flags byte
	Mask  uint32
	// Trustee is the SID the entry applies to.
	Trustee sid.SID
	// ObjectType is the property, property set, extended right, validated
	// write or child class the entry is restricted to, as a canonical
	// lowercase GUID; empty when absent.
	ObjectType string
	// InheritedObjectType is the class of the objects that inherit the
	// entry, as a canonical lowercase GUID; empty when absent.
	InheritedObjectType string
	// Known is true for the types this package decodes.
	Known bool
	// Raw is the whole ACE (header included) as found in the descriptor.
	Raw []byte
}

// IsAllow reports whether the entry grants access (allowed or allowed
// object type).
func (a ACE) IsAllow() bool {
	return a.Known && (a.Type == AceTypeAccessAllowed || a.Type == AceTypeAccessAllowedObject)
}

// IsObject reports whether the entry is an object ACE (allowed or denied
// object type).
func (a ACE) IsObject() bool {
	return a.Known && (a.Type == AceTypeAccessAllowedObject || a.Type == AceTypeAccessDeniedObject)
}

// InheritOnly reports whether the entry only applies to children.
func (a ACE) InheritOnly() bool { return a.Flags&AceFlagInheritOnly != 0 }

// Inherited reports whether the entry was inherited from a parent.
func (a ACE) Inherited() bool { return a.Flags&AceFlagInherited != 0 }

// GrantsMoreThanRead reports whether the entry is an allow entry whose
// mask holds any right beyond listing and reading (DSList, DSReadProp,
// DSListObject, ReadControl, GenericRead).
func (a ACE) GrantsMoreThanRead() bool {
	return a.IsAllow() && a.Mask&^readOnlyMask != 0
}

// NullDACL reports whether the descriptor says a DACL is present but has
// none, which grants every access to everyone.
func (d *Descriptor) NullDACL() bool {
	return d.Control&ControlDACLPresent != 0 && d.DACL == nil
}

const headerSize = 20

// Parse decodes a self-relative security descriptor. The SACL is skipped.
func Parse(b []byte) (*Descriptor, error) {
	if len(b) < headerSize {
		return nil, fmt.Errorf("%w: %d bytes, header needs %d", ErrMalformed, len(b), headerSize)
	}
	d := &Descriptor{Revision: b[0], Control: binary.LittleEndian.Uint16(b[2:])}
	if d.Revision != 1 {
		return nil, fmt.Errorf("%w: revision %d", ErrMalformed, d.Revision)
	}
	if d.Control&ControlSelfRelative == 0 {
		return nil, fmt.Errorf("%w: not self-relative", ErrMalformed)
	}
	offOwner := binary.LittleEndian.Uint32(b[4:])
	offGroup := binary.LittleEndian.Uint32(b[8:])
	offDACL := binary.LittleEndian.Uint32(b[16:])
	var err error
	if offOwner != 0 {
		if d.Owner, _, err = sidAt(b, offOwner); err != nil {
			return nil, fmt.Errorf("owner: %w", err)
		}
	}
	if offGroup != 0 {
		if d.Group, _, err = sidAt(b, offGroup); err != nil {
			return nil, fmt.Errorf("group: %w", err)
		}
	}
	if d.Control&ControlDACLPresent != 0 && offDACL != 0 {
		if d.DACL, err = parseACL(b, offDACL); err != nil {
			return nil, fmt.Errorf("DACL: %w", err)
		}
	}
	return d, nil
}

// sidAt decodes the SID starting at off and returns it with its length.
func sidAt(b []byte, off uint32) (sid.SID, int, error) {
	if uint64(off)+8 > uint64(len(b)) {
		return sid.SID{}, 0, fmt.Errorf("%w: SID at %d beyond %d bytes", ErrMalformed, off, len(b))
	}
	n := 8 + 4*int(b[off+1])
	if uint64(off)+uint64(n) > uint64(len(b)) {
		return sid.SID{}, 0, fmt.Errorf("%w: SID at %d truncated", ErrMalformed, off)
	}
	s, err := sid.FromBytes(b[off : int(off)+n])
	if err != nil {
		return sid.SID{}, 0, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return s, n, nil
}

const aclHeaderSize = 8

func parseACL(b []byte, off uint32) (*ACL, error) {
	if uint64(off)+aclHeaderSize > uint64(len(b)) {
		return nil, fmt.Errorf("%w: ACL at %d beyond %d bytes", ErrMalformed, off, len(b))
	}
	h := b[off:]
	size := int(binary.LittleEndian.Uint16(h[2:]))
	count := int(binary.LittleEndian.Uint16(h[4:]))
	if size < aclHeaderSize || size > len(h) {
		return nil, fmt.Errorf("%w: ACL size %d at %d (%d bytes left)", ErrMalformed, size, off, len(h))
	}
	body := h[aclHeaderSize:size]
	// Every ACE takes at least its 4-byte header.
	if count > len(body)/4 {
		return nil, fmt.Errorf("%w: %d ACEs cannot fit in %d bytes", ErrMalformed, count, len(body))
	}
	acl := &ACL{Revision: h[0], ACEs: make([]ACE, 0, count)}
	pos := 0
	for i := range count {
		if pos+4 > len(body) {
			return nil, fmt.Errorf("%w: ACE %d header truncated", ErrMalformed, i)
		}
		aceSize := int(binary.LittleEndian.Uint16(body[pos+2:]))
		if aceSize < 4 || pos+aceSize > len(body) {
			return nil, fmt.Errorf("%w: ACE %d size %d out of bounds", ErrMalformed, i, aceSize)
		}
		ace, err := parseACE(body[pos : pos+aceSize])
		if err != nil {
			return nil, fmt.Errorf("ACE %d: %w", i, err)
		}
		acl.ACEs = append(acl.ACEs, ace)
		pos += aceSize
	}
	return acl, nil
}

// parseACE decodes one ACE; raw is exactly AceSize bytes long.
func parseACE(raw []byte) (ACE, error) {
	a := ACE{Type: AceType(raw[0]), Flags: raw[1], Raw: append([]byte(nil), raw...)}
	switch a.Type {
	case AceTypeAccessAllowed, AceTypeAccessDenied:
		if len(raw) < 8 {
			return ACE{}, fmt.Errorf("%w: ACE of %d bytes", ErrMalformed, len(raw))
		}
		a.Mask = binary.LittleEndian.Uint32(raw[4:])
		s, _, err := sidAt(raw, 8)
		if err != nil {
			return ACE{}, err
		}
		a.Trustee = s
	case AceTypeAccessAllowedObject, AceTypeAccessDeniedObject:
		if len(raw) < 12 {
			return ACE{}, fmt.Errorf("%w: object ACE of %d bytes", ErrMalformed, len(raw))
		}
		a.Mask = binary.LittleEndian.Uint32(raw[4:])
		flags := binary.LittleEndian.Uint32(raw[8:])
		pos := 12
		if flags&objectTypePresent != 0 {
			g, err := guidAt(raw, pos)
			if err != nil {
				return ACE{}, err
			}
			a.ObjectType = g
			pos += 16
		}
		if flags&inheritedObjectTypePresent != 0 {
			g, err := guidAt(raw, pos)
			if err != nil {
				return ACE{}, err
			}
			a.InheritedObjectType = g
			pos += 16
		}
		s, _, err := sidAt(raw, uint32(pos))
		if err != nil {
			return ACE{}, err
		}
		a.Trustee = s
	default:
		return a, nil
	}
	a.Known = true
	return a, nil
}

func guidAt(b []byte, pos int) (string, error) {
	if pos+16 > len(b) {
		return "", fmt.Errorf("%w: GUID truncated", ErrMalformed)
	}
	g, err := sid.GUIDFromBytes(b[pos : pos+16])
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return g.String(), nil
}
