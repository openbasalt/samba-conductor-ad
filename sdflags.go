package ad

import (
	"context"
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sd"
)

// ControlTypeSDFlags is LDAP_SERVER_SD_FLAGS_OID (MS-ADTS 3.1.1.3.4.1.11).
const ControlTypeSDFlags = "1.2.840.113556.1.4.801"

// sdFlagsControl asks the DC to return only the given parts of
// nTSecurityDescriptor. It is sent as critical, so a server that cannot
// honour it fails the search instead of returning something else. The
// criticality boolean is written as 0xFF by hand for the same reason as in
// sortControl: Samba decodes BER booleans strictly.
type sdFlagsControl struct {
	flags uint32
}

func (c sdFlagsControl) GetControlType() string { return ControlTypeSDFlags }

func (c sdFlagsControl) String() string {
	return fmt.Sprintf("Control Type: SD Flags (%q) flags=%#x", c.GetControlType(), c.flags)
}

// Encode returns the control packet: type, criticality TRUE and the value
// SEQUENCE { INTEGER flags }.
func (c sdFlagsControl) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.GetControlType(), "Control Type"))
	crit := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, nil, "Criticality")
	crit.Data.WriteByte(0xFF)
	crit.Value = true
	packet.AppendChild(crit)
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(c.value()), "Control Value"))
	return packet
}

func (c sdFlagsControl) value() []byte {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlagsRequestValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.flags), "Flags"))
	return seq.Bytes()
}

// ErrNoSecurityDescriptor is returned when an object comes back without
// nTSecurityDescriptor (normally: the caller may not read it).
var ErrNoSecurityDescriptor = errors.New("ad: no nTSecurityDescriptor returned")

// SecurityDescriptor reads and parses the nTSecurityDescriptor of one
// object, with only the parts named by flags (sd.FlagOwner, sd.FlagGroup,
// sd.FlagDACL; the SACL is never parsed). flags 0 means owner, group and
// DACL.
func (c *Conn) SecurityDescriptor(ctx context.Context, dn string, flags uint32) (*sd.Descriptor, error) {
	if _, err := escape.ParseDN(dn); err != nil {
		return nil, err
	}
	if flags == 0 {
		flags = sd.FlagOwner | sd.FlagGroup | sd.FlagDACL
	}
	entries, err := c.SearchAll(ctx, SearchRequest{BaseDN: dn, Scope: ScopeBase,
		Filter: escape.RawFilter("(objectClass=*)"), Attributes: []string{"nTSecurityDescriptor"},
		SecurityDescriptorFlags: flags})
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, dn)
	}
	return ParseSecurityDescriptor(entries[0])
}

// ParseSecurityDescriptor parses the nTSecurityDescriptor of an entry read
// with SearchRequest.SecurityDescriptorFlags.
func ParseSecurityDescriptor(e *ldap.Entry) (*sd.Descriptor, error) {
	raw := e.GetRawAttributeValue("nTSecurityDescriptor")
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoSecurityDescriptor, e.DN)
	}
	d, err := sd.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ad: %s: %w", e.DN, err)
	}
	return d, nil
}
