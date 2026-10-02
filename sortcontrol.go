package ad

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// sortControl is the RFC 2891 server-side sort request with one key.
//
// go-ldap's ControlServerSideSorting encodes reverseOrder TRUE as 0x01;
// Samba decodes BER booleans strictly (only 0xFF is TRUE, as DER requires)
// and silently sorts ascending. This encoder writes 0xFF.
type sortControl struct {
	attr    string
	reverse bool
}

func (c sortControl) GetControlType() string { return ldap.ControlTypeServerSideSorting }

func (c sortControl) String() string {
	return fmt.Sprintf("Control Type: Server Side Sorting (%q) attribute=%s reverse=%t", c.GetControlType(), c.attr, c.reverse)
}

// Encode returns the control packet (non-critical).
func (c sortControl) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.GetControlType(), "Control Type"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(c.value()), "Control Value"))
	return packet
}

// value is the BER SortKeyList.
func (c sortControl) value() []byte {
	keys := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SortKeyList")
	key := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SortKey")
	key.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.attr, "attributeType"))
	if c.reverse {
		rev := ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, nil, "reverseOrder")
		rev.Data.WriteByte(0xFF)
		rev.Value = true
		key.AppendChild(rev)
	}
	keys.AppendChild(key)
	return keys.Bytes()
}
