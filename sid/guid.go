package sid

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// GUID is an objectGUID in its binary (wire) layout: the first three fields
// little-endian, the last eight bytes as is (MS-DTYP 2.3.4).
type GUID [16]byte

// GUIDFromBytes decodes a binary objectGUID.
func GUIDFromBytes(b []byte) (GUID, error) {
	var g GUID
	if len(b) != 16 {
		return g, fmt.Errorf("sid: invalid GUID length %d", len(b))
	}
	copy(g[:], b)
	return g, nil
}

// ParseGUID decodes the canonical string form
// "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (case-insensitive, optional braces).
func ParseGUID(s string) (GUID, error) {
	var g GUID
	s = strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return g, fmt.Errorf("sid: invalid GUID %q", s)
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil {
		return g, fmt.Errorf("sid: invalid GUID %q", s)
	}
	binary.LittleEndian.PutUint32(g[0:], binary.BigEndian.Uint32(raw[0:]))
	binary.LittleEndian.PutUint16(g[4:], binary.BigEndian.Uint16(raw[4:]))
	binary.LittleEndian.PutUint16(g[6:], binary.BigEndian.Uint16(raw[6:]))
	copy(g[8:], raw[8:])
	return g, nil
}

// String renders the canonical lowercase form.
func (g GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(g[0:]), binary.LittleEndian.Uint16(g[4:]),
		binary.LittleEndian.Uint16(g[6:]), g[8:10], g[10:])
}

// Bytes returns the binary form, suitable for an objectGUID filter.
func (g GUID) Bytes() []byte { return append([]byte(nil), g[:]...) }

// IsZero reports whether g is all zeros.
func (g GUID) IsZero() bool { return g == GUID{} }
