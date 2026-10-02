package ad

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// DNSType is a DNS record type as stored in a dnsRecord value (MS-DNSP
// 2.2.2.1.1).
type DNSType uint16

// Record types. DNSTypeZero marks a tombstoned node.
const (
	DNSTypeZero  DNSType = 0
	DNSTypeA     DNSType = 1
	DNSTypeNS    DNSType = 2
	DNSTypeCNAME DNSType = 5
	DNSTypeSOA   DNSType = 6
	DNSTypePTR   DNSType = 12
	DNSTypeMX    DNSType = 15
	DNSTypeTXT   DNSType = 16
	DNSTypeAAAA  DNSType = 28
	DNSTypeSRV   DNSType = 33
)

var dnsTypeNames = map[DNSType]string{DNSTypeZero: "TOMBSTONE", DNSTypeA: "A", DNSTypeNS: "NS", DNSTypeCNAME: "CNAME",
	DNSTypeSOA: "SOA", DNSTypePTR: "PTR", DNSTypeMX: "MX", DNSTypeTXT: "TXT", DNSTypeAAAA: "AAAA", DNSTypeSRV: "SRV"}

func (t DNSType) String() string {
	if n, ok := dnsTypeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// WritableDNSTypes are the record types the operations of this package
// create, change and delete (SOA is managed with the zone).
var WritableDNSTypes = []DNSType{DNSTypeA, DNSTypeAAAA, DNSTypeCNAME, DNSTypeMX, DNSTypeTXT, DNSTypeSRV, DNSTypePTR, DNSTypeNS}

// ParseDNSType parses one of WritableDNSTypes ("A", "aaaa", …).
func ParseDNSType(s string) (DNSType, error) {
	for _, t := range WritableDNSTypes {
		if strings.EqualFold(s, t.String()) {
			return t, nil
		}
	}
	return 0, fmt.Errorf("%w: record type %q", ErrInvalid, s)
}

// DNS ranks (MS-DNSP 2.2.2.1.2) used by AD-integrated zones.
const (
	dnsRankZone    uint8 = 0xF0
	dnsRecordVers  uint8 = 5
	dnsRecordHdr         = 24
	maxTXTChunk          = 255
	defaultDNSTTL        = 3600
	maxDNSTTL            = 2147483647
	dnsMaxNameLen        = 253
	dnsMaxLabelLen       = 63
)

// DNSRecord is one value of a dnsNode's dnsRecord attribute (MS-DNSP
// 2.3.2.2), decoded. Data is the canonical text form:
//
//	A, AAAA          address                    192.0.2.10
//	NS, CNAME, PTR   host name, no final dot    host.example.com
//	MX               preference host            10 mail.example.com
//	SRV              priority weight port host  0 100 389 dc1.example.com
//	TXT              quoted strings             "v=spf1 mx -all"
//	SOA              mname rname serial refresh retry expire minimum
type DNSRecord struct {
	Type   DNSType
	TTL    uint32
	Rank   uint8
	Serial uint32
	// Timestamp is the aging time stamp in hours since 1601; 0 = static.
	Timestamp uint32
	Data      string
	raw       []byte
}

// Raw returns the value as stored (what a delete must send).
func (r DNSRecord) Raw() []byte { return r.raw }

// Static reports a record without aging (not dynamically registered).
func (r DNSRecord) Static() bool { return r.Timestamp == 0 }

// String renders "TYPE data (ttl N)".
func (r DNSRecord) String() string {
	return fmt.Sprintf("%s %s (ttl %d)", r.Type, r.Data, r.TTL)
}

// Equal reports the same type and data (TTL and metadata ignored).
func (r DNSRecord) Equal(o DNSRecord) bool {
	return r.Type == o.Type && strings.EqualFold(r.Data, o.Data)
}

// NewDNSRecord validates and normalizes a record a user typed: data is
// checked against the type and brought to the canonical text form; ttl 0
// means the default (3600 s).
func NewDNSRecord(t DNSType, data string, ttl uint32) (DNSRecord, error) {
	if t == DNSTypeSOA || t == DNSTypeZero {
		return DNSRecord{}, fmt.Errorf("%w: %s records are not edited directly", ErrInvalid, t)
	}
	if ttl == 0 {
		ttl = defaultDNSTTL
	}
	if ttl > maxDNSTTL {
		return DNSRecord{}, fmt.Errorf("%w: TTL too large", ErrInvalid)
	}
	norm, err := normalizeDNSData(t, strings.TrimSpace(data))
	if err != nil {
		return DNSRecord{}, err
	}
	r := DNSRecord{Type: t, TTL: ttl, Rank: dnsRankZone, Data: norm}
	if _, err := encodeDNSData(t, norm); err != nil {
		return DNSRecord{}, err
	}
	return r, nil
}

var dnsLabelRE = regexp.MustCompile(`^(\*|[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)$`)

// validDNSName checks a host name (no trailing dot, labels of letters,
// digits, '-', '_', a leading "*" label allowed).
func validDNSName(s string, allowWildcard bool) bool {
	if s == "" || len(s) > dnsMaxNameLen {
		return false
	}
	for i, l := range strings.Split(s, ".") {
		if !dnsLabelRE.MatchString(l) || (l == "*" && (i != 0 || !allowWildcard)) {
			return false
		}
	}
	return true
}

func cleanHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.TrimSpace(h), ".")
	if !validDNSName(h, false) {
		return "", fmt.Errorf("%w: %q is not a host name", ErrInvalid, h)
	}
	return strings.ToLower(h), nil
}

func parseUint16(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not a number 0-65535", ErrInvalid, s)
	}
	return uint16(n), nil
}

func normalizeDNSData(t DNSType, data string) (string, error) {
	if data == "" {
		return "", fmt.Errorf("%w: empty record data", ErrInvalid)
	}
	switch t {
	case DNSTypeA, DNSTypeAAAA:
		a, err := netip.ParseAddr(data)
		if err != nil || (t == DNSTypeA) != a.Is4() || a.Zone() != "" {
			return "", fmt.Errorf("%w: %q is not an IPv%s address", ErrInvalid, data, map[bool]string{true: "4", false: "6"}[t == DNSTypeA])
		}
		return a.String(), nil
	case DNSTypeNS, DNSTypeCNAME, DNSTypePTR:
		return cleanHost(data)
	case DNSTypeMX:
		f := strings.Fields(data)
		if len(f) != 2 {
			return "", fmt.Errorf("%w: MX data is \"preference host\"", ErrInvalid)
		}
		pref, err := parseUint16(f[0])
		if err != nil {
			return "", err
		}
		host, err := cleanHost(f[1])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %s", pref, host), nil
	case DNSTypeSRV:
		f := strings.Fields(data)
		if len(f) != 4 {
			return "", fmt.Errorf("%w: SRV data is \"priority weight port host\"", ErrInvalid)
		}
		var n [3]uint16
		for i := range 3 {
			v, err := parseUint16(f[i])
			if err != nil {
				return "", err
			}
			n[i] = v
		}
		host, err := cleanHost(f[3])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %d %d %s", n[0], n[1], n[2], host), nil
	case DNSTypeTXT:
		parts, err := txtStrings(data)
		if err != nil {
			return "", err
		}
		return quoteTXT(parts), nil
	}
	return "", fmt.Errorf("%w: record type %s", ErrInvalid, t)
}

// txtStrings parses TXT data: either one or more quoted strings ("a" "b",
// Go/zone-file escapes) or raw text, which is split into 255-byte strings.
func txtStrings(data string) ([]string, error) {
	var parts []string
	if strings.HasPrefix(data, `"`) {
		rest := data
		for rest != "" {
			q, err := strconv.QuotedPrefix(rest)
			if err != nil {
				return nil, fmt.Errorf("%w: TXT data: unbalanced quotes", ErrInvalid)
			}
			s, err := strconv.Unquote(q)
			if err != nil {
				return nil, fmt.Errorf("%w: TXT data: %v", ErrInvalid, err)
			}
			parts = append(parts, s)
			rest = strings.TrimLeft(rest[len(q):], " ")
		}
	} else {
		for len(data) > maxTXTChunk {
			parts = append(parts, data[:maxTXTChunk])
			data = data[maxTXTChunk:]
		}
		parts = append(parts, data)
	}
	total := 0
	for _, p := range parts {
		if len(p) > maxTXTChunk {
			return nil, fmt.Errorf("%w: a TXT string is longer than 255 bytes", ErrInvalid)
		}
		if strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, fmt.Errorf("%w: control character in TXT data", ErrInvalid)
		}
		total += len(p) + 1
	}
	if len(parts) == 0 || total > 4000 {
		return nil, fmt.Errorf("%w: TXT data too long", ErrInvalid)
	}
	return parts, nil
}

func quoteTXT(parts []string) string {
	q := make([]string, len(parts))
	for i, p := range parts {
		q[i] = strconv.Quote(p)
	}
	return strings.Join(q, " ")
}

// ---- wire format (MS-DNSP 2.3.2.2, Samba's dnsp_DnssrvRpcRecord) ----

var errDNSRecordFormat = errors.New("ad: malformed dnsRecord value")

// EncodeDNSRecord renders a record as a dnsRecord attribute value.
func EncodeDNSRecord(r DNSRecord) ([]byte, error) {
	data, err := encodeDNSData(r.Type, r.Data)
	if err != nil {
		return nil, err
	}
	if len(data) > 0xffff {
		return nil, fmt.Errorf("%w: record data too long", ErrInvalid)
	}
	b := make([]byte, dnsRecordHdr+len(data))
	binary.LittleEndian.PutUint16(b[0:], uint16(len(data)))
	binary.LittleEndian.PutUint16(b[2:], uint16(r.Type))
	b[4] = dnsRecordVers
	b[5] = r.Rank
	// b[6:8] flags = 0
	binary.LittleEndian.PutUint32(b[8:], r.Serial)
	binary.BigEndian.PutUint32(b[12:], r.TTL) // the TTL alone is big-endian
	// b[16:20] reserved = 0
	binary.LittleEndian.PutUint32(b[20:], r.Timestamp)
	copy(b[dnsRecordHdr:], data)
	return b, nil
}

// DecodeDNSRecord parses a dnsRecord attribute value. Unknown types keep
// their data as "\# <length> <hex>" (RFC 3597).
func DecodeDNSRecord(b []byte) (DNSRecord, error) {
	if len(b) < dnsRecordHdr {
		return DNSRecord{}, errDNSRecordFormat
	}
	n := int(binary.LittleEndian.Uint16(b[0:]))
	if len(b) < dnsRecordHdr+n || b[4] != dnsRecordVers {
		return DNSRecord{}, errDNSRecordFormat
	}
	r := DNSRecord{
		Type:      DNSType(binary.LittleEndian.Uint16(b[2:])),
		Rank:      b[5],
		Serial:    binary.LittleEndian.Uint32(b[8:]),
		TTL:       binary.BigEndian.Uint32(b[12:]),
		Timestamp: binary.LittleEndian.Uint32(b[20:]),
		raw:       append([]byte(nil), b...),
	}
	data := b[dnsRecordHdr : dnsRecordHdr+n]
	text, err := decodeDNSData(r.Type, data)
	if err != nil {
		return DNSRecord{}, err
	}
	r.Data = text
	return r, nil
}

// encodeName renders a dnsp_name: total length, label count, the labels
// each prefixed with its length, and a zero terminator.
func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{1, 0, 0}, nil // the root
	}
	labels := strings.Split(name, ".")
	raw := make([]byte, 0, len(name)+2)
	for _, l := range labels {
		if l == "" || len(l) > dnsMaxLabelLen {
			return nil, fmt.Errorf("%w: bad label in %q", ErrInvalid, name)
		}
		raw = append(raw, byte(len(l)))
		raw = append(raw, l...)
	}
	raw = append(raw, 0)
	if len(raw) > 255 || len(labels) > 127 {
		return nil, fmt.Errorf("%w: name too long", ErrInvalid)
	}
	return append([]byte{byte(len(raw)), byte(len(labels))}, raw...), nil
}

// decodeName parses a dnsp_name at the start of b and returns the name and
// the number of bytes it used.
func decodeName(b []byte) (string, int, error) {
	if len(b) < 2 {
		return "", 0, errDNSRecordFormat
	}
	total, count := int(b[0]), int(b[1])
	if len(b) < 2+total {
		return "", 0, errDNSRecordFormat
	}
	raw := b[2 : 2+total]
	labels := make([]string, 0, count)
	off := 0
	for range count {
		if off >= len(raw) {
			return "", 0, errDNSRecordFormat
		}
		l := int(raw[off])
		off++
		if off+l > len(raw) {
			return "", 0, errDNSRecordFormat
		}
		labels = append(labels, string(raw[off:off+l]))
		off += l
	}
	if off >= len(raw) || raw[off] != 0 {
		return "", 0, errDNSRecordFormat
	}
	return strings.Join(labels, "."), 2 + total, nil
}

func encodeDNSData(t DNSType, data string) ([]byte, error) {
	switch t {
	case DNSTypeA, DNSTypeAAAA:
		a, err := netip.ParseAddr(data)
		if err != nil {
			return nil, fmt.Errorf("%w: address %q", ErrInvalid, data)
		}
		return a.AsSlice(), nil
	case DNSTypeNS, DNSTypeCNAME, DNSTypePTR:
		return encodeName(data)
	case DNSTypeMX:
		f := strings.Fields(data)
		if len(f) != 2 {
			return nil, fmt.Errorf("%w: MX data", ErrInvalid)
		}
		pref, err := parseUint16(f[0])
		if err != nil {
			return nil, err
		}
		n, err := encodeName(f[1])
		if err != nil {
			return nil, err
		}
		return append(binary.BigEndian.AppendUint16(nil, pref), n...), nil
	case DNSTypeSRV:
		f := strings.Fields(data)
		if len(f) != 4 {
			return nil, fmt.Errorf("%w: SRV data", ErrInvalid)
		}
		var out []byte
		for i := range 3 {
			v, err := parseUint16(f[i])
			if err != nil {
				return nil, err
			}
			out = binary.BigEndian.AppendUint16(out, v)
		}
		n, err := encodeName(f[3])
		if err != nil {
			return nil, err
		}
		return append(out, n...), nil
	case DNSTypeTXT:
		parts, err := txtStrings(data)
		if err != nil {
			return nil, err
		}
		var out []byte
		for _, p := range parts {
			out = append(out, byte(len(p)))
			out = append(out, p...)
		}
		return out, nil
	case DNSTypeSOA:
		f := strings.Fields(data)
		if len(f) != 7 {
			return nil, fmt.Errorf("%w: SOA data", ErrInvalid)
		}
		var out []byte
		for _, s := range f[2:] {
			v, err := strconv.ParseUint(s, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: SOA number %q", ErrInvalid, s)
			}
			out = binary.BigEndian.AppendUint32(out, uint32(v))
		}
		for _, h := range f[:2] {
			n, err := encodeName(h)
			if err != nil {
				return nil, err
			}
			out = append(out, n...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: cannot encode record type %s", ErrInvalid, t)
}

func decodeDNSData(t DNSType, d []byte) (string, error) {
	switch t {
	case DNSTypeA:
		if len(d) != 4 {
			return "", errDNSRecordFormat
		}
		return netip.AddrFrom4([4]byte(d)).String(), nil
	case DNSTypeAAAA:
		if len(d) != 16 {
			return "", errDNSRecordFormat
		}
		return netip.AddrFrom16([16]byte(d)).String(), nil
	case DNSTypeNS, DNSTypeCNAME, DNSTypePTR:
		n, _, err := decodeName(d)
		return n, err
	case DNSTypeMX:
		if len(d) < 2 {
			return "", errDNSRecordFormat
		}
		n, _, err := decodeName(d[2:])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(d), n), nil
	case DNSTypeSRV:
		if len(d) < 6 {
			return "", errDNSRecordFormat
		}
		n, _, err := decodeName(d[6:])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(d), binary.BigEndian.Uint16(d[2:]), binary.BigEndian.Uint16(d[4:]), n), nil
	case DNSTypeTXT:
		var parts []string
		for len(d) > 0 {
			l := int(d[0])
			if 1+l > len(d) {
				return "", errDNSRecordFormat
			}
			parts = append(parts, string(d[1:1+l]))
			d = d[1+l:]
		}
		return quoteTXT(parts), nil
	case DNSTypeSOA:
		if len(d) < 20 {
			return "", errDNSRecordFormat
		}
		mname, n1, err := decodeName(d[20:])
		if err != nil {
			return "", err
		}
		rname, _, err := decodeName(d[20+n1:])
		if err != nil {
			return "", err
		}
		u := func(i int) uint32 { return binary.BigEndian.Uint32(d[4*i:]) }
		return fmt.Sprintf("%s %s %d %d %d %d %d", mname, rname, u(0), u(1), u(2), u(3), u(4)), nil
	}
	return fmt.Sprintf(`\# %d %s`, len(d), hex.EncodeToString(d)), nil
}

// soaSerial reads the serial of an SOA record's data.
func soaSerial(r DNSRecord) (uint32, error) {
	f := strings.Fields(r.Data)
	if r.Type != DNSTypeSOA || len(f) != 7 {
		return 0, errDNSRecordFormat
	}
	v, err := strconv.ParseUint(f[2], 10, 32)
	return uint32(v), err
}

// withSOASerial returns the SOA record with a new serial (data and header).
func withSOASerial(r DNSRecord, serial uint32) DNSRecord {
	f := strings.Fields(r.Data)
	f[2] = strconv.FormatUint(uint64(serial), 10)
	r.Data = strings.Join(f, " ")
	r.Serial = serial
	r.raw = nil
	return r
}
