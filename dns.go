package ad

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/ad/escape"
)

// AD-integrated DNS lives in the directory (MS-DNSP 2.3): a zone is a
// dnsZone object under CN=MicrosoftDNS in the DomainDnsZones or
// ForestDnsZones application partition (or, legacy, under CN=System), and
// every name in it is a dnsNode whose multi-valued dnsRecord attribute holds
// the records in binary form. Samba's internal DNS server reads the zones
// and records from the database on every query, so LDAP writes made with
// the user's own credentials take effect at once (verified in the lab,
// planning/docs/decisions.md), with AD's ACLs applied.

// DNS partitions a zone can live in.
const (
	DNSPartitionDomain = "DomainDnsZones"
	DNSPartitionForest = "ForestDnsZones"
	DNSPartitionLegacy = "System"
)

// DNSZone is a dnsZone object.
type DNSZone struct {
	Name      string // e.g. "example.com" or "2.0.192.in-addr.arpa"
	DN        string
	Partition string // DNSPartitionDomain, DNSPartitionForest or DNSPartitionLegacy
}

// Reverse reports a reverse-lookup zone.
func (z DNSZone) Reverse() bool {
	n := strings.ToLower(z.Name)
	return strings.HasSuffix(n, ".in-addr.arpa") || strings.HasSuffix(n, ".ip6.arpa")
}

// DNSNode is one name in a zone with its records.
type DNSNode struct {
	Name       string // relative to the zone; "@" is the apex
	DN         string
	Records    []DNSRecord
	Tombstoned bool
	// Exists is false for a node built for a name that has no object yet.
	Exists bool
}

// FQDN returns the node's full name in zone.
func (n DNSNode) FQDN(zone string) string {
	if n.Name == "@" || n.Name == "" {
		return zone
	}
	return n.Name + "." + zone
}

var dnsNodeAttrs = []string{"dc", "dnsRecord", "dNSTombstoned"}

// dnsContainers returns the CN=MicrosoftDNS containers to look for zones in.
func (c *Conn) dnsContainers() []struct{ dn, partition string } {
	return []struct{ dn, partition string }{
		{"CN=MicrosoftDNS,DC=DomainDnsZones," + c.baseDN, DNSPartitionDomain},
		{"CN=MicrosoftDNS,DC=ForestDnsZones," + c.forestDN, DNSPartitionForest},
		{"CN=MicrosoftDNS,CN=System," + c.baseDN, DNSPartitionLegacy},
	}
}

// DNSPartitionDN returns the container new zones of a partition go into.
func (c *Conn) DNSPartitionDN(partition string) (string, error) {
	for _, p := range c.dnsContainers() {
		if p.partition == partition && partition != DNSPartitionLegacy {
			return p.dn, nil
		}
	}
	return "", fmt.Errorf("%w: DNS partition %q", ErrInvalid, partition)
}

// hiddenZone reports internal zone objects that are not served zones.
func hiddenZone(name string) bool {
	return strings.EqualFold(name, "RootDNSServers") || strings.HasPrefix(name, "..")
}

// DNSZones lists the zones of every partition the user can read, sorted
// by name (forward zones first).
func (c *Conn) DNSZones(ctx context.Context) ([]DNSZone, error) {
	var out []DNSZone
	for _, p := range c.dnsContainers() {
		for e, err := range c.Search(ctx, SearchRequest{BaseDN: p.dn, Scope: ScopeOneLevel,
			Filter: escape.Eq("objectClass", "dnsZone"), Attributes: []string{"dc"}}) {
			if errors.Is(err, ErrNotFound) {
				break // the partition or container does not exist
			}
			if err != nil {
				return nil, err
			}
			name := e.GetAttributeValue("dc")
			if name == "" || hiddenZone(name) {
				continue
			}
			out = append(out, DNSZone{Name: name, DN: e.DN, Partition: p.partition})
		}
	}
	slices.SortFunc(out, func(a, b DNSZone) int {
		if a.Reverse() != b.Reverse() {
			if a.Reverse() {
				return 1
			}
			return -1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out, nil
}

// DNSZoneByName finds a zone by its name.
func (c *Conn) DNSZoneByName(ctx context.Context, name string) (DNSZone, error) {
	zones, err := c.DNSZones(ctx)
	if err != nil {
		return DNSZone{}, err
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, name) {
			return z, nil
		}
	}
	return DNSZone{}, fmt.Errorf("%w: DNS zone %q", ErrNotFound, name)
}

func nodeFromEntry(e *ldap.Entry) (DNSNode, error) {
	n := DNSNode{Name: e.GetAttributeValue("dc"), DN: e.DN, Exists: true,
		Tombstoned: strings.EqualFold(e.GetAttributeValue("dNSTombstoned"), "TRUE")}
	for _, raw := range e.GetRawAttributeValues("dnsRecord") {
		r, err := DecodeDNSRecord(raw)
		if err != nil {
			return n, fmt.Errorf("ad: %s: %w", e.DN, err)
		}
		if r.Type == DNSTypeZero {
			n.Tombstoned = true
			continue
		}
		n.Records = append(n.Records, r)
	}
	return n, nil
}

// DNSNodes returns one window of a zone's names (sorted, tombstoned names
// left out), optionally only names starting with prefix, and whether more
// follow.
func (c *Conn) DNSNodes(ctx context.Context, z DNSZone, prefix string, skip, n int) ([]DNSNode, bool, error) {
	f := escape.And(escape.Eq("objectClass", "dnsNode"), escape.Not(escape.Eq("dNSTombstoned", "TRUE")))
	if prefix = strings.TrimSpace(prefix); prefix != "" {
		f = escape.And(f, escape.Prefix("dc", prefix))
	}
	entries, more, err := c.SearchWindow(ctx, SearchRequest{BaseDN: z.DN, Scope: ScopeOneLevel, Filter: f,
		Attributes: dnsNodeAttrs, SortBy: "dc"}, skip, n)
	if err != nil {
		return nil, false, err
	}
	out := make([]DNSNode, 0, len(entries))
	for _, e := range entries {
		node, err := nodeFromEntry(e)
		if err != nil {
			return nil, false, err
		}
		if node.Tombstoned && len(node.Records) == 0 {
			continue
		}
		out = append(out, node)
	}
	return out, more, nil
}

// CountDNSNodes counts the live names of a zone.
func (c *Conn) CountDNSNodes(ctx context.Context, z DNSZone) (int, error) {
	return c.Count(ctx, SearchRequest{BaseDN: z.DN, Scope: ScopeOneLevel,
		Filter: escape.And(escape.Eq("objectClass", "dnsNode"), escape.Not(escape.Eq("dNSTombstoned", "TRUE")))})
}

// DNSNodeByName reads one name of a zone. A name without an object returns
// a node with Exists=false (so records can be added to it).
func (c *Conn) DNSNodeByName(ctx context.Context, z DNSZone, name string) (DNSNode, error) {
	name, err := cleanNodeName(name)
	if err != nil {
		return DNSNode{}, err
	}
	dn, err := escape.ChildDN("DC", name, z.DN)
	if err != nil {
		return DNSNode{}, err
	}
	e, err := c.Get(ctx, dn, dnsNodeAttrs...)
	if errors.Is(err, ErrNotFound) {
		return DNSNode{Name: name, DN: dn}, nil
	}
	if err != nil {
		return DNSNode{}, err
	}
	node, err := nodeFromEntry(e)
	if node.Name == "" {
		node.Name = name
	}
	return node, err
}

// cleanNodeName validates a name relative to its zone ("@" = apex).
func cleanNodeName(name string) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "@" {
		return name, nil
	}
	if !validDNSName(name, true) {
		return "", fmt.Errorf("%w: %q is not a valid DNS name", ErrInvalid, name)
	}
	return name, nil
}

// DCHost is a domain controller as AD lists it.
type DCHost struct {
	Name     string // computer name, e.g. "DC1"
	DNSHost  string // dNSHostName, lower case
	DN       string
	ReadOnly bool
}

// DomainControllers lists the domain's DCs from their computer accounts
// (SERVER_TRUST_ACCOUNT, or PARTIAL_SECRETS_ACCOUNT for read-only DCs).
// Nothing is hardcoded: callers use it for DNS protection, lockout views
// and the like.
func (c *Conn) DomainControllers(ctx context.Context) ([]DCHost, error) {
	const partialSecrets = 0x4000000
	f := escape.And(escape.Eq("objectClass", "computer"),
		escape.Or(escape.BitAnd("userAccountControl", uint32(UACServerTrustAccount)), escape.BitAnd("userAccountControl", partialSecrets)))
	var out []DCHost
	for e, err := range c.Search(ctx, SearchRequest{Filter: f, Attributes: []string{"cn", "dNSHostName", "userAccountControl"}, SortBy: "cn"}) {
		if err != nil {
			return nil, err
		}
		uac := uint32(attrInt64(e, "userAccountControl"))
		out = append(out, DCHost{Name: e.GetAttributeValue("cn"), DNSHost: strings.ToLower(e.GetAttributeValue("dNSHostName")),
			DN: e.DN, ReadOnly: uac&partialSecrets != 0 && uac&uint32(UACServerTrustAccount) == 0})
	}
	return out, nil
}

// DNSPolicy says which zones and records belong to AD itself. Build it
// with Conn.DNSPolicy; the operations below refuse to touch what it
// protects (ErrProtectedObject).
type DNSPolicy struct {
	Domain  string   // the domain's DNS name
	Forest  string   // the forest root's DNS name
	DCHosts []string // FQDNs of the DCs (discovered, never hardcoded)
}

// DNSPolicy builds the protection rules from the directory.
func (c *Conn) DNSPolicy(ctx context.Context) (DNSPolicy, error) {
	dcs, err := c.DomainControllers(ctx)
	if err != nil {
		return DNSPolicy{}, err
	}
	p := DNSPolicy{Domain: c.dnsDomain, Forest: dnsNameOfDN(c.forestDN)}
	for _, d := range dcs {
		if d.DNSHost != "" {
			p.DCHosts = append(p.DCHosts, d.DNSHost)
		}
	}
	return p, nil
}

// dnsNameOfDN turns "DC=lab,DC=example,DC=com" into "lab.example.com".
func dnsNameOfDN(dn string) string {
	parsed, err := escape.ParseDN(dn)
	if err != nil {
		return ""
	}
	var labels []string
	for _, r := range parsed.RDNs {
		for _, a := range r.Attributes {
			if strings.EqualFold(a.Type, "DC") {
				labels = append(labels, strings.ToLower(a.Value))
			}
		}
	}
	return strings.Join(labels, ".")
}

// ADZone reports a zone AD itself needs (the domain zone and the forest's
// _msdcs zone): it can never be deleted.
func (p DNSPolicy) ADZone(zone string) bool {
	z := strings.ToLower(strings.TrimSuffix(zone, "."))
	return z == strings.ToLower(p.Domain) || z == "_msdcs."+strings.ToLower(p.Forest)
}

// ProtectedRecord reports whether a record of type t at name (relative to
// zone) is managed by AD and must stay read-only:
//   - in every zone: the apex SOA and NS records (they belong to the zone);
//   - in the _msdcs zone: everything;
//   - in the domain zone: names with a label starting with "_" (SRV
//     locators: _ldap, _kerberos, _gc, _kpasswd, _msdcs delegation…), the
//     DomainDnsZones/ForestDnsZones names, the apex A/AAAA records (the
//     DCs' addresses) and the host records of every DC.
func (p DNSPolicy) ProtectedRecord(zone, name string, t DNSType) bool {
	z := strings.ToLower(strings.TrimSuffix(zone, "."))
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	apex := n == "@" || n == ""
	if apex && (t == DNSTypeSOA || t == DNSTypeNS) {
		return true
	}
	if z == "_msdcs."+strings.ToLower(p.Forest) {
		return true
	}
	if z != strings.ToLower(p.Domain) {
		return false
	}
	if apex {
		return t == DNSTypeA || t == DNSTypeAAAA
	}
	for _, l := range strings.Split(n, ".") {
		if strings.HasPrefix(l, "_") || l == "domaindnszones" || l == "forestdnszones" {
			return true
		}
	}
	for _, h := range p.DCHosts {
		if strings.EqualFold(n+"."+z, h) {
			return true
		}
	}
	return false
}

// ProtectedNode reports a name whose every record is AD-managed (the UI
// shows it read-only).
func (p DNSPolicy) ProtectedNode(zone string, n DNSNode) bool {
	if len(n.Records) == 0 {
		return p.ProtectedRecord(zone, n.Name, DNSTypeA)
	}
	for _, r := range n.Records {
		if !p.ProtectedRecord(zone, n.Name, r.Type) {
			return false
		}
	}
	return true
}

// ---- operations ----

// soaChange builds the SOA serial increment of a zone's apex that goes
// with every record change (as Samba's DNS RPC server does), so secondary
// servers see the change. The old SOA value is deleted by its exact bytes,
// so a concurrent change of the zone fails with ErrConflict.
func soaChange(apex DNSNode) (Change, uint32, error) {
	for _, r := range apex.Records {
		if r.Type != DNSTypeSOA {
			continue
		}
		old, err := soaSerial(r)
		if err != nil {
			return Change{}, 0, err
		}
		next := old + 1
		if next == 0 {
			next = 1
		}
		nr := withSOASerial(r, next)
		raw, err := EncodeDNSRecord(nr)
		if err != nil {
			return Change{}, 0, err
		}
		return Change{Type: ChangeModify, DN: apex.DN,
			Notes: []string{fmt.Sprintf("zone serial %d -> %d", old, next)},
			Attrs: []AttrChange{
				binaryAttr(ModDelete, "dnsRecord", r.raw, "SOA "+r.Data),
				binaryAttr(ModAdd, "dnsRecord", raw, "SOA "+nr.Data),
			}}, next, nil
	}
	return Change{}, 0, fmt.Errorf("%w: the zone has no SOA record", ErrNotFound)
}

// binaryAttr is an attribute change whose value is binary: the preview
// shows it base64-encoded (LDIF), with the decoded form in a note.
func binaryAttr(op ModOp, name string, value []byte, display string) AttrChange {
	return AttrChange{Op: op, Name: name, Values: []string{string(value)}, Display: []string{display}}
}

func checkRecordTarget(z DNSZone, p DNSPolicy, name string, t DNSType) error {
	if p.ProtectedRecord(z.Name, name, t) {
		return fmt.Errorf("%w: %s record at %q in %s is managed by AD", ErrProtectedObject, t, name, z.Name)
	}
	return nil
}

// AddDNSRecord adds a record to a name of the zone (creating the name when
// it has no object yet), with the zone's SOA serial incremented. apex is
// the zone's "@" node as read; node is the target name as read by
// DNSNodeByName.
func AddDNSRecord(z DNSZone, p DNSPolicy, apex, node DNSNode, rec DNSRecord) (*Operation, error) {
	if err := checkRecordTarget(z, p, node.Name, rec.Type); err != nil {
		return nil, err
	}
	live := node.Records
	if node.Tombstoned {
		live = nil
	}
	for _, r := range live {
		if r.Equal(rec) {
			return nil, fmt.Errorf("%w: %s %s already exists", ErrAlreadyExists, rec.Type, rec.Data)
		}
		if (r.Type == DNSTypeCNAME) != (rec.Type == DNSTypeCNAME) {
			return nil, fmt.Errorf("%w: a CNAME cannot share a name with other records", ErrInvalid)
		}
	}
	soa, serial, err := soaChange(apex)
	if err != nil {
		return nil, err
	}
	rec.Serial, rec.Rank, rec.Timestamp = serial, dnsRankZone, 0
	raw, err := EncodeDNSRecord(rec)
	if err != nil {
		return nil, err
	}
	note := fmt.Sprintf("add %s %s (ttl %d) at %s", rec.Type, rec.Data, rec.TTL, node.FQDN(z.Name))
	var ch Change
	switch {
	case !node.Exists:
		ch = Change{Type: ChangeAdd, DN: node.DN, Notes: []string{note}, Attrs: []AttrChange{
			{Name: "objectClass", Values: []string{"top", "dnsNode"}},
			{Name: "dnsRecord", Values: []string{string(raw)}, Display: []string{rec.String()}},
		}}
	case node.Tombstoned:
		ch = Change{Type: ChangeModify, DN: node.DN, Notes: []string{note, "the name was tombstoned; it comes back"}, Attrs: []AttrChange{
			{Op: ModReplace, Name: "dnsRecord", Values: []string{string(raw)}, Display: []string{rec.String()}},
			{Op: ModReplace, Name: "dNSTombstoned", Values: []string{"FALSE"}},
		}}
	default:
		ch = Change{Type: ChangeModify, DN: node.DN, Notes: []string{note}, Attrs: []AttrChange{binaryAttr(ModAdd, "dnsRecord", raw, rec.String())}}
	}
	return &Operation{preview: Preview{Summary: note, Changes: []Change{soa, ch}}}, nil
}

// UpdateDNSRecord replaces one record of a name with a new value of the
// same type (data and/or TTL), deleting the old value by its exact bytes.
func UpdateDNSRecord(z DNSZone, p DNSPolicy, apex, node DNSNode, old DNSRecord, rec DNSRecord) (*Operation, error) {
	if err := checkRecordTarget(z, p, node.Name, old.Type); err != nil {
		return nil, err
	}
	if rec.Type != old.Type {
		return nil, fmt.Errorf("%w: the record type cannot change", ErrInvalid)
	}
	if old.Data == rec.Data && old.TTL == rec.TTL {
		return nil, ErrNoChange
	}
	if len(old.raw) == 0 {
		return nil, fmt.Errorf("%w: the old record was not read", ErrInvalid)
	}
	for _, r := range node.Records {
		if r.Equal(rec) && !r.Equal(old) {
			return nil, fmt.Errorf("%w: %s %s already exists", ErrAlreadyExists, rec.Type, rec.Data)
		}
	}
	soa, serial, err := soaChange(apex)
	if err != nil {
		return nil, err
	}
	rec.Serial, rec.Rank, rec.Timestamp = serial, dnsRankZone, 0
	raw, err := EncodeDNSRecord(rec)
	if err != nil {
		return nil, err
	}
	note := fmt.Sprintf("change %s at %s: %s (ttl %d) -> %s (ttl %d)", rec.Type, node.FQDN(z.Name), old.Data, old.TTL, rec.Data, rec.TTL)
	ch := Change{Type: ChangeModify, DN: node.DN, Notes: []string{note}, Attrs: []AttrChange{
		binaryAttr(ModDelete, "dnsRecord", old.raw, old.String()),
		binaryAttr(ModAdd, "dnsRecord", raw, rec.String()),
	}}
	return &Operation{preview: Preview{Summary: note, Changes: []Change{soa, ch}}}, nil
}

// DeleteDNSRecord removes one record; the name's object goes away with its
// last record.
func DeleteDNSRecord(z DNSZone, p DNSPolicy, apex, node DNSNode, rec DNSRecord) (*Operation, error) {
	if err := checkRecordTarget(z, p, node.Name, rec.Type); err != nil {
		return nil, err
	}
	if len(rec.raw) == 0 {
		return nil, fmt.Errorf("%w: the record was not read", ErrInvalid)
	}
	soa, _, err := soaChange(apex)
	if err != nil {
		return nil, err
	}
	note := fmt.Sprintf("delete %s %s at %s", rec.Type, rec.Data, node.FQDN(z.Name))
	var ch Change
	if len(node.Records) == 1 && node.Name != "@" {
		ch = Change{Type: ChangeDelete, DN: node.DN, Notes: []string{note, "it is the name's last record: the name is deleted"},
			Assert: escape.EqBytes("dnsRecord", rec.raw)}
	} else {
		ch = Change{Type: ChangeModify, DN: node.DN, Notes: []string{note}, Attrs: []AttrChange{binaryAttr(ModDelete, "dnsRecord", rec.raw, rec.String())}}
	}
	return &Operation{preview: Preview{Summary: note, Changes: []Change{soa, ch}}}, nil
}

// ValidZoneName checks a zone name: a DNS name with at least two labels
// (forward) or an in-addr.arpa / ip6.arpa name (reverse).
func ValidZoneName(name string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if !validDNSName(n, false) || !strings.Contains(n, ".") || strings.HasPrefix(n, "_") {
		return "", fmt.Errorf("%w: %q is not a zone name", ErrInvalid, name)
	}
	return n, nil
}

// zoneProperties are the dNSProperty values Samba writes for a new primary
// zone (MS-DNSP 2.3.2.1): primary type, secure dynamic updates, no aging,
// 168 h refresh intervals.
func zoneProperties() [][]byte {
	prop := func(id uint32, data []byte) []byte {
		b := binary.LittleEndian.AppendUint32(nil, uint32(len(data))) // DataLength
		b = binary.LittleEndian.AppendUint32(b, 0)                    // NameLength
		b = binary.LittleEndian.AppendUint32(b, 0)                    // Flag
		b = binary.LittleEndian.AppendUint32(b, 1)                    // Version
		b = binary.LittleEndian.AppendUint32(b, id)                   // Id
		b = append(b, data...)
		return binary.LittleEndian.AppendUint32(b, 0) // Name
	}
	u32 := func(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
	return [][]byte{
		prop(0x01, u32(1)),    // DSPROPERTY_ZONE_TYPE: primary
		prop(0x02, []byte{2}), // DSPROPERTY_ZONE_ALLOW_UPDATE: secure only
		prop(0x08, make([]byte, 8)),
		prop(0x10, u32(168)), // DSPROPERTY_ZONE_NOREFRESH_INTERVAL (hours)
		prop(0x20, u32(168)), // DSPROPERTY_ZONE_REFRESH_INTERVAL (hours)
		prop(0x40, u32(0)),   // DSPROPERTY_ZONE_AGING_STATE: off
		prop(0x12, u32(0)),   // DSPROPERTY_ZONE_AGING_ENABLED_TIME
	}
}

// CreateDNSZone builds a new primary zone in a DNS partition container
// (Conn.DNSPartitionDN): the dnsZone object and its apex with an SOA
// (serial 1) and an NS record naming primary, the DC the user works with
// (Conn.DCHostName; never a hardcoded name).
func CreateDNSZone(containerDN, name, primary string, p DNSPolicy) (*Operation, error) {
	n, err := ValidZoneName(name)
	if err != nil {
		return nil, err
	}
	if p.ADZone(n) {
		return nil, fmt.Errorf("%w: %s is an AD zone", ErrProtectedObject, n)
	}
	host, err := cleanHost(primary)
	if err != nil {
		return nil, err
	}
	zdn, err := escape.ChildDN("DC", n, containerDN)
	if err != nil {
		return nil, err
	}
	apexDN, err := escape.ChildDN("DC", "@", zdn)
	if err != nil {
		return nil, err
	}
	soa := DNSRecord{Type: DNSTypeSOA, TTL: defaultDNSTTL, Rank: dnsRankZone, Serial: 1,
		Data: fmt.Sprintf("%s hostmaster.%s 1 900 600 86400 3600", host, n)}
	ns := DNSRecord{Type: DNSTypeNS, TTL: defaultDNSTTL, Rank: dnsRankZone, Serial: 1, Data: host}
	var vals, disp []string
	for _, r := range []DNSRecord{soa, ns} {
		raw, err := EncodeDNSRecord(r)
		if err != nil {
			return nil, err
		}
		vals = append(vals, string(raw))
		disp = append(disp, r.String())
	}
	var props []string
	for _, b := range zoneProperties() {
		props = append(props, string(b))
	}
	return &Operation{preview: Preview{Summary: "create DNS zone " + n, Changes: []Change{
		{Type: ChangeAdd, DN: zdn, Notes: []string{"primary zone, secure dynamic updates only, aging off"}, Attrs: []AttrChange{
			{Name: "objectClass", Values: []string{"top", "dnsZone"}},
			{Name: "dNSProperty", Values: props, Display: []string{"zone type: primary", "allow update: secure", "secure time: 0",
				"no-refresh interval: 168 h", "refresh interval: 168 h", "aging: off", "aging enabled time: 0"}},
		}},
		{Type: ChangeAdd, DN: apexDN, Notes: []string{"zone apex"}, Attrs: []AttrChange{
			{Name: "objectClass", Values: []string{"top", "dnsNode"}},
			{Name: "dnsRecord", Values: vals, Display: disp},
		}},
	}}}, nil
}

// DeleteDNSZone deletes a zone with all its names (tree delete). AD zones
// are refused. names is shown in the preview (Conn.CountDNSNodes).
func DeleteDNSZone(z DNSZone, p DNSPolicy, names int) (*Operation, error) {
	if p.ADZone(z.Name) {
		return nil, fmt.Errorf("%w: %s is an AD zone", ErrProtectedObject, z.Name)
	}
	if err := checkDN(z.DN); err != nil {
		return nil, err
	}
	return &Operation{preview: Preview{Summary: "delete DNS zone " + z.Name, Changes: []Change{
		{Type: ChangeDelete, DN: z.DN, TreeDelete: true, Notes: []string{fmt.Sprintf("deletes the zone %s and its %d names with all their records", z.Name, names)}},
	}}}, nil
}
