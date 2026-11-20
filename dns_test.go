package ad

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Values read from the lab's Samba 4.22 DC (ldbsearch of dnsRecord).
var labDNSRecords = []struct {
	b64  string
	typ  DNSType
	data string
	ttl  uint32
}{
	{"BAABAAXwAABuAAAAAAADhAAAAAAAAAAACl0ACg==", DNSTypeA, "10.93.0.10", 900},
	{"IAAhAAXwAABuAAAAAAADhAAAAAAAAAAAAAAAZAGFGAQDZGMxA2xhYgljb25kdWN0b3IEdGVzdAA=", DNSTypeSRV, "0 100 389 dc1.lab.conductor.test", 900},
	{"GgACAAXwAABuAAAAAAADhAAAAAAAAAAAGAQDZGMxA2xhYgljb25kdWN0b3IEdGVzdAA=", DNSTypeNS, "dc1.lab.conductor.test", 900},
	{"TwAGAAXwAABuAAAAAAAOEAAAAAAAAAAAAAAAAgAAA4QAAAJYAAFRgAAADhAYBANkYzIDbGFiCWNvbmR1Y3RvcgR0ZXN0AB8ECmhvc3RtYXN0ZXIDbGFiCWNvbmR1Y3RvcgR0ZXN0AA==",
		DNSTypeSOA, "dc2.lab.conductor.test hostmaster.lab.conductor.test 2 900 600 86400 3600", 3600},
}

func TestDNSRecordDecodeLabValues(t *testing.T) {
	for _, c := range labDNSRecords {
		raw, _ := base64.StdEncoding.DecodeString(c.b64)
		r, err := DecodeDNSRecord(raw)
		if err != nil {
			t.Fatalf("%s: %v", c.b64, err)
		}
		if r.Type != c.typ || r.Data != c.data || r.TTL != c.ttl || r.Rank != dnsRankZone || r.Serial != 110 {
			t.Errorf("decoded %+v, want %s %q ttl %d", r, c.typ, c.data, c.ttl)
		}
		// Encoding the decoded record gives back the exact bytes.
		again, err := EncodeDNSRecord(r)
		if err != nil || !bytes.Equal(again, raw) {
			t.Errorf("%s: re-encoded %x, want %x (%v)", c.typ, again, raw, err)
		}
	}
}

func TestNewDNSRecordNormalizes(t *testing.T) {
	ok := []struct {
		t          DNSType
		in, want   string
		roundTrips bool
	}{
		{DNSTypeA, " 192.0.2.7 ", "192.0.2.7", true},
		{DNSTypeAAAA, "2001:DB8::0:1", "2001:db8::1", true},
		{DNSTypeCNAME, "WWW.Example.com.", "www.example.com", true},
		{DNSTypeMX, "10  mail.example.com", "10 mail.example.com", true},
		{DNSTypeSRV, "0 5 443 web.example.com.", "0 5 443 web.example.com", true},
		{DNSTypeTXT, "v=spf1 mx -all", `"v=spf1 mx -all"`, true},
		{DNSTypeTXT, `"a b" "c\"d"`, `"a b" "c\"d"`, true},
		{DNSTypeTXT, strings.Repeat("x", 300), `"` + strings.Repeat("x", 255) + `" "` + strings.Repeat("x", 45) + `"`, true},
		{DNSTypePTR, "host.example.com", "host.example.com", true},
		{DNSTypeNS, "ns1.example.com", "ns1.example.com", true},
	}
	for _, c := range ok {
		r, err := NewDNSRecord(c.t, c.in, 0)
		if err != nil || r.Data != c.want || r.TTL != 3600 {
			t.Errorf("%s %q: %+v %v, want %q", c.t, c.in, r, err, c.want)
			continue
		}
		raw, err := EncodeDNSRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		back, err := DecodeDNSRecord(raw)
		if err != nil || back.Data != r.Data || back.Type != r.Type {
			t.Errorf("%s round trip: %+v %v", c.t, back, err)
		}
	}
	bad := []struct {
		t  DNSType
		in string
	}{
		{DNSTypeA, "2001:db8::1"}, {DNSTypeA, "300.1.1.1"}, {DNSTypeAAAA, "192.0.2.1"}, {DNSTypeCNAME, "bad name"},
		{DNSTypeCNAME, "-x.example"}, {DNSTypeMX, "mail.example.com"}, {DNSTypeMX, "70000 mail"}, {DNSTypeSRV, "1 2 3"},
		{DNSTypeSRV, "a b c host"}, {DNSTypeTXT, `"unbalanced`}, {DNSTypeTXT, "bell\a"}, {DNSTypeSOA, "x"}, {DNSTypeA, ""},
		{DNSTypeCNAME, "*.example.com"},
	}
	for _, c := range bad {
		if _, err := NewDNSRecord(c.t, c.in, 0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s %q: accepted (%v)", c.t, c.in, err)
		}
	}
}

func TestDecodeDNSRecordRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 10), append(make([]byte, 24), 9), {0xff, 0, 1, 0, 5, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, err := DecodeDNSRecord(b); err == nil {
			t.Errorf("%x accepted", b)
		}
	}
	// A name whose label runs past the data.
	raw, _ := EncodeDNSRecord(DNSRecord{Type: DNSTypeCNAME, Data: "a.example", TTL: 1})
	raw[dnsRecordHdr+2] = 60
	if _, err := DecodeDNSRecord(raw); err == nil {
		t.Error("overlong label accepted")
	}
}

func FuzzDecodeDNSRecord(f *testing.F) {
	for _, c := range labDNSRecords {
		raw, _ := base64.StdEncoding.DecodeString(c.b64)
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeDNSRecord(b)
		if err != nil {
			return
		}
		_ = r.String()
	})
}

var testDNSPolicy = DNSPolicy{Domain: "lab.example", Forest: "lab.example", DCHosts: []string{"dc1.lab.example", "dc2.lab.example"}}

func TestDNSPolicyProtection(t *testing.T) {
	p := testDNSPolicy
	if !p.ADZone("lab.example") || !p.ADZone("_msdcs.lab.example.") || p.ADZone("apps.example") {
		t.Fatal("AD zones")
	}
	cases := []struct {
		zone, name string
		t          DNSType
		want       bool
	}{
		{"lab.example", "@", DNSTypeSOA, true},
		{"lab.example", "@", DNSTypeNS, true},
		{"lab.example", "@", DNSTypeA, true},
		{"lab.example", "@", DNSTypeMX, false},
		{"lab.example", "@", DNSTypeTXT, false},
		{"lab.example", "_ldap._tcp", DNSTypeSRV, true},
		{"lab.example", "_kerberos._tcp.Default-First-Site-Name._sites", DNSTypeSRV, true},
		{"lab.example", "DomainDnsZones", DNSTypeA, true},
		{"lab.example", "dc1", DNSTypeA, true},
		{"lab.example", "DC2", DNSTypeA, true},
		{"lab.example", "intranet", DNSTypeA, false},
		{"lab.example", "dc3", DNSTypeA, false},
		{"_msdcs.lab.example", "gc", DNSTypeA, true},
		{"apps.example", "@", DNSTypeSOA, true},
		{"apps.example", "@", DNSTypeMX, false},
		{"apps.example", "_http._tcp", DNSTypeSRV, false},
		{"apps.example", "dc1", DNSTypeA, false},
	}
	for _, c := range cases {
		if got := p.ProtectedRecord(c.zone, c.name, c.t); got != c.want {
			t.Errorf("%s / %s %s: protected=%v, want %v", c.zone, c.name, c.t, got, c.want)
		}
	}
}

// TestDNSPolicyADOwnedNames checks that only the names AD registers are
// protected (Samba's dns_update_list and provisioning), not every name with
// a label starting with "_" (openbasalt/samba-conductor#38).
func TestDNSPolicyADOwnedNames(t *testing.T) {
	single := testDNSPolicy
	child := DNSPolicy{Domain: "child.lab.example", Forest: "lab.example", DCHosts: []string{"dc9.child.lab.example"}}
	const site = "Default-First-Site-Name"
	// Every locator Samba registers, relative to the zone that holds it in
	// a single-domain forest (the domain zone is also the forest zone).
	locators := []string{
		"_ldap._tcp", "_kerberos._tcp", "_kerberos._udp", "_kpasswd._tcp", "_kpasswd._udp", "_gc._tcp",
		"_ldap._tcp." + site + "._sites", "_kerberos._tcp." + site + "._sites", "_gc._tcp." + site + "._sites",
		"_ldap._tcp.dc._msdcs", "_kerberos._tcp.dc._msdcs", "_ldap._tcp.pdc._msdcs", "_ldap._tcp.gc._msdcs",
		"_ldap._tcp." + site + "._sites.dc._msdcs", "_kerberos._tcp." + site + "._sites.dc._msdcs",
		"_ldap._tcp." + site + "._sites.gc._msdcs", "gc._msdcs",
		"_ldap._tcp.0f3b2c1d-1111-2222-3333-444455556666.domains._msdcs", "_msdcs",
		"DomainDnsZones", "ForestDnsZones", "_ldap._tcp.DomainDnsZones", "_ldap._tcp.ForestDnsZones",
		"_ldap._tcp." + site + "._sites.DomainDnsZones", "_ldap._tcp." + site + "._sites.ForestDnsZones",
		"_sites", "_tcp." + site + "._sites", "other._sites",
	}
	for _, n := range locators {
		for _, name := range []string{n, strings.ToUpper(n), strings.ToLower(n) + "."} {
			for _, typ := range []DNSType{DNSTypeSRV, DNSTypeA, DNSTypeTXT, DNSTypeCNAME} {
				if !single.ProtectedRecord("lab.example", name, typ) {
					t.Errorf("single-domain zone: %s %s not protected", name, typ)
				}
				if !child.ProtectedRecord("CHILD.lab.example.", name, typ) {
					t.Errorf("child domain zone: %s %s not protected", name, typ)
				}
				if !child.ProtectedRecord("lab.example", name, typ) {
					t.Errorf("forest root zone seen from a child domain: %s %s not protected", name, typ)
				}
			}
		}
	}
	// Names that start with "_" but belong to the administrator.
	allowed := []struct {
		name string
		t    DNSType
	}{
		{"selector._domainkey", DNSTypeTXT},
		{"S1._DomainKey", DNSTypeTXT},
		{"_domainkey", DNSTypeTXT},
		{"_dmarc", DNSTypeTXT},
		{"_acme-challenge", DNSTypeTXT},
		{"_acme-challenge.www", DNSTypeTXT},
		{"_mta-sts", DNSTypeTXT},
		{"_smtp._tls", DNSTypeTXT},
		{"_sip._tcp", DNSTypeSRV},
		{"_sip._udp", DNSTypeSRV},
		{"_xmpp-server._tcp", DNSTypeSRV},
		{"_kerberos-master._udp", DNSTypeSRV},
		{"_ldaps._tcp", DNSTypeSRV},
		{"_http._tcp.intranet", DNSTypeSRV},
		{"ldap._tcp", DNSTypeSRV},
		{"_ldap", DNSTypeTXT},
		{"_tcp", DNSTypeTXT},
		{"sites", DNSTypeA},
		{"msdcs", DNSTypeA},
	}
	for _, c := range allowed {
		if single.ProtectedRecord("lab.example", c.name, c.t) {
			t.Errorf("single-domain zone: %s %s protected", c.name, c.t)
		}
		if child.ProtectedRecord("child.lab.example", c.name, c.t) {
			t.Errorf("child domain zone: %s %s protected", c.name, c.t)
		}
		if child.ProtectedRecord("lab.example", c.name, c.t) {
			t.Errorf("forest root zone: %s %s protected", c.name, c.t)
		}
	}
	// The forest root zone of a child domain keeps its apex and host names
	// editable (they are the root domain's, outside this policy), except
	// the apex SOA and NS like every zone.
	if child.ProtectedRecord("lab.example", "@", DNSTypeA) || child.ProtectedRecord("lab.example", "dc9.child", DNSTypeA) {
		t.Error("forest root zone apex A or host protected")
	}
	if !child.ProtectedRecord("lab.example", "@", DNSTypeNS) {
		t.Error("forest root zone apex NS not protected")
	}
	// The domain zone rules that do not depend on the name stay.
	if !child.ProtectedRecord("child.lab.example", "@", DNSTypeAAAA) || !child.ProtectedRecord("child.lab.example", "DC9", DNSTypeA) {
		t.Error("child domain apex AAAA or DC host not protected")
	}
	// Everything in the forest's _msdcs zone stays protected, even names
	// that would be the administrator's elsewhere.
	if !child.ProtectedRecord("_msdcs.lab.example", "_dmarc", DNSTypeTXT) {
		t.Error("_msdcs zone record not protected")
	}
	// Other zones are the administrator's, apart from the apex SOA and NS.
	if single.ProtectedRecord("apps.example", "_ldap._tcp", DNSTypeSRV) || single.ProtectedRecord("apps.example", "_msdcs", DNSTypeNS) {
		t.Error("non-AD zone locator name protected")
	}
	// A DKIM record can be added and deleted in the domain zone.
	z := DNSZone{Name: "lab.example", DN: "DC=lab.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=example"}
	dkim := DNSRecord{Type: DNSTypeTXT, TTL: 3600, Data: `"v=DKIM1; k=rsa; p=MIIB"`}
	if _, err := AddDNSRecord(z, single, testApex(t, z.Name), DNSNode{Name: "sel._domainkey", DN: "DC=sel._domainkey," + z.DN}, dkim); err != nil {
		t.Fatalf("add DKIM: %v", err)
	}
}

func testApex(t *testing.T, zone string) DNSNode {
	t.Helper()
	soa := DNSRecord{Type: DNSTypeSOA, TTL: 3600, Rank: dnsRankZone, Serial: 1, Data: "dc1.lab.example hostmaster." + zone + " 41 900 600 86400 3600"}
	raw, err := EncodeDNSRecord(soa)
	if err != nil {
		t.Fatal(err)
	}
	soa.raw = raw
	return DNSNode{Name: "@", DN: "DC=@,DC=" + zone + ",CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=example", Exists: true, Records: []DNSRecord{soa}}
}

func TestAddUpdateDeleteDNSRecord(t *testing.T) {
	z := DNSZone{Name: "apps.example", DN: "DC=apps.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=example", Partition: DNSPartitionDomain}
	apex := testApex(t, z.Name)
	rec, _ := NewDNSRecord(DNSTypeA, "192.0.2.7", 600)
	node := DNSNode{Name: "www", DN: "DC=www," + z.DN}
	op, err := AddDNSRecord(z, testDNSPolicy, apex, node, rec)
	if err != nil {
		t.Fatal(err)
	}
	pv := op.Preview()
	if len(pv.Changes) != 2 || pv.Changes[0].DN != apex.DN || pv.Changes[1].Type != ChangeAdd {
		t.Fatalf("changes %+v", pv.Changes)
	}
	text := pv.String()
	for _, want := range []string{"zone serial 41 -> 42", "# dnsRecord: A 192.0.2.7 (ttl 600)", "dnsRecord:: ", "add A 192.0.2.7 (ttl 600) at www.apps.example"} {
		if !strings.Contains(text, want) {
			t.Errorf("preview lacks %q:\n%s", want, text)
		}
	}
	// The record carries the new zone serial.
	added, _ := DecodeDNSRecord([]byte(pv.Changes[1].Attrs[1].Values[0]))
	if added.Serial != 42 || added.TTL != 600 {
		t.Fatalf("added %+v", added)
	}
	// Existing name: a modify add; a duplicate is refused; CNAME rules.
	added.raw = []byte(pv.Changes[1].Attrs[1].Values[0])
	node = DNSNode{Name: "www", DN: node.DN, Exists: true, Records: []DNSRecord{added}}
	if _, err := AddDNSRecord(z, testDNSPolicy, apex, node, rec); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	cname, _ := NewDNSRecord(DNSTypeCNAME, "other.example", 0)
	if _, err := AddDNSRecord(z, testDNSPolicy, apex, node, cname); !errors.Is(err, ErrInvalid) {
		t.Fatalf("CNAME next to A: %v", err)
	}
	rec2, _ := NewDNSRecord(DNSTypeA, "192.0.2.8", 0)
	op, err = AddDNSRecord(z, testDNSPolicy, apex, node, rec2)
	if err != nil || op.Preview().Changes[1].Type != ChangeModify || op.Preview().Changes[1].Attrs[0].Op != ModAdd {
		t.Fatalf("add to existing name: %v", err)
	}
	// Update: delete the exact old bytes, add the new value.
	op, err = UpdateDNSRecord(z, testDNSPolicy, apex, node, added, rec2)
	if err != nil {
		t.Fatal(err)
	}
	ch := op.Preview().Changes[1]
	if ch.Attrs[0].Op != ModDelete || ch.Attrs[0].Values[0] != string(added.raw) || ch.Attrs[1].Op != ModAdd {
		t.Fatalf("update %+v", ch)
	}
	if _, err := UpdateDNSRecord(z, testDNSPolicy, apex, node, added, added); !errors.Is(err, ErrNoChange) {
		t.Fatalf("no-op update: %v", err)
	}
	// Delete of the last record deletes the name, conditionally.
	op, err = DeleteDNSRecord(z, testDNSPolicy, apex, node, added)
	if err != nil || op.Preview().Changes[1].Type != ChangeDelete || op.Preview().Changes[1].Assert == nil {
		t.Fatalf("delete last: %+v %v", op, err)
	}
	// Protected records are refused.
	adZone := DNSZone{Name: "lab.example", DN: "DC=lab.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=example"}
	srv, _ := NewDNSRecord(DNSTypeSRV, "0 100 389 dc9.lab.example", 0)
	if _, err := AddDNSRecord(adZone, testDNSPolicy, testApex(t, adZone.Name), DNSNode{Name: "_ldap._tcp", DN: "DC=_ldap._tcp," + adZone.DN}, srv); !errors.Is(err, ErrProtectedObject) {
		t.Fatalf("AD-managed record: %v", err)
	}
	if _, err := DeleteDNSRecord(adZone, testDNSPolicy, testApex(t, adZone.Name), DNSNode{Name: "dc1", Exists: true, Records: []DNSRecord{added}}, added); !errors.Is(err, ErrProtectedObject) {
		t.Fatalf("DC host record: %v", err)
	}
}

func TestCreateAndDeleteDNSZone(t *testing.T) {
	op, err := CreateDNSZone("CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=example", "New.Example.", "DC1.lab.example", testDNSPolicy)
	if err != nil {
		t.Fatal(err)
	}
	pv := op.Preview()
	if pv.Changes[0].DN != "DC=new.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=example" || len(pv.Changes[0].Attrs[1].Values) != 7 {
		t.Fatalf("zone %+v", pv.Changes[0])
	}
	for _, v := range pv.Changes[0].Attrs[1].Values {
		if len(v) < 25 {
			t.Fatalf("dNSProperty %x", v)
		}
	}
	soa, err := DecodeDNSRecord([]byte(pv.Changes[1].Attrs[1].Values[0]))
	if err != nil || soa.Data != "dc1.lab.example hostmaster.new.example 1 900 600 86400 3600" {
		t.Fatalf("SOA %+v %v", soa, err)
	}
	for _, name := range []string{"lab.example", "_msdcs.lab.example", "single", "bad name.example", "_x.example"} {
		if _, err := CreateDNSZone("CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=example", name, "dc1.lab.example", testDNSPolicy); err == nil {
			t.Errorf("zone %q accepted", name)
		}
	}
	if _, err := DeleteDNSZone(DNSZone{Name: "lab.example", DN: "DC=lab.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=example"}, testDNSPolicy, 3); !errors.Is(err, ErrProtectedObject) {
		t.Fatalf("delete AD zone: %v", err)
	}
	op, err = DeleteDNSZone(DNSZone{Name: "apps.example", DN: "DC=apps.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=example"}, testDNSPolicy, 3)
	if err != nil || !op.Preview().Changes[0].TreeDelete || !strings.Contains(op.Preview().String(), "control: 1.2.840.113556.1.4.805 true") {
		t.Fatalf("delete zone: %v\n%s", err, op.Preview())
	}
}

func TestDNSNameOfDN(t *testing.T) {
	if got := dnsNameOfDN("DC=Lab,DC=Conductor,DC=test"); got != "lab.conductor.test" {
		t.Fatal(got)
	}
}
