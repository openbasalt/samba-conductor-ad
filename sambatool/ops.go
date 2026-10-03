package sambatool

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// DNSRecordType is an allowlisted DNS record type.
type DNSRecordType string

// Supported record types.
const (
	DNSTypeA     DNSRecordType = "A"
	DNSTypeAAAA  DNSRecordType = "AAAA"
	DNSTypeCNAME DNSRecordType = "CNAME"
	DNSTypePTR   DNSRecordType = "PTR"
	DNSTypeTXT   DNSRecordType = "TXT"
	DNSTypeMX    DNSRecordType = "MX"
	DNSTypeSRV   DNSRecordType = "SRV"
	DNSTypeNS    DNSRecordType = "NS"
	DNSTypeALL   DNSRecordType = "ALL" // query only
)

func (t DNSRecordType) valid(forQuery bool) bool {
	switch t {
	case DNSTypeA, DNSTypeAAAA, DNSTypeCNAME, DNSTypePTR, DNSTypeTXT, DNSTypeMX, DNSTypeSRV, DNSTypeNS:
		return true
	case DNSTypeALL:
		return forQuery
	}
	return false
}

// validateRecordData checks the data of a record against its type.
func validateRecordData(t DNSRecordType, data string) error {
	if err := ValidateValue(data); err != nil {
		return err
	}
	switch t {
	case DNSTypeA:
		if a, err := netip.ParseAddr(data); err != nil || !a.Is4() {
			return fmt.Errorf("sambatool: %q is not an IPv4 address", data)
		}
	case DNSTypeAAAA:
		if a, err := netip.ParseAddr(data); err != nil || !a.Is6() {
			return fmt.Errorf("sambatool: %q is not an IPv6 address", data)
		}
	case DNSTypeCNAME, DNSTypePTR, DNSTypeNS:
		if !validDNSName(data) {
			return fmt.Errorf("sambatool: %q is not a DNS name", data)
		}
	case DNSTypeMX:
		host, pref, ok := strings.Cut(data, " ")
		if _, err := strconv.ParseUint(pref, 10, 16); !ok || err != nil || !validDNSName(host) {
			return fmt.Errorf("sambatool: MX data must be \"host preference\", got %q", data)
		}
	case DNSTypeSRV:
		f := strings.Fields(data)
		if len(f) != 4 || !validDNSName(f[0]) {
			return fmt.Errorf("sambatool: SRV data must be \"target port priority weight\", got %q", data)
		}
		for _, n := range f[1:] {
			if _, err := strconv.ParseUint(n, 10, 16); err != nil {
				return fmt.Errorf("sambatool: SRV data must be \"target port priority weight\", got %q", data)
			}
		}
	case DNSTypeTXT:
		if len(data) > 255 {
			return errors.New("sambatool: TXT data longer than 255")
		}
	}
	return nil
}

func checkServerZone(server, zone string) error {
	if !validServer(server) {
		return fmt.Errorf("sambatool: invalid DNS server %q", server)
	}
	if zone == "@" || !validDNSName(zone) {
		return fmt.Errorf("sambatool: invalid zone %q", zone)
	}
	return nil
}

// DNSZoneList lists the zones served by a DC: `samba-tool dns zonelist`.
type DNSZoneList struct{ Server string }

// Command implements Operation.
func (o DNSZoneList) Command() (Command, error) {
	if !validServer(o.Server) {
		return Command{}, fmt.Errorf("sambatool: invalid DNS server %q", o.Server)
	}
	return Command{Subcommand: []string{"dns", "zonelist"}, Args: []string{o.Server}}, nil
}

var zoneNameRE = regexp.MustCompile(`(?m)^\s*pszZoneName\s*:\s*(\S+)\s*$`)

// Parse implements Operation.
func (DNSZoneList) Parse(out []byte) ([]string, error) {
	var zones []string
	for _, m := range zoneNameRE.FindAllSubmatch(out, -1) {
		zones = append(zones, string(m[1]))
	}
	return zones, nil
}

// DNSRecord is one record from a query.
type DNSRecord struct {
	Name  string // relative to the zone; "" is the apex
	Type  string
	Data  string
	TTL   uint32
	Flags string
}

// DNSQuery queries records: `samba-tool dns query`.
type DNSQuery struct {
	Server, Zone, Name string
	Type               DNSRecordType
}

// Command implements Operation.
func (o DNSQuery) Command() (Command, error) {
	if err := checkServerZone(o.Server, o.Zone); err != nil {
		return Command{}, err
	}
	if !validDNSName(o.Name) {
		return Command{}, fmt.Errorf("sambatool: invalid record name %q", o.Name)
	}
	if !o.Type.valid(true) {
		return Command{}, fmt.Errorf("sambatool: record type %q not allowed", o.Type)
	}
	return Command{Subcommand: []string{"dns", "query"}, Args: []string{o.Server, o.Zone, o.Name, string(o.Type)}}, nil
}

var (
	queryNameRE   = regexp.MustCompile(`^\s*Name=([^,]*), Records=\d+, Children=\d+`)
	queryRecordRE = regexp.MustCompile(`^\s+([A-Z]+): (.*?)(?: \(flags=([0-9a-fA-F]+), serial=\d+, ttl=(\d+)\))?\s*$`)
)

// Parse implements Operation.
func (DNSQuery) Parse(out []byte) ([]DNSRecord, error) {
	var recs []DNSRecord
	name := ""
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if m := queryNameRE.FindStringSubmatch(line); m != nil {
			name = m[1]
			continue
		}
		if m := queryRecordRE.FindStringSubmatch(line); m != nil {
			ttl, _ := strconv.ParseUint(m[4], 10, 32)
			recs = append(recs, DNSRecord{Name: name, Type: m[1], Data: m[2], TTL: uint32(ttl), Flags: m[3]})
		}
	}
	return recs, sc.Err()
}

// DNSAddRecord adds a record: `samba-tool dns add`.
type DNSAddRecord struct {
	Server, Zone, Name string
	Type               DNSRecordType
	Data               string
}

// Command implements Operation.
func (o DNSAddRecord) Command() (Command, error) {
	return recordCommand("add", o.Server, o.Zone, o.Name, o.Type, o.Data)
}

// Parse implements Operation.
func (DNSAddRecord) Parse(out []byte) (struct{}, error) {
	return struct{}{}, expectOutput(out, "Record added successfully")
}

// DNSDeleteRecord deletes a record: `samba-tool dns delete`.
type DNSDeleteRecord struct {
	Server, Zone, Name string
	Type               DNSRecordType
	Data               string
}

// Command implements Operation.
func (o DNSDeleteRecord) Command() (Command, error) {
	return recordCommand("delete", o.Server, o.Zone, o.Name, o.Type, o.Data)
}

// Parse implements Operation.
func (DNSDeleteRecord) Parse(out []byte) (struct{}, error) {
	return struct{}{}, expectOutput(out, "Record deleted successfully")
}

func recordCommand(verb, server, zone, name string, t DNSRecordType, data string) (Command, error) {
	if err := checkServerZone(server, zone); err != nil {
		return Command{}, err
	}
	if !validDNSName(name) {
		return Command{}, fmt.Errorf("sambatool: invalid record name %q", name)
	}
	if !t.valid(false) {
		return Command{}, fmt.Errorf("sambatool: record type %q not allowed", t)
	}
	if err := validateRecordData(t, data); err != nil {
		return Command{}, err
	}
	return Command{Subcommand: []string{"dns", verb}, Args: []string{server, zone, name, string(t), data}}, nil
}

func expectOutput(out []byte, want string) error {
	if !bytes.Contains(out, []byte(want)) {
		return fmt.Errorf("sambatool: unexpected output: %q", strings.TrimSpace(string(out)))
	}
	return nil
}

// DomainLevel is the output of `samba-tool domain level show`.
type DomainLevel struct {
	Forest, Domain, LowestDC string
}

// DomainLevelShow reads the functional levels: `samba-tool domain level show`.
type DomainLevelShow struct {
	// URL of the DC, e.g. "ldap://dc1.lab.example" (empty: local sam.ldb).
	URL string
}

var urlRE = regexp.MustCompile(`^(ldaps?|tdb)://[A-Za-z0-9._/-]+$`)

// Command implements Operation.
func (o DomainLevelShow) Command() (Command, error) {
	c := Command{Subcommand: []string{"domain", "level", "show"}}
	if o.URL != "" {
		if !urlRE.MatchString(o.URL) {
			return Command{}, fmt.Errorf("sambatool: invalid URL %q", o.URL)
		}
		c.Options = append(c.Options, "--URL="+o.URL)
	}
	return c, nil
}

var levelRE = regexp.MustCompile(`(?m)^(Forest|Domain) function level: (.+?)\s*$|^Lowest function level of a DC: (.+?)\s*$`)

// Parse implements Operation.
func (DomainLevelShow) Parse(out []byte) (DomainLevel, error) {
	var l DomainLevel
	for _, m := range levelRE.FindAllStringSubmatch(string(out), -1) {
		switch {
		case m[1] == "Forest":
			l.Forest = m[2]
		case m[1] == "Domain":
			l.Domain = m[2]
		case m[3] != "":
			l.LowestDC = m[3]
		}
	}
	if l.Domain == "" {
		return l, fmt.Errorf("sambatool: no domain level in output %q", strings.TrimSpace(string(out)))
	}
	return l, nil
}

// ReplicationStatus is the parsed `samba-tool drs showrepl --json`.
type ReplicationStatus struct {
	Server   string        `json:"server"`
	Site     string        `json:"site"`
	RepsFrom []Replication `json:"repsFrom"`
	RepsTo   []Replication `json:"repsTo"`
}

// Replication is one naming context link with a partner DC.
type Replication struct {
	NamingContext       string `json:"NC dn"`
	DSA                 string `json:"DSA"`
	LastAttempt         string `json:"last attempt time"`
	LastAttemptMessage  string `json:"last attempt message"`
	LastSuccess         string `json:"last success"`
	ConsecutiveFailures int    `json:"consecutive failures"`
	IsDeleted           bool   `json:"is deleted"`
}

// Healthy reports whether every inbound link succeeded on its last attempt.
func (r ReplicationStatus) Healthy() bool {
	for _, l := range r.RepsFrom {
		if l.ConsecutiveFailures > 0 {
			return false
		}
	}
	return len(r.RepsFrom) > 0
}

// DRSShowRepl reads the replication status of a DC (default: local).
type DRSShowRepl struct{ DC string }

// Command implements Operation.
func (o DRSShowRepl) Command() (Command, error) {
	c := Command{Subcommand: []string{"drs", "showrepl"}, Options: []string{"--json"}}
	if o.DC != "" {
		if !validServer(o.DC) {
			return Command{}, fmt.Errorf("sambatool: invalid DC %q", o.DC)
		}
		c.Args = []string{o.DC}
	}
	return c, nil
}

// Parse implements Operation.
func (DRSShowRepl) Parse(out []byte) (ReplicationStatus, error) {
	var r ReplicationStatus
	if err := json.Unmarshal(out, &r); err != nil {
		return r, fmt.Errorf("sambatool: decoding showrepl JSON: %w", err)
	}
	return r, nil
}

// DomainBackupOnline takes an online backup from a DC:
// `samba-tool domain backup online --server=DC --targetdir=DIR`. The result is
// the path of the backup file when samba-tool reports it on stdout (it
// usually logs to stderr, so callers should give it an empty target
// directory and look for the one samba-backup-*.tar.bz2 file there). Run
// it from the privileged helper with the backup account's credentials.
type DomainBackupOnline struct {
	Server    string
	TargetDir string // absolute, simple characters only
}

var pathRE = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// Command implements Operation.
func (o DomainBackupOnline) Command() (Command, error) {
	if !validServer(o.Server) || strings.HasPrefix(o.Server, "-") {
		return Command{}, fmt.Errorf("sambatool: invalid server %q", o.Server)
	}
	if !pathRE.MatchString(o.TargetDir) || strings.Contains(o.TargetDir, "..") {
		return Command{}, fmt.Errorf("sambatool: invalid target directory %q", o.TargetDir)
	}
	return Command{Subcommand: []string{"domain", "backup", "online"},
		Options: []string{"--server=" + o.Server, "--targetdir=" + o.TargetDir}}, nil
}

var backupFileRE = regexp.MustCompile(`(?m)(/\S+\.tar\.bz2)`)

// Parse implements Operation: the reported backup file, or "" when stdout
// does not name it (the caller then looks in the target directory).
func (DomainBackupOnline) Parse(out []byte) (string, error) {
	m := backupFileRE.FindSubmatch(out)
	if m == nil {
		return "", nil
	}
	return string(m[1]), nil
}

// netbiosRE is a NetBIOS computer name (what --newservername takes).
var netbiosRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)

// DomainBackupRestore restores a backup file into a new DC database:
// `samba-tool domain backup restore --backup-file=F --targetdir=D
// --newservername=N [--host-ip=IP]`. The original SIDs and GUIDs are kept;
// the old DCs are removed from the restored database and every FSMO role is
// seized by the new one. Runs as root on the host that becomes the DC (or
// in a restore drill's sandbox). TargetDir must not exist or be empty.
type DomainBackupRestore struct {
	BackupFile    string
	TargetDir     string
	NewServerName string
	// HostIP is optional (only used by samba for renamed-domain backups).
	HostIP string
}

// Command implements Operation.
func (o DomainBackupRestore) Command() (Command, error) {
	for _, p := range []string{o.BackupFile, o.TargetDir} {
		if !pathRE.MatchString(p) || strings.Contains(p, "..") {
			return Command{}, fmt.Errorf("sambatool: invalid path %q", p)
		}
	}
	if !netbiosRE.MatchString(o.NewServerName) {
		return Command{}, fmt.Errorf("sambatool: invalid server name %q", o.NewServerName)
	}
	c := Command{Subcommand: []string{"domain", "backup", "restore"},
		Options: []string{"--backup-file=" + o.BackupFile, "--targetdir=" + o.TargetDir, "--newservername=" + o.NewServerName}}
	if o.HostIP != "" {
		ip, err := netip.ParseAddr(o.HostIP)
		if err != nil || !ip.Is4() {
			return Command{}, fmt.Errorf("sambatool: invalid IPv4 address %q", o.HostIP)
		}
		c.Options = append(c.Options, "--host-ip="+ip.String())
	}
	return c, nil
}

// Parse implements Operation: samba-tool ends with "Backup file
// successfully restored to …" (stdout).
func (DomainBackupRestore) Parse(out []byte) (struct{}, error) {
	return struct{}{}, expectOutput(out, "successfully restored")
}

// checkLDAPURL accepts only ldap:// or ldaps:// URLs of a host (no path).
func checkLDAPURL(u string) error {
	if !urlRE.MatchString(u) || !(strings.HasPrefix(u, "ldap://") || strings.HasPrefix(u, "ldaps://")) ||
		strings.Count(u, "/") != 2 {
		return fmt.Errorf("sambatool: invalid LDAP URL %q", u)
	}
	return nil
}

// UserList lists the sAMAccountName of every normal user account
// (userAccountControl NORMAL_ACCOUNT, disabled ones included):
// `samba-tool user list --URL=URL`. Used by restore drills to count users
// over LDAP with the probe account's credentials.
type UserList struct {
	URL string // ldap://host
}

// Command implements Operation.
func (o UserList) Command() (Command, error) {
	if err := checkLDAPURL(o.URL); err != nil {
		return Command{}, err
	}
	return Command{Subcommand: []string{"user", "list"}, Options: []string{"--URL=" + o.URL}}, nil
}

// Parse implements Operation: one name per line.
func (UserList) Parse(out []byte) ([]string, error) {
	var names []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			names = append(names, line)
		}
	}
	return names, sc.Err()
}

// ObjectKind selects `samba-tool user show` or `samba-tool group show`.
type ObjectKind string

// Object kinds for ObjectSID.
const (
	KindUser  ObjectKind = "user"
	KindGroup ObjectKind = "group"
)

// ObjectSID reads the objectSid of a user or group by sAMAccountName:
// `samba-tool user|group show --attributes=objectSid --URL=URL -- NAME`.
type ObjectSID struct {
	Kind ObjectKind
	Name string
	URL  string // ldap://host
}

// Command implements Operation.
func (o ObjectSID) Command() (Command, error) {
	if o.Kind != KindUser && o.Kind != KindGroup {
		return Command{}, fmt.Errorf("sambatool: invalid object kind %q", o.Kind)
	}
	if err := ValidateValue(o.Name); err != nil {
		return Command{}, err
	}
	if len(o.Name) > 256 {
		return Command{}, errors.New("sambatool: name too long")
	}
	if err := checkLDAPURL(o.URL); err != nil {
		return Command{}, err
	}
	return Command{Subcommand: []string{string(o.Kind), "show"}, Options: []string{"--attributes=objectSid", "--URL=" + o.URL},
		Args: []string{o.Name}}, nil
}

var objectSIDRE = regexp.MustCompile(`(?m)^objectSid: (S-1-[0-9-]+)\s*$`)

// Parse implements Operation.
func (ObjectSID) Parse(out []byte) (string, error) {
	m := objectSIDRE.FindSubmatch(out)
	if m == nil {
		return "", errors.New("sambatool: no objectSid in output")
	}
	return string(m[1]), nil
}

// FSMORole is one operations-master role and the NTDS Settings DN of its
// owner.
type FSMORole struct {
	Role  string // e.g. "SchemaMasterRole", "PdcEmulationMasterRole"
	Owner string
}

// FSMOShow lists the FSMO role owners: `samba-tool fsmo show`.
type FSMOShow struct {
	// URL of the DC (empty: local sam.ldb).
	URL string
}

// Command implements Operation.
func (o FSMOShow) Command() (Command, error) {
	c := Command{Subcommand: []string{"fsmo", "show"}}
	if o.URL != "" {
		if !urlRE.MatchString(o.URL) {
			return Command{}, fmt.Errorf("sambatool: invalid URL %q", o.URL)
		}
		c.Options = append(c.Options, "--URL="+o.URL)
	}
	return c, nil
}

var fsmoRE = regexp.MustCompile(`(?m)^([A-Za-z]+Role) owner: (.+?)\s*$`)

// Parse implements Operation.
func (FSMOShow) Parse(out []byte) ([]FSMORole, error) {
	var roles []FSMORole
	for _, m := range fsmoRE.FindAllStringSubmatch(string(out), -1) {
		roles = append(roles, FSMORole{Role: m[1], Owner: m[2]})
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("sambatool: no FSMO roles in output %q", strings.TrimSpace(string(out)))
	}
	return roles, nil
}

// GroupListMembers lists the direct members of a group by DN:
// `samba-tool group listmembers --full-dn -- GROUP`.
type GroupListMembers struct {
	Group string // sAMAccountName of the group
	// URL of the DC (empty: local sam.ldb).
	URL string
}

// Command implements Operation.
func (o GroupListMembers) Command() (Command, error) {
	if err := ValidateValue(o.Group); err != nil {
		return Command{}, err
	}
	if len(o.Group) > 256 {
		return Command{}, errors.New("sambatool: group name too long")
	}
	c := Command{Subcommand: []string{"group", "listmembers"}, Options: []string{"--full-dn"}, Args: []string{o.Group}}
	if o.URL != "" {
		if !urlRE.MatchString(o.URL) {
			return Command{}, fmt.Errorf("sambatool: invalid URL %q", o.URL)
		}
		c.Options = append(c.Options, "--URL="+o.URL)
	}
	return c, nil
}

// Parse implements Operation: one DN per line.
func (GroupListMembers) Parse(out []byte) ([]string, error) {
	var dns []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.Contains(line, "=") {
			return nil, fmt.Errorf("sambatool: unexpected listmembers line %q", line)
		}
		dns = append(dns, line)
	}
	return dns, sc.Err()
}

// gpoIDRE is the "{GUID}" name of a GPO.
var gpoIDRE = regexp.MustCompile(`\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}`)

func checkGPOURL(u string) error {
	if !urlRE.MatchString(u) || !strings.HasPrefix(u, "ldap") {
		return fmt.Errorf("sambatool: invalid URL %q (ldap:// or ldaps:// of a DC)", u)
	}
	return nil
}

// GPOCreate creates an empty GPO (the groupPolicyContainer in LDAP and its
// folder in SYSVOL): `samba-tool gpo create -Hldap://DC -- NAME`. Run it
// with the caller's own credentials (KerberosCCache); AD decides whether
// the caller may create GPOs. The result is the new GPO's "{GUID}".
type GPOCreate struct {
	DisplayName string
	// URL of the DC, e.g. "ldap://dc1.example.com" (required).
	URL string
}

// Command implements Operation.
func (o GPOCreate) Command() (Command, error) {
	if err := ValidateValue(o.DisplayName); err != nil {
		return Command{}, err
	}
	if len([]rune(o.DisplayName)) > 200 || strings.ContainsAny(o.DisplayName, "\\\"") {
		return Command{}, fmt.Errorf("sambatool: invalid GPO name %q", o.DisplayName)
	}
	if err := checkGPOURL(o.URL); err != nil {
		return Command{}, err
	}
	return Command{Subcommand: []string{"gpo", "create"}, Options: []string{"-H" + o.URL}, Args: []string{o.DisplayName}}, nil
}

var gpoCreatedRE = regexp.MustCompile(`created as (\{[0-9A-Fa-f-]{36}\})`)

// Parse implements Operation.
func (GPOCreate) Parse(out []byte) (string, error) {
	m := gpoCreatedRE.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("sambatool: GPO id not reported: %q", strings.TrimSpace(string(out)))
	}
	return strings.ToUpper(string(m[1])), nil
}

// GPODelete deletes a GPO (LDAP and SYSVOL), together with any links to it
// samba-tool finds: `samba-tool gpo del -Hldap://DC -- {GUID}`. Callers
// refuse to delete a linked GPO before getting here.
type GPODelete struct {
	ID  string // "{GUID}"
	URL string
}

// Command implements Operation.
func (o GPODelete) Command() (Command, error) {
	if !gpoIDRE.MatchString(o.ID) || len(o.ID) != 38 {
		return Command{}, fmt.Errorf("sambatool: invalid GPO id %q", o.ID)
	}
	if err := checkGPOURL(o.URL); err != nil {
		return Command{}, err
	}
	return Command{Subcommand: []string{"gpo", "del"}, Options: []string{"-H" + o.URL}, Args: []string{o.ID}}, nil
}

// Parse implements Operation.
func (GPODelete) Parse(out []byte) (struct{}, error) {
	return struct{}{}, expectOutput(out, "deleted")
}
