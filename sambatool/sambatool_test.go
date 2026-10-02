package sambatool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreviewInsertsDoubleDash(t *testing.T) {
	r := &Runner{Credentials: Password{Username: `LAB\admin`, Password: "secret"}}
	got, err := Preview(r, DNSAddRecord{Server: "dc1.lab.test", Zone: "lab.test", Name: "www", Type: DNSTypeA, Data: "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	want := `samba-tool dns add --use-kerberos=off -U 'LAB\admin' -- dc1.lab.test lab.test www A 10.0.0.5`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if strings.Contains(got, "secret") {
		t.Fatal("password in preview")
	}
}

func TestRejectsOptionLikeAndBadValues(t *testing.T) {
	bad := []Operation[struct{}]{
		DNSAddRecord{Server: "-H", Zone: "lab.test", Name: "x", Type: DNSTypeA, Data: "10.0.0.1"},
		DNSAddRecord{Server: "dc1", Zone: "lab.test", Name: "--force", Type: DNSTypeA, Data: "10.0.0.1"},
		DNSAddRecord{Server: "dc1", Zone: "lab.test", Name: "x", Type: DNSTypeA, Data: "-1"},
		DNSAddRecord{Server: "dc1", Zone: "lab.test", Name: "x", Type: DNSTypeA, Data: "999.1.1.1"},
		DNSAddRecord{Server: "dc1", Zone: "lab.test", Name: "x", Type: "SOA", Data: "x"},
		DNSAddRecord{Server: "dc1", Zone: "lab.test", Name: "x", Type: DNSTypeTXT, Data: "a\nb"},
		DNSAddRecord{Server: "dc1", Zone: "lab.test", Name: "x", Type: DNSTypeALL, Data: "x"},
		DNSDeleteRecord{Server: "dc1", Zone: "lab.test", Name: "x y", Type: DNSTypeA, Data: "10.0.0.1"},
	}
	for i, op := range bad {
		if _, err := op.Command(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := (DomainBackupOnline{Server: "dc1", TargetDir: "/tmp/../etc"}).Command(); err == nil {
		t.Error("path traversal accepted")
	}
	if _, err := (DomainLevelShow{URL: "ldap://x -H y"}).Command(); err == nil {
		t.Error("bad URL accepted")
	}
	if err := ValidateValue("-rf"); err == nil {
		t.Error("leading dash accepted")
	}
}

func TestParsers(t *testing.T) {
	zones, _ := DNSZoneList{}.Parse([]byte("  2 zone(s) found\n\n  pszZoneName                 : lab.test\n  Flags : X\n\n  pszZoneName                 : _msdcs.lab.test\n"))
	if len(zones) != 2 || zones[1] != "_msdcs.lab.test" {
		t.Fatalf("zones %v", zones)
	}
	recs, _ := DNSQuery{}.Parse([]byte(`  Name=, Records=2, Children=0
    SOA: serial=3, refresh=900, retry=600, expire=86400, minttl=0, ns=dc1.lab.test., email=hostmaster.lab.test. (flags=600000f0, serial=3, ttl=3600)
    A: 10.93.0.10 (flags=600000f0, serial=110, ttl=900)
  Name=www, Records=1, Children=0
    A: 10.0.0.5 (flags=f0, serial=4, ttl=900)
`))
	if len(recs) != 3 || recs[2].Name != "www" || recs[2].Data != "10.0.0.5" || recs[1].TTL != 900 {
		t.Fatalf("records %+v", recs)
	}
	lvl, err := DomainLevelShow{}.Parse([]byte("Domain and forest function level for domain 'DC=lab'\n\nForest function level: (Windows) 2016\nDomain function level: (Windows) 2016\nLowest function level of a DC: (Windows) 2016\n"))
	if err != nil || lvl.Forest != "(Windows) 2016" || lvl.LowestDC != "(Windows) 2016" {
		t.Fatalf("level %+v %v", lvl, err)
	}
	st, err := DRSShowRepl{}.Parse([]byte(`{"server":"DC1","site":"Default-First-Site-Name","repsFrom":[{"NC dn":"DC=lab","DSA":"x","consecutive failures":0,"last attempt message":"was successful"}],"repsTo":[]}`))
	if err != nil || !st.Healthy() || st.RepsFrom[0].NamingContext != "DC=lab" {
		t.Fatalf("showrepl %+v %v", st, err)
	}
	if _, err := (DNSAddRecord{}).Parse([]byte("ERROR")); err == nil {
		t.Error("unexpected output accepted")
	}
}

// fakeSambaTool writes a script that records its argv and the password it
// can read from PASSWD_FD.
func fakeSambaTool(t *testing.T) (bin, argvFile, pwFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "samba-tool")
	argvFile = filepath.Join(dir, "argv")
	pwFile = filepath.Join(dir, "pw")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argvFile + "\n" +
		"if [ -n \"$PASSWD_FD\" ]; then cat <&\"$PASSWD_FD\" > " + pwFile + "; fi\n" +
		"echo '  pszZoneName                 : lab.test'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argvFile, pwFile
}

func TestRunPassesPasswordThroughFD(t *testing.T) {
	bin, argvFile, pwFile := fakeSambaTool(t)
	r := &Runner{Binary: bin, Credentials: Password{Username: "admin", Password: "Sup3r-secret"}}
	zones, err := Run(context.Background(), r, DNSZoneList{Server: "dc1.lab.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 || zones[0] != "lab.test" {
		t.Fatalf("zones %v", zones)
	}
	argv, _ := os.ReadFile(argvFile)
	if strings.Contains(string(argv), "Sup3r") {
		t.Fatal("password in argv")
	}
	if !strings.Contains(string(argv), "--\ndc1.lab.test\n") {
		t.Fatalf("argv %q lacks '--' before user values", argv)
	}
	pw, _ := os.ReadFile(pwFile)
	if string(pw) != "Sup3r-secret" {
		t.Fatalf("password via fd: %q", pw)
	}
}

func TestRunExitError(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "samba-tool")
	_ = os.WriteFile(bin, []byte("#!/bin/sh\necho 'ERROR: nope' >&2\nexit 3\n"), 0o700)
	_, err := Run(context.Background(), &Runner{Binary: bin}, DNSZoneList{Server: "dc1"})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 3 || !strings.Contains(ee.Stderr, "nope") {
		t.Fatalf("got %v", err)
	}
}

func FuzzValidateValue(f *testing.F) {
	f.Add("dc1.lab.test")
	f.Add("-x")
	f.Fuzz(func(t *testing.T, v string) {
		op := DNSQuery{Server: "dc1", Zone: "lab.test", Name: v, Type: DNSTypeA}
		c, err := op.Command()
		if err != nil {
			return
		}
		args, err := argv(c, nil)
		if err != nil {
			return
		}
		dash := -1
		for i, a := range args {
			if a == "--" {
				dash = i
				break
			}
		}
		for i, a := range args {
			if i > dash && strings.HasPrefix(a, "-") {
				t.Fatalf("option-like user value %q after --", a)
			}
			if i < dash && a == v && v != "dns" && v != "query" {
				t.Fatalf("user value %q before --", v)
			}
		}
	})
}

func TestFSMOAndListMembers(t *testing.T) {
	out := `SchemaMasterRole owner: CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=lab
InfrastructureMasterRole owner: CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=lab
PdcEmulationMasterRole owner: CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=lab
`
	roles, err := FSMOShow{}.Parse([]byte(out))
	if err != nil || len(roles) != 3 || roles[2].Role != "PdcEmulationMasterRole" || !strings.Contains(roles[2].Owner, "CN=DC2,") {
		t.Fatalf("roles %+v %v", roles, err)
	}
	if _, err := (FSMOShow{}).Parse([]byte("ERROR: no")); err == nil {
		t.Error("garbage accepted")
	}
	r := &Runner{}
	p, err := Preview(r, GroupListMembers{Group: "Domain Controllers"})
	if err != nil || p != "samba-tool group listmembers --full-dn -- 'Domain Controllers'" {
		t.Fatalf("preview %q %v", p, err)
	}
	if _, err := Preview(r, GroupListMembers{Group: "--URL=ldap://evil"}); err == nil {
		t.Error("option-like group accepted")
	}
	if _, err := Preview(r, FSMOShow{URL: "ldap://x; rm"}); err == nil {
		t.Error("bad URL accepted")
	}
	dns, err := GroupListMembers{}.Parse([]byte("CN=DC1,OU=Domain Controllers,DC=lab\nCN=DC2,OU=Domain Controllers,DC=lab\n"))
	if err != nil || len(dns) != 2 {
		t.Fatalf("members %v %v", dns, err)
	}
	if _, err := (GroupListMembers{}).Parse([]byte("ERROR(ldb): no such group\n")); err == nil {
		t.Error("error line accepted as a member")
	}
}

func TestGPOOperations(t *testing.T) {
	r := &Runner{Credentials: KerberosCCache{Path: "/run/conductor/cc-1"}}
	got, err := Preview(r, GPOCreate{DisplayName: "Lab Baseline", URL: "ldap://dc1.lab.test"})
	if err != nil {
		t.Fatal(err)
	}
	want := `samba-tool gpo create -Hldap://dc1.lab.test --use-kerberos=required --use-krb5-ccache=/run/conductor/cc-1 -- 'Lab Baseline'`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	id, err := GPOCreate{}.Parse([]byte("Using temporary directory /tmp/x\nGPO 'Lab Baseline' created as {c06bded1-2aed-457f-be21-3d4ba75b44ce}\n"))
	if err != nil || id != "{C06BDED1-2AED-457F-BE21-3D4BA75B44CE}" {
		t.Fatalf("parse create: %q %v", id, err)
	}
	if _, err := (GPOCreate{}).Parse([]byte("ERROR")); err == nil {
		t.Fatal("create without id accepted")
	}
	for _, bad := range []GPOCreate{{DisplayName: "-x", URL: "ldap://dc1"}, {DisplayName: "a\nb", URL: "ldap://dc1"},
		{DisplayName: "ok", URL: "tdb:///var/lib/samba"}, {DisplayName: "ok", URL: "ldap://dc1 -k"}, {DisplayName: `a"b`, URL: "ldap://dc1"}} {
		if _, err := bad.Command(); err == nil {
			t.Errorf("create %+v accepted", bad)
		}
	}
	got, err = Preview(r, GPODelete{ID: "{C06BDED1-2AED-457F-BE21-3D4BA75B44CE}", URL: "ldap://dc1.lab.test"})
	if err != nil || !strings.HasSuffix(got, "-- '{C06BDED1-2AED-457F-BE21-3D4BA75B44CE}'") {
		t.Fatalf("delete preview %q %v", got, err)
	}
	for _, bad := range []string{"", "C06BDED1-2AED-457F-BE21-3D4BA75B44CE", "{x}", "{C06BDED1-2AED-457F-BE21-3D4BA75B44CE}x"} {
		if _, err := (GPODelete{ID: bad, URL: "ldap://dc1"}).Command(); err == nil {
			t.Errorf("delete id %q accepted", bad)
		}
	}
}
