//go:build lab

// samba-tool integration tests. They run as root ON a lab DC (dc1), where
// samba-tool exists: scripts/lab-test.sh copies the compiled test binary
// there and sets AD_LAB_SAMBATOOL=1, AD_LAB_REALM, AD_LAB_ADMIN_USER and
// AD_LAB_ADMIN_PASSWORD.
package sambatool

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func labRunner(t *testing.T, withPassword bool) (*Runner, string) {
	t.Helper()
	if os.Getenv("AD_LAB_SAMBATOOL") != "1" {
		t.Skip("AD_LAB_SAMBATOOL not set (run on a lab DC)")
	}
	realm := strings.ToLower(os.Getenv("AD_LAB_REALM"))
	r := &Runner{Timeout: time.Minute}
	if withPassword {
		r.Credentials = Password{Username: os.Getenv("AD_LAB_ADMIN_USER"), Password: os.Getenv("AD_LAB_ADMIN_PASSWORD")}
	}
	return r, realm
}

func TestLabDomainLevel(t *testing.T) {
	r, _ := labRunner(t, false)
	op := DomainLevelShow{}
	p, _ := Preview(r, op)
	t.Logf("$ %s", p)
	lvl, err := Run(context.Background(), r, op)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", lvl)
	if !strings.Contains(lvl.Domain, "2016") {
		t.Fatalf("domain level %q", lvl.Domain)
	}
}

func TestLabReplication(t *testing.T) {
	r, _ := labRunner(t, false)
	op := DRSShowRepl{}
	p, _ := Preview(r, op)
	t.Logf("$ %s", p)
	st, err := Run(context.Background(), r, op)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range st.RepsFrom {
		t.Logf("inbound %s from %s: failures=%d %q", l.NamingContext, l.DSA, l.ConsecutiveFailures, l.LastAttemptMessage)
	}
	if !st.Healthy() {
		t.Fatal("replication not healthy")
	}
}

func TestLabDNSWithPasswordFD(t *testing.T) {
	r, realm := labRunner(t, true)
	server := "dc1." + realm
	zones, err := Run(context.Background(), r, DNSZoneList{Server: server})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("zones: %v", zones)
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	name := fmt.Sprintf("conductor-test-%x", b)
	add := DNSAddRecord{Server: server, Zone: realm, Name: name, Type: DNSTypeA, Data: "10.93.0.250"}
	p, _ := Preview(r, add)
	t.Logf("$ %s", p)
	if strings.Contains(p, os.Getenv("AD_LAB_ADMIN_PASSWORD")) {
		t.Fatal("password in command line")
	}
	if _, err := Run(context.Background(), r, add); err != nil {
		t.Fatal(err)
	}
	recs, err := Run(context.Background(), r, DNSQuery{Server: server, Zone: realm, Name: name, Type: DNSTypeA})
	if err != nil || len(recs) != 1 || recs[0].Data != "10.93.0.250" {
		t.Fatalf("query: %+v %v", recs, err)
	}
	t.Logf("query: %+v", recs[0])
	if _, err := Run(context.Background(), r, DNSDeleteRecord{Server: server, Zone: realm, Name: name, Type: DNSTypeA, Data: "10.93.0.250"}); err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), r, DNSQuery{Server: server, Zone: realm, Name: name, Type: DNSTypeA})
	t.Logf("after delete: %v", err)
	if err == nil {
		t.Fatal("record still present")
	}
}

func TestLabFSMOAndDCs(t *testing.T) {
	r, _ := labRunner(t, false)
	p, _ := Preview(r, FSMOShow{})
	t.Logf("$ %s", p)
	roles, err := Run(context.Background(), r, FSMOShow{})
	if err != nil || len(roles) < 5 {
		t.Fatalf("fsmo %+v %v", roles, err)
	}
	for _, x := range roles {
		t.Logf("%s: %s", x.Role, x.Owner)
	}
	op := GroupListMembers{Group: "Domain Controllers"}
	p, _ = Preview(r, op)
	t.Logf("$ %s", p)
	dcs, err := Run(context.Background(), r, op)
	if err != nil || len(dcs) != 2 {
		t.Fatalf("dcs %v %v", dcs, err)
	}
	t.Logf("DCs: %v", dcs)
}
