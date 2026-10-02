package ad

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestIntervals(t *testing.T) {
	if encodeInterval(42*24*time.Hour, true) != "-36288000000000" || encodeInterval(0, true) != "-9223372036854775808" || encodeInterval(0, false) != "0" {
		t.Fatal("encode")
	}
	for _, c := range []struct {
		in   string
		want time.Duration
	}{{"-36288000000000", 42 * 24 * time.Hour}, {"-9223372036854775808", 0}, {"0", 0}, {"-18000000000", 30 * time.Minute}, {"x", 0}} {
		if got := decodeInterval(c.in); got != c.want {
			t.Errorf("%s: %v", c.in, got)
		}
	}
}

func validPolicy() PasswordPolicy {
	return PasswordPolicy{MinLength: 7, History: 24, Complexity: true, MaxAge: 42 * 24 * time.Hour, MinAge: 24 * time.Hour,
		LockoutThreshold: 10, LockoutDuration: 30 * time.Minute, ObservationWindow: 30 * time.Minute}
}

func TestPolicyValidate(t *testing.T) {
	if err := validPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(*PasswordPolicy){
		func(p *PasswordPolicy) { p.MinLength = 300 },
		func(p *PasswordPolicy) { p.History = 25 },
		func(p *PasswordPolicy) { p.MinAge = p.MaxAge },
		func(p *PasswordPolicy) { p.LockoutThreshold = -1 },
		func(p *PasswordPolicy) { p.ObservationWindow = 0 },
		func(p *PasswordPolicy) { p.ObservationWindow = time.Hour },
		func(p *PasswordPolicy) { p.MaxAge = 1000 * 24 * time.Hour },
	}
	for i, f := range bad {
		p := validPolicy()
		f(&p)
		if err := p.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted", i)
		}
	}
	p := validPolicy()
	p.LockoutDuration = 0 // until unlocked: any window is fine
	p.ObservationWindow = 2 * time.Hour
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func domainEntry() *ldap.Entry {
	return ldap.NewEntry("DC=lab,DC=example", map[string][]string{
		"minPwdLength": {"7"}, "pwdHistoryLength": {"24"}, "pwdProperties": {"1"}, "minPwdAge": {"0"},
		"maxPwdAge": {"-9223372036854775808"}, "lockoutThreshold": {"0"}, "lockoutDuration": {"-18000000000"},
		"lockOutObservationWindow": {"-18000000000"},
	})
}

func TestUpdateDomainPasswordPolicy(t *testing.T) {
	cur := domainPolicyFromEntry(domainEntry())
	if cur.Policy.MaxAge != 0 || !cur.Policy.Complexity || !cur.Policy.LockoutDisabled() || cur.Policy.LockoutDuration != 30*time.Minute {
		t.Fatalf("read %+v", cur.Policy)
	}
	next := cur.Policy
	next.LockoutThreshold = 10
	next.MinLength = 10
	op, err := UpdateDomainPasswordPolicy(cur, next)
	if err != nil {
		t.Fatal(err)
	}
	ch := op.Preview().Changes[0]
	if len(ch.Attrs) != 2 || ch.Attrs[0].Name != "minPwdLength" || ch.Attrs[1].Name != "lockoutThreshold" || ch.Assert == nil {
		t.Fatalf("change %+v", ch)
	}
	text := op.Preview().String()
	if !strings.Contains(text, "# lockout threshold: 0 -> 10") || !strings.Contains(text, "(minPwdLength=7)") {
		t.Fatalf("preview:\n%s", text)
	}
	if _, err := UpdateDomainPasswordPolicy(cur, cur.Policy); !errors.Is(err, ErrNoChange) {
		t.Fatalf("no-op: %v", err)
	}
	// Turning lockout off again warns.
	cur2 := cur
	cur2.raw = map[string]string{}
	for k, v := range cur.raw {
		cur2.raw[k] = v
	}
	cur2.raw["lockoutThreshold"] = "10"
	cur2.Policy.LockoutThreshold = 10
	op, _ = UpdateDomainPasswordPolicy(cur2, cur.Policy)
	if !strings.Contains(op.Preview().String(), "never lock out") {
		t.Fatal("no warning for threshold 0")
	}
	// Max age: a value is written as a negative interval.
	next = cur.Policy
	next.MaxAge = 90 * 24 * time.Hour
	op, _ = UpdateDomainPasswordPolicy(cur, next)
	if v := op.Preview().Changes[0].Attrs[0]; v.Name != "maxPwdAge" || v.Values[0] != "-77760000000000" {
		t.Fatalf("max age %+v", v)
	}
	// Complexity off keeps unknown pwdProperties bits.
	cur.raw["pwdProperties"] = "5"
	next = cur.Policy
	next.Complexity = false
	op, _ = UpdateDomainPasswordPolicy(cur, next)
	if v := op.Preview().Changes[0].Attrs[0]; v.Name != "pwdProperties" || v.Values[0] != "4" {
		t.Fatalf("pwdProperties %+v", v)
	}
}

func TestPSOOperations(t *testing.T) {
	p := validPolicy()
	op, err := CreatePSO("CN=Password Settings Container,CN=System,DC=lab,DC=example", "staff", 30, p, []string{"CN=Staff,OU=Groups,DC=lab,DC=example"})
	if err != nil {
		t.Fatal(err)
	}
	ch := op.Preview().Changes[0]
	if ch.DN != "CN=staff,CN=Password Settings Container,CN=System,DC=lab,DC=example" || len(ch.Attrs) != 12 {
		t.Fatalf("create %+v", ch)
	}
	if _, err := CreatePSO("CN=x,DC=lab", "bad", 0, p, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("precedence 0 accepted")
	}
	e := ldap.NewEntry(ch.DN, map[string][]string{"cn": {"staff"}, "msDS-PasswordSettingsPrecedence": {"30"},
		"msDS-MinimumPasswordLength": {"7"}, "msDS-PasswordHistoryLength": {"24"}, "msDS-PasswordComplexityEnabled": {"TRUE"},
		"msDS-PasswordReversibleEncryptionEnabled": {"FALSE"}, "msDS-MinimumPasswordAge": {"-864000000000"},
		"msDS-MaximumPasswordAge": {"-36288000000000"}, "msDS-LockoutThreshold": {"10"}, "msDS-LockoutDuration": {"-18000000000"},
		"msDS-LockoutObservationWindow": {"-18000000000"}, "msDS-PSOAppliesTo": {"CN=Staff,OU=Groups,DC=lab,DC=example"}})
	pso := psoFromEntry(e)
	if pso.Policy != p || pso.Precedence != 30 {
		t.Fatalf("read back %+v", pso)
	}
	if _, err := UpdatePSO(pso, 30, p); !errors.Is(err, ErrNoChange) {
		t.Fatal("no-op update")
	}
	np := p
	np.MaxAge = 20 * 24 * time.Hour
	op, err = UpdatePSO(pso, 25, np)
	if err != nil || len(op.Preview().Changes[0].Attrs) != 2 {
		t.Fatalf("update %v %+v", err, op)
	}
	if _, err := ApplyPSO(pso, "cn=staff,ou=groups,dc=lab,dc=example"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatal("apply twice")
	}
	if _, err := UnapplyPSO(pso, "CN=Other,DC=lab,DC=example"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unapply unknown")
	}
	op, err = ApplyPSO(pso, "CN=Other,DC=lab,DC=example")
	if err != nil || op.Preview().Changes[0].Attrs[0].Op != ModAdd {
		t.Fatal("apply")
	}
}

func TestGeneralizedTime(t *testing.T) {
	if got := generalizedTime("20261002021448.0Z"); !got.Equal(time.Date(2026, 10, 2, 2, 14, 48, 0, time.UTC)) {
		t.Fatal(got)
	}
	if !generalizedTime("garbage").IsZero() || !generalizedTime("").IsZero() {
		t.Fatal("garbage")
	}
}
