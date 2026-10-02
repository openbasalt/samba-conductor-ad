package escape

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

func TestFilterValue(t *testing.T) {
	cases := map[string]string{
		"plain":        "plain",
		"a*b":          `a\2ab`,
		"(x)":          `\28x\29`,
		`back\slash`:   `back\5cslash`,
		"nul\x00":      `nul\00`,
		"*)(uid=*))(|": `\2a\29\28uid=\2a\29\29\28|`,
		"José":         `Jos\c3\a9`,
	}
	for in, want := range cases {
		if got := FilterValue(in); got != want {
			t.Errorf("FilterValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompileFilters(t *testing.T) {
	cases := []struct {
		f    Filter
		want string
	}{
		{Eq("sAMAccountName", "jdoe"), "(sAMAccountName=jdoe)"},
		{And(Eq("objectClass", "user"), Not(BitAnd("userAccountControl", 2))),
			"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"},
		{Or(Prefix("cn", "Jo*"), Contains("mail", "@x")), `(|(cn=Jo\2a*)(mail=*@x*))`},
		{Substring("cn", "a", []string{"b", "c"}, "d"), "(cn=a*b*c*d)"},
		{Present("mail"), "(mail=*)"},
		{EqBytes("objectSid", []byte{1, 0xff}), `(objectSid=\01\ff)`},
		{InChain("memberOf", "CN=G (1),DC=x"), `(memberOf:1.2.840.113556.1.4.1941:=CN=G \281\29,DC=x)`},
		{RawFilter("(objectClass=*)"), "(objectClass=*)"},
		{GreaterOrEqual("uSNChanged", "10"), "(uSNChanged>=10)"},
	}
	for _, c := range cases {
		got, err := Compile(c.f)
		if err != nil {
			t.Fatalf("Compile(%v): %v", c.want, err)
		}
		if got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
		if _, err := ldap.CompileFilter(got); err != nil {
			t.Errorf("go-ldap rejects %q: %v", got, err)
		}
	}
}

func TestCompileRejects(t *testing.T) {
	bad := []Filter{
		Eq("cn)(x", "v"),
		Eq("", "v"),
		Present("1cn"),
		And(),
		Or(Eq("cn", "a"), nil),
		Not(nil),
		Substring("cn", "", nil, ""),
		RawFilter("objectClass=*"),
		RawFilter("((a=b)"),
	}
	for i, f := range bad {
		if _, err := Compile(f); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
	if _, err := Compile(Eq("x y", "v")); !errors.Is(err, ErrInvalidAttribute) {
		t.Errorf("want ErrInvalidAttribute, got %v", err)
	}
}

func TestValidAttribute(t *testing.T) {
	good := []string{"cn", "sAMAccountName", "msDS-User-Account-Control-Computed", "1.2.840.113556.1.4.221", "member;range=0-1499", "member;range=1500-*"}
	bad := []string{"", "1cn", "cn=", "cn;", "a b", "1.02.3", "cn;x;", "*"}
	for _, g := range good {
		if !ValidAttribute(g) {
			t.Errorf("%q should be valid", g)
		}
	}
	for _, b := range bad {
		if ValidAttribute(b) {
			t.Errorf("%q should be invalid", b)
		}
	}
}

func TestDNValue(t *testing.T) {
	cases := map[string]string{
		"Doe, John":       `Doe\, John`,
		"#start":          `\#start`,
		" lead":           `\ lead`,
		"trail ":          `trail\ `,
		`a+b"c<d>e;f\g=h`: `a\+b\"c\<d\>e\;f\\g\=h`,
		"José":            "José",
		"nul\x00":         `nul\00`,
	}
	for in, want := range cases {
		if got := DNValue(in); got != want {
			t.Errorf("DNValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChildAndParentDN(t *testing.T) {
	dn, err := ChildDN("CN", `Escape, Test #1 + "q" <x>; \ =`, "OU=Special,DC=lab,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	parent, value, err := ParentDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	if value != `Escape, Test #1 + "q" <x>; \ =` {
		t.Errorf("value round trip: %q", value)
	}
	if !EqualDN(parent, "ou=special,dc=LAB,dc=test") {
		t.Errorf("parent %q", parent)
	}
	if _, err := ChildDN("CN", "x", "not a dn"); !errors.Is(err, ErrInvalidDN) {
		t.Errorf("want ErrInvalidDN, got %v", err)
	}
	if _, err := RDN("member;range=0-1", "x"); err == nil {
		t.Error("options must be rejected in DNs")
	}
}

// compiledValue extracts the assertion value of an equality filter compiled by
// go-ldap, i.e. what goes on the wire after unescaping.
func compiledValue(t *testing.T, filter string) (string, bool) {
	t.Helper()
	p, err := ldap.CompileFilter(filter)
	if err != nil {
		return "", false
	}
	if len(p.Children) != 2 {
		t.Fatalf("unexpected packet shape for %q", filter)
	}
	return p.Children[1].Data.String(), true
}

func FuzzFilterValue(f *testing.F) {
	for _, s := range []string{"", "a", "*", "(|(uid=*))", "\x00\xff", "José", `\2a`, "a)(b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		escaped := FilterValue(v)
		for i := 0; i < len(escaped); i++ {
			c := escaped[i]
			if c == '(' || c == ')' || c == '*' || c == 0 || c >= 0x7f {
				t.Fatalf("unescaped byte %q in %q", c, escaped)
			}
		}
		filter, err := Compile(Eq("cn", v))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := compiledValue(t, filter)
		if !ok {
			// go-ldap only refuses values that are not valid UTF-8 once
			// unescaped; the escaping itself must never be the reason.
			if utf8.ValidString(v) {
				t.Fatalf("go-ldap rejected valid input %q as %q", v, filter)
			}
			return
		}
		if got != v {
			t.Fatalf("round trip: %q -> %q -> %q", v, filter, got)
		}
	})
}

func FuzzDNValue(f *testing.F) {
	for _, s := range []string{"a", "#x", " x ", `"+,;<>\=`, "José", "a\x00b", "=", "\\"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if v == "" || !utf8.ValidString(v) || strings.TrimSpace(v) == "" {
			return
		}
		dn, err := ChildDN("cn", v, "dc=example,dc=test")
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ldap.ParseDN(dn)
		if err != nil {
			t.Fatalf("ParseDN(%q) for value %q: %v", dn, v, err)
		}
		if len(parsed.RDNs) != 3 || len(parsed.RDNs[0].Attributes) != 1 {
			t.Fatalf("value %q changed the DN structure: %q", v, dn)
		}
		if got := parsed.RDNs[0].Attributes[0].Value; got != v {
			t.Fatalf("round trip %q -> %q -> %q", v, dn, got)
		}
	})
}
