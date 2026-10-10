package ad

import (
	"errors"
	"testing"

	"github.com/openbasalt/samba-conductor-ad/escape"
)

func TestCreateUserExtraAttributes(t *testing.T) {
	base := NewUser{ParentDN: "OU=People,DC=lab,DC=test", CN: "Ana Souza", SAMAccountName: "ana", UserPrincipalName: "ana@lab.test"}
	u := base
	u.ExtraAttributes = map[string][]string{"msDS-cloudExtensionAttribute1": {"google-first:101"}, "proxyAddresses": {"smtp:a@x.test"}}
	op, err := CreateUser(u)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, a := range op.Preview().Changes[0].Attrs {
		got[a.Name] = a.Values
	}
	if v := got["msDS-cloudExtensionAttribute1"]; len(v) != 1 || v[0] != "google-first:101" {
		t.Fatalf("marker %v", got)
	}
	if v := got["proxyAddresses"]; len(v) != 1 {
		t.Fatalf("proxyAddresses %v", got)
	}
	for name, vals := range map[string][]string{
		"userAccountControl": {"512"}, "unicodePwd": {"x"}, "memberOf": {"CN=x"}, "sAMAccountName": {"y"},
		"nTSecurityDescriptor": {"x"}, "mail": {"a@x.test"}, "Title": {"t"}, "bad attr": {"v"}, "cn;binary": {"v"},
		"proxyAddresses": {""}} {
		u := base
		u.ExtraAttributes = map[string][]string{name: vals}
		if _, err := CreateUser(u); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReplaceAttributes(t *testing.T) {
	op, err := ReplaceAttributes("CN=Ana,OU=People,DC=lab,DC=test", []AttrReplace{
		{Name: "title", Before: []string{"Old"}, After: []string{"New"}},
		{Name: "mobile", After: []string{"+55 11 5555"}},
		{Name: "department", Before: []string{"Sales"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := op.Preview().Changes[0]
	if ch.Type != ChangeModify || len(ch.Attrs) != 3 || ch.Assert == nil {
		t.Fatalf("change %+v", ch)
	}
	want := "(&(title=Old)(!(mobile=*))(department=Sales))"
	if s, err := escape.Compile(ch.Assert); err != nil || s != want {
		t.Fatalf("assertion %s, want %s", s, want)
	}
	if ch.Attrs[2].Op != ModReplace || len(ch.Attrs[2].Values) != 0 {
		t.Fatalf("removal %+v", ch.Attrs[2])
	}
	for _, bad := range [][]AttrReplace{
		nil,
		{{Name: "userAccountControl", After: []string{"514"}}},
		{{Name: "member", After: []string{"CN=x"}}},
		{{Name: "title", After: []string{"a"}}, {Name: "TITLE", After: []string{"b"}}},
		{{Name: "title", After: []string{"bad\nvalue"}}},
	} {
		if _, err := ReplaceAttributes("CN=Ana,OU=People,DC=lab,DC=test", bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if _, err := ReplaceAttributes("not a dn", []AttrReplace{{Name: "title", After: []string{"x"}}}); err == nil {
		t.Error("bad DN accepted")
	}
}
