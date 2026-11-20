package ad

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

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

func TestIsSecretAttribute(t *testing.T) {
	for _, n := range []string{"unicodePwd", "UNICODEPWD", "unicodePwd;binary", "dBCSPwd", "userPassword", "unixUserPassword",
		"ntPwdHistory", "lmPwdHistory", "supplementalCredentials", "msDS-ManagedPassword", "ms-Mcs-AdmPwd",
		"msLAPS-Password", "msLAPS-EncryptedPassword", "msFVE-RecoveryPassword", "msFVE-KeyPackage", "msDS-KeyCredentialLink",
		"nTSecurityDescriptor", "pwdHistory", "msTPM-OwnerInformation", "trustAuthIncoming", "msPKIAccountCredentials",
		"msKds-RootKeyData", "msSFU30Password", "userPKCS12"} {
		if !IsSecretAttribute(n) {
			t.Errorf("%s not secret", n)
		}
	}
	for _, n := range []string{"cn", "loginShell", "description", "mail", "objectSid", "pwdLastSet", "userCertificate"} {
		if IsSecretAttribute(n) {
			t.Errorf("%s secret", n)
		}
	}
}

func TestRawEntryFrom(t *testing.T) {
	sidBytes := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0x50, 4, 0, 0}
	guidBytes := make([]byte, 16)
	guidBytes[0] = 0x33
	many := make([][]byte, MaxRawValues+7)
	for i := range many {
		many[i] = []byte("v")
	}
	long := []byte(strings.Repeat("a", MaxRawValueBytes-1) + "é" + "tail")
	e := &ldap.Entry{DN: "CN=Ana,DC=lab,DC=test", Attributes: []*ldap.EntryAttribute{
		{Name: "sn", ByteValues: [][]byte{[]byte("Souza")}},
		{Name: "objectSid", ByteValues: [][]byte{sidBytes}},
		{Name: "objectGUID", ByteValues: [][]byte{guidBytes}},
		{Name: "unicodePwd", ByteValues: [][]byte{[]byte("secret-hash")}},
		{Name: "supplementalCredentials", ByteValues: [][]byte{[]byte("kerberos keys")}},
		{Name: "msLAPS-Password", ByteValues: [][]byte{[]byte("p@ss")}},
		{Name: "description", ByteValues: [][]byte{[]byte("line1\nline2"), {0xff, 0xfe}, []byte("bidi\u202eevil"), []byte("ok")}},
		{Name: "otherMailbox", ByteValues: many},
		{Name: "info", ByteValues: [][]byte{long}},
		{Name: "Cn", ByteValues: [][]byte{[]byte("Ana")}},
	}}
	r := RawEntryFrom(e)
	var names []string
	byName := map[string]RawAttribute{}
	for _, a := range r.Attributes {
		names = append(names, a.Name)
		byName[a.Name] = a
	}
	want := []string{"Cn", "description", "info", "msLAPS-Password", "objectGUID", "objectSid", "otherMailbox", "sn", "supplementalCredentials", "unicodePwd"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("order %v", names)
	}
	for _, n := range []string{"unicodePwd", "supplementalCredentials", "msLAPS-Password"} {
		if a := byName[n]; !a.Hidden || len(a.Values) != 0 {
			t.Errorf("%s shown: %+v", n, a)
		}
	}
	if v := byName["objectSid"].Values[0].Text; v != "S-1-5-21-1-2-3-1104" {
		t.Errorf("sid %q", v)
	}
	if v := byName["objectGUID"].Values[0].Text; !strings.Contains(v, "33") || len(v) != 36 {
		t.Errorf("guid %q", v)
	}
	d := byName["description"].Values
	if !d[0].Binary || d[0].Text != "" || d[0].Len != 11 || !d[1].Binary || d[1].Len != 2 || !d[2].Binary || d[3].Binary || d[3].Text != "ok" {
		t.Errorf("description %+v", d)
	}
	if m := byName["otherMailbox"]; len(m.Values) != MaxRawValues || m.More != 7 {
		t.Errorf("cap %d more %d", len(m.Values), m.More)
	}
	in := byName["info"].Values[0]
	if !in.Truncated || len(in.Text) != MaxRawValueBytes-1 || in.Len != len(long) || !utf8.ValidString(in.Text) {
		t.Errorf("truncation %d %v", len(in.Text), in.Truncated)
	}
	// A malformed SID is binary, never raw bytes.
	bad := RawEntryFrom(&ldap.Entry{Attributes: []*ldap.EntryAttribute{{Name: "objectSid", ByteValues: [][]byte{{1, 2}}}}})
	if v := bad.Attributes[0].Values[0]; !v.Binary || v.Text != "" {
		t.Errorf("bad sid %+v", v)
	}
}

func TestValidateUserAttribute(t *testing.T) {
	good := map[string][]string{
		"loginShell":        {"/bin/bash"},
		"LOGINSHELL":        {"/usr/local/bin/zsh-5.9"},
		"unixHomeDirectory": {"/home/ana.souza"},
		"uidNumber":         {"1000"},
		"gidNumber":         {"2147483647"},
		"gecos":             {"Ana Souza, Room 12"},
		"otherMailbox":      {"ana@example.com", "a.s+tag@mail.example.org"},
	}
	for n, v := range good {
		if err := ValidateUserAttribute(n, v); err != nil {
			t.Errorf("%s %q: %v", n, v, err)
		}
	}
	if err := ValidateUserAttribute("gecos", nil); err != nil {
		t.Errorf("removal: %v", err)
	}
	sixteen := make([]string, 17)
	for i := range sixteen {
		sixteen[i] = fmt.Sprintf("u%d@example.com", i)
	}
	bad := []struct {
		name   string
		values []string
		reason string
	}{
		{"title", []string{"x"}, AttrNotEditable},
		{"unicodePwd", []string{"x"}, AttrNotEditable},
		{"loginShell", []string{"bin/bash"}, AttrNotAbsolute},
		{"loginShell", []string{"/bin/../etc/passwd"}, AttrDotDot},
		{"loginShell", []string{"/bin/ba sh"}, AttrBadChars},
		{"loginShell", []string{"/bin/bash;rm"}, AttrBadChars},
		{"loginShell", []string{"/" + strings.Repeat("a", 255)}, AttrTooLong},
		{"loginShell", []string{"/bin/sh", "/bin/bash"}, AttrTooMany},
		{"unixHomeDirectory", []string{"/home/é"}, AttrBadChars},
		{"uidNumber", []string{"0"}, AttrNotNumber},
		{"uidNumber", []string{"999"}, AttrOutOfRange},
		{"uidNumber", []string{"01000"}, AttrNotNumber},
		{"uidNumber", []string{"+1000"}, AttrNotNumber},
		{"uidNumber", []string{"-1"}, AttrNotNumber},
		{"uidNumber", []string{"2147483648"}, AttrOutOfRange},
		{"uidNumber", []string{"99999999999999999999999"}, AttrOutOfRange},
		{"gidNumber", []string{"12a"}, AttrNotNumber},
		{"gecos", []string{"a:b"}, AttrColon},
		{"gecos", []string{"a\nb"}, AttrNotPrintable},
		{"gecos", []string{"a\u202eb"}, AttrNotPrintable},
		{"gecos", []string{strings.Repeat("x", 256)}, AttrTooLong},
		{"otherMailbox", []string{"no-at"}, AttrNotEmail},
		{"otherMailbox", []string{"a@b@c"}, AttrNotEmail},
		{"otherMailbox", []string{"a b@c.test"}, AttrNotEmail},
		{"otherMailbox", []string{"<a@c.test>"}, AttrNotEmail},
		{"otherMailbox", []string{"a@c..test"}, AttrNotEmail},
		{"otherMailbox", []string{"a@"}, AttrNotEmail},
		{"otherMailbox", []string{"a@x.test", "A@x.test"}, AttrDuplicate},
		{"otherMailbox", sixteen, AttrTooMany},
		{"otherMailbox", []string{strings.Repeat("a", 250) + "@x.test"}, AttrTooLong},
	}
	for _, c := range bad {
		err := ValidateUserAttribute(c.name, c.values)
		var ae *AttrError
		if !errors.As(err, &ae) || ae.Reason != c.reason || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s %q: %v, want %s", c.name, c.values, err, c.reason)
		}
	}
}

func TestUpdateUserAttributes(t *testing.T) {
	dn := "CN=Ana,OU=People,DC=lab,DC=test"
	op, err := UpdateUserAttributes(dn, []AttrReplace{
		{Name: "loginShell", Before: []string{"/bin/bash"}, After: []string{"/bin/zsh"}},
		{Name: "uidNumber", After: []string{"10001"}},
		{Name: "gecos", Before: []string{"Ana"}, After: []string{"Ana"}},
		{Name: "otherMailbox", Before: []string{"a@x.test", "b@x.test"}, After: []string{"b@x.test", "a@x.test"}},
		{Name: "unixHomeDirectory", Before: []string{"/home/ana"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := op.Preview().Changes[0]
	if len(ch.Attrs) != 3 {
		t.Fatalf("unchanged attributes included: %+v", ch.Attrs)
	}
	want := "(&(loginShell=/bin/bash)(!(uidNumber=*))(unixHomeDirectory=/home/ana))"
	if s, _ := escape.Compile(ch.Assert); s != want {
		t.Fatalf("assertion %s", s)
	}
	text := op.Preview().String()
	for _, w := range []string{"# loginShell: /bin/bash -> /bin/zsh", "# uidNumber: (none) -> 10001", "# unixHomeDirectory: /home/ana -> (none)",
		"replace: loginShell\nloginShell: /bin/zsh\n"} {
		if !strings.Contains(text, w) {
			t.Errorf("preview lacks %q:\n%s", w, text)
		}
	}
	if _, err := UpdateUserAttributes(dn, []AttrReplace{{Name: "gecos", Before: []string{"x"}, After: []string{"x"}}}); !errors.Is(err, ErrNoChange) {
		t.Errorf("no change: %v", err)
	}
	if _, err := UpdateUserAttributes(dn, nil); !errors.Is(err, ErrNoChange) {
		t.Errorf("empty: %v", err)
	}
	for _, bad := range [][]AttrReplace{
		{{Name: "title", After: []string{"x"}}},
		{{Name: "userAccountControl", After: []string{"512"}}},
		{{Name: "description", After: []string{"x"}}},
		{{Name: "uidNumber", After: []string{"0"}}},
		{{Name: "loginShell", After: []string{"sh"}}},
		{{Name: "loginShell", After: []string{"/bin/sh"}}, {Name: "LoginShell", After: []string{"/bin/zsh"}}},
	} {
		if _, err := UpdateUserAttributes(dn, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("accepted %+v: %v", bad, err)
		}
	}
	if _, err := UpdateUserAttributes("not a dn", []AttrReplace{{Name: "gecos", After: []string{"x"}}}); err == nil {
		t.Error("bad DN accepted")
	}
	names := []string{}
	for _, a := range EditableUserAttributes() {
		names = append(names, a.Name)
	}
	if strings.Join(names, ",") != "loginShell,unixHomeDirectory,uidNumber,gidNumber,gecos,otherMailbox" {
		t.Errorf("allowlist %v", names)
	}
}
