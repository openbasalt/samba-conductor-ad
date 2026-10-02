package ad

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	krbasn1 "github.com/go-krb5/x/encoding/asn1"
	"github.com/go-ldap/ldap/v3"
)

func ldapErr(code uint16, msg string) error {
	return &ldap.Error{ResultCode: code, Err: errors.New(msg)}
}

func TestClassifyBindError(t *testing.T) {
	const prefix = "80090308: LdapErr: DSID-0C09030B, comment: AcceptSecurityContext error, data "
	cases := []struct {
		msg      string
		reason   Reason
		sentinel error
		verified bool
	}{
		{prefix + "52e, v893", ReasonInvalidCredentials, ErrInvalidCredentials, false},
		{prefix + "525, v893", ReasonInvalidCredentials, ErrInvalidCredentials, false},
		{prefix + "532, v893", ReasonPasswordExpired, ErrPasswordExpired, true},
		{prefix + "773, v893", ReasonPasswordMustChange, ErrPasswordMustChange, true},
		{prefix + "775, v893", ReasonAccountLocked, ErrAccountLocked, false},
		{prefix + "533, v893", ReasonAccountDisabled, ErrAccountDisabled, false},
		{prefix + "701, v893", ReasonAccountExpired, ErrAccountExpired, false},
		{prefix + "530, v893", ReasonLogonHours, ErrAccountRestricted, false},
		// The v1 takeover bug: a generic 49 must never be read as "expired".
		{"Invalid credentials", ReasonInvalidCredentials, ErrInvalidCredentials, false},
		{prefix + "999, v1", ReasonInvalidCredentials, ErrInvalidCredentials, false},
	}
	for _, c := range cases {
		err := ClassifyBindError(ldapErr(ldap.LDAPResultInvalidCredentials, c.msg))
		var ae *AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("%q: not an AuthError: %v", c.msg, err)
		}
		if ae.Reason != c.reason || !errors.Is(err, c.sentinel) || ae.PasswordVerified() != c.verified {
			t.Errorf("%q: got reason=%v verified=%v", c.msg, ae.Reason, ae.PasswordVerified())
		}
	}
	other := ldapErr(ldap.LDAPResultStrongAuthRequired, "strong auth required")
	if got := ClassifyBindError(other); got != other {
		t.Errorf("non-49 errors must pass through, got %v", got)
	}
	if ClassifyBindError(nil) != nil {
		t.Error("nil")
	}
}

func TestClassifyWriteError(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{ldapErr(ldap.LDAPResultConstraintViolation, "00000056: Constraint violation - old password mismatch"), ErrWrongPassword},
		{ldapErr(ldap.LDAPResultConstraintViolation, "0000052D: Constraint violation - check_password_restrictions"), ErrPasswordPolicy},
		{ldapErr(ldap.LDAPResultInsufficientAccessRights, "00002098: insufficient access"), ErrAccessDenied},
		{ldapErr(ldap.LDAPResultNoSuchObject, "no such object"), ErrNotFound},
		{ldapErr(ldap.LDAPResultEntryAlreadyExists, "exists"), ErrAlreadyExists},
		{ldapErr(ldap.LDAPResultNoSuchAttribute, "no such attribute"), ErrConflict},
	}
	for _, c := range cases {
		if got := classifyWriteError(c.err); !errors.Is(got, c.want) {
			t.Errorf("%v: got %v", c.err, got)
		}
	}
}

func krbErrorWithStatus(code int32, status uint32) messages.KRBError {
	val := []byte{byte(status), byte(status >> 8), byte(status >> 16), byte(status >> 24), 0, 0, 0, 0, 1, 0, 0, 0}
	edata, _ := asn1.Marshal([]paData{{Type: 3, Value: val}})
	return messages.KRBError{ErrorCode: code, EData: edata}
}

func TestClassifyKRBError(t *testing.T) {
	cases := []struct {
		e            messages.KRBError
		afterPreauth bool
		reason       Reason
		verified     bool
	}{
		{messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_FAILED}, true, ReasonInvalidCredentials, false},
		{messages.KRBError{ErrorCode: errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN}, false, ReasonInvalidCredentials, false},
		{krbErrorWithStatus(errorcode.KDC_ERR_KEY_EXPIRED, statusPasswordMustChange), true, ReasonPasswordMustChange, true},
		{krbErrorWithStatus(errorcode.KDC_ERR_KEY_EXPIRED, statusPasswordExpired), true, ReasonPasswordExpired, true},
		// Expired reported before our pre-authentication proves nothing.
		{krbErrorWithStatus(errorcode.KDC_ERR_KEY_EXPIRED, statusPasswordExpired), false, ReasonPasswordExpired, false},
		{krbErrorWithStatus(errorcode.KDC_ERR_CLIENT_REVOKED, statusAccountLocked), true, ReasonAccountLocked, false},
		{krbErrorWithStatus(errorcode.KDC_ERR_CLIENT_REVOKED, statusAccountDisabled), true, ReasonAccountDisabled, false},
		{krbErrorWithStatus(errorcode.KDC_ERR_CLIENT_REVOKED, statusAccountExpired), true, ReasonAccountExpired, false},
		{messages.KRBError{ErrorCode: errorcode.KDC_ERR_CLIENT_REVOKED}, true, ReasonAccountRestricted, false},
		{messages.KRBError{ErrorCode: errorcode.KRB_AP_ERR_SKEW}, true, ReasonClockSkew, false},
	}
	for i, c := range cases {
		ae := classifyKRBError(c.e, c.afterPreauth)
		if ae.Reason != c.reason || ae.PasswordVerified() != c.verified {
			t.Errorf("case %d (%s): reason=%v verified=%v", i, ae.Code, ae.Reason, ae.PasswordVerified())
		}
	}
	if code := classifyKRBError(krbErrorWithStatus(errorcode.KDC_ERR_CLIENT_REVOKED, statusAccountLocked), true).Code; code != "KDC_ERR_CLIENT_REVOKED/0xC0000234" {
		t.Errorf("code %q", code)
	}
}

func TestNTStatusSinglePAData(t *testing.T) {
	edata, _ := asn1.Marshal(paData{Type: 3, Value: []byte{0x34, 0x02, 0x00, 0xc0}})
	if st, ok := ntStatusFromEData(edata); !ok || st != statusAccountLocked {
		t.Fatalf("got %x %v", st, ok)
	}
	if _, ok := ntStatusFromEData([]byte{1, 2, 3}); ok {
		t.Fatal("garbage accepted")
	}
}

func TestClientPrincipal(t *testing.T) {
	for in, want := range map[string]string{"jdoe": "jdoe", "jdoe@lab.example.test": "jdoe", "LAB\\jdoe": "jdoe"} {
		p, err := clientPrincipal(in, "LAB.EXAMPLE.TEST")
		if err != nil || p.PrincipalNameString() != want {
			t.Errorf("%q: %v %v", in, p, err)
		}
	}
	for _, bad := range []string{"", "a/b", "j@other.test", "x\x00", "a*"} {
		if _, err := clientPrincipal(bad, "LAB.EXAMPLE.TEST"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestKrb5Config(t *testing.T) {
	cfg, err := krb5Config("LAB.EXAMPLE.TEST", []string{"dc1.lab.example.test", "dc2.lab.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LibDefaults.UDPPreferenceLimit != 1 || cfg.LibDefaults.DNSLookupKDC {
		t.Error("TCP only, no DNS KDC lookup expected")
	}
	_, kdcs, err := cfg.GetKDCs("LAB.EXAMPLE.TEST", true)
	// go-krb5 shuffles the configured KDCs; only membership is stable.
	if err != nil || len(kdcs) != 2 || (kdcs[1] != "dc1.lab.example.test:88" && kdcs[2] != "dc1.lab.example.test:88") {
		t.Errorf("kdcs %v %v", kdcs, err)
	}
	for _, et := range cfg.LibDefaults.DefaultTktEnctypeIDs {
		if et != 17 && et != 18 {
			t.Errorf("non-AES enctype %d", et)
		}
	}
	if _, err := krb5Config("LAB.EXAMPLE.TEST", []string{"dc1\n kdc = evil"}); err == nil {
		t.Error("injection in host accepted")
	}
	if _, err := krb5Config("LAB }", []string{"dc1"}); err == nil {
		t.Error("bad realm accepted")
	}
}

func TestCCacheFromASRep(t *testing.T) {
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "jdoe")
	now := time.Now().UTC().Truncate(time.Second)
	rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{
		Ticket: messages.Ticket{TktVNO: 5, Realm: "LAB.EXAMPLE.TEST",
			SName:   types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/LAB.EXAMPLE.TEST"),
			EncPart: types.EncryptedData{EType: 18, KVNO: 1, Cipher: []byte("opaque")}},
		DecryptedEncPart: messages.EncKDCRepPart{
			Key:      types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)},
			AuthTime: now, StartTime: now, EndTime: now.Add(10 * time.Hour), RenewTill: now.Add(24 * time.Hour),
			Flags: krbasn1.BitString{Bytes: []byte{0x40, 0xe1, 0, 0}, BitLength: 32},
		},
	}}
	cc, raw, err := ccacheFromASRep(rep, cname, "LAB.EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	// WriteCCache writes exactly these bytes to a new 0600 file.
	sess := &Session{ccache: raw, expires: now.Add(10 * time.Hour)}
	path := filepath.Join(t.TempDir(), "cc")
	if err := sess.WriteCCache(path); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("ccache file mode: %v %v", st, err)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, raw) {
		t.Fatal("ccache file content")
	}
	if err := sess.WriteCCache(path); err == nil {
		t.Fatal("existing ccache file overwritten")
	}
	expired := &Session{ccache: raw, expires: now.Add(-time.Minute)}
	if err := expired.WriteCCache(path + "2"); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("expired session: %v", err)
	}
	if cc.GetClientPrincipalName().PrincipalNameString() != "jdoe" || cc.GetClientRealm() != "LAB.EXAMPLE.TEST" {
		t.Fatalf("principal %v", cc.GetClientPrincipalName())
	}
	cred, ok := cc.GetEntry(rep.Ticket.SName)
	if !ok || !cred.EndTime.Equal(now.Add(10*time.Hour)) || len(cred.Key.KeyValue) != 32 {
		t.Fatalf("credential %+v %v", cred, ok)
	}
	var tkt messages.Ticket
	if err := tkt.Unmarshal(cred.Ticket); err != nil || string(tkt.EncPart.Cipher) != "opaque" {
		t.Fatalf("ticket round trip: %v", err)
	}
}

type fakeResolver struct{ srvs map[string][]*net.SRV }

func (f fakeResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	key := fmt.Sprintf("_%s._%s.%s", service, proto, name)
	if s, ok := f.srvs[key]; ok {
		return key, s, nil
	}
	return "", nil, &net.DNSError{Err: "no such host", Name: key, IsNotFound: true}
}

func (f fakeResolver) LookupHost(context.Context, string) ([]string, error) { return nil, nil }

func TestDiscoverDCs(t *testing.T) {
	r := fakeResolver{srvs: map[string][]*net.SRV{
		"_ldap._tcp.dc._msdcs.lab.example.test": {
			{Target: "dc1.lab.example.test.", Port: 389, Priority: 0, Weight: 100},
			{Target: "DC2.lab.example.test.", Port: 389, Priority: 0, Weight: 100},
			{Target: "dc2.lab.example.test.", Port: 389},
			{Target: "bad host!.", Port: 389},
		},
	}}
	dcs, err := DiscoverDCs(context.Background(), r, "LAB.EXAMPLE.TEST", []string{"dc2.lab.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(dcs) != 2 || dcs[0].Host != "dc2.lab.example.test" || dcs[1].Host != "dc1.lab.example.test" {
		t.Fatalf("got %+v", dcs)
	}
	if _, err := DiscoverDCs(context.Background(), r, "OTHER.TEST", nil); err == nil {
		t.Fatal("expected lookup failure")
	}
	if _, err := DiscoverDCs(context.Background(), r, "bad realm", nil); err == nil {
		t.Fatal("expected invalid realm")
	}
}

func TestConfigRequiresPinnedCA(t *testing.T) {
	_, err := Connect(context.Background(), Config{Realm: "LAB.EXAMPLE.TEST", DCs: []string{"dc1.lab.example.test"}}, SimpleAuth("u", "p"))
	if err == nil || !strings.Contains(err.Error(), "RootCAs") {
		t.Fatalf("got %v", err)
	}
	if _, err := CertPoolFromPEM([]byte("not pem")); err == nil {
		t.Fatal("bad PEM accepted")
	}
}

func TestFailoverOnUnreachableDCs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // nothing listens there now: connection refused
	cfg := Config{Realm: "LAB.EXAMPLE.TEST", DCs: []string{"127.0.0.1", "127.0.0.2"}, LDAPSPort: port,
		InsecureSkipTLSVerifyForTestsOnly: true, DialTimeout: time.Second}
	_, err = Connect(context.Background(), cfg, SimpleAuth("u", "p"))
	var fe *FailoverError
	if !errors.As(err, &fe) || len(fe.Attempts) != 2 {
		t.Fatalf("want 2 failed attempts, got %v", err)
	}
}

func TestUACAndFileTime(t *testing.T) {
	u := UACNormalAccount | UACAccountDisable
	if u.String() != "ACCOUNTDISABLE|NORMAL_ACCOUNT" || !u.Has(UACAccountDisable) {
		t.Errorf("uac %s", u)
	}
	ts := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if got := FileTimeFrom(ts).Time(); !got.Equal(ts) {
		t.Errorf("filetime round trip %v", got)
	}
	if !Never.Time().IsZero() || !FileTime(0).Time().IsZero() {
		t.Error("never/zero")
	}
	user := User{AccountExpires: FileTimeFrom(ts.Add(-time.Hour))}
	if !user.AccountExpired(ts) {
		t.Error("account should be expired")
	}
}

func TestEncodePassword(t *testing.T) {
	got := []byte(encodePassword("Aé1"))
	want := []byte{'"', 0, 'A', 0, 0xe9, 0, '1', 0, '"', 0}
	if string(got) != string(want) {
		t.Fatalf("got %x", got)
	}
}

func TestOperationPreviews(t *testing.T) {
	op, err := CreateUser(NewUser{ParentDN: "OU=People,DC=lab,DC=test", CN: "Doe, John", SAMAccountName: "jdoe",
		UserPrincipalName: "jdoe@lab.test", GivenName: "John", Surname: "Doe", Password: "S3cret!pass", MustChangePassword: true})
	if err != nil {
		t.Fatal(err)
	}
	p := op.Preview().String()
	for _, want := range []string{
		`dn: CN=Doe\, John,OU=People,DC=lab,DC=test`, "changetype: add", "sAMAccountName: jdoe",
		"unicodePwd: <redacted>", "userAccountControl: 512", "pwdLastSet: 0",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("preview lacks %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "S3cret") {
		t.Fatal("password leaked into the preview")
	}

	disabled, _ := CreateUser(NewUser{ParentDN: "OU=People,DC=lab,DC=test", CN: "X", SAMAccountName: "x", UserPrincipalName: "x@lab.test"})
	if !strings.Contains(disabled.Preview().String(), "userAccountControl: 514") {
		t.Error("user without password must be created disabled")
	}

	en, err := SetUserEnabled(User{DN: "CN=X,DC=lab,DC=test", SAMAccountName: "x", UAC: 514}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := "dn: CN=X,DC=lab,DC=test\n# only if the entry still matches (userAccountControl=514)\ncontrol: 1.3.6.1.1.12 true\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: 512\n-\n"
	if got := en.Preview().String(); !strings.HasSuffix(got, want) {
		t.Errorf("enable preview:\n%s", got)
	}
	if _, err := SetUserEnabled(User{DN: "CN=X,DC=lab,DC=test", UAC: 512}, true); !errors.Is(err, ErrNoChange) {
		t.Errorf("want ErrNoChange, got %v", err)
	}

	ch, _ := ChangePassword("CN=X,DC=lab,DC=test", "old", "new")
	if got := ch.Preview().String(); !strings.Contains(got, "delete: unicodePwd\nunicodePwd: <redacted>\n-\nadd: unicodePwd\nunicodePwd: <redacted>") {
		t.Errorf("change preview:\n%s", got)
	}
	reset, _ := ResetPassword("CN=X,DC=lab,DC=test", "new", true)
	if got := reset.Preview().String(); !strings.Contains(got, "replace: unicodePwd") || !strings.Contains(got, "replace: pwdLastSet") {
		t.Errorf("reset preview:\n%s", got)
	}

	mv, err := MoveObject(`CN=Doe\, John,OU=A,DC=lab,DC=test`, "OU=B,DC=lab,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	if got := mv.Preview().String(); !strings.Contains(got, `newrdn: CN=Doe\, John`) || !strings.Contains(got, "newsuperior: OU=B,DC=lab,DC=test") {
		t.Errorf("move preview:\n%s", got)
	}

	g, _ := CreateGroup(NewGroup{ParentDN: "OU=G,DC=lab,DC=test", Name: "Ops"})
	if !strings.Contains(g.Preview().String(), "groupType: -2147483646") {
		t.Errorf("group preview:\n%s", g.Preview())
	}
	name := "Ana Maria"
	empty := ""
	up, _ := UpdateUser("CN=X,DC=lab,DC=test", UserUpdate{DisplayName: &name, Mail: &empty})
	if got := up.Preview().String(); !strings.Contains(got, "replace: displayName\ndisplayName: Ana Maria\n-\nreplace: mail\n-\n") {
		t.Errorf("update preview:\n%s", got)
	}
	nonASCII, _ := UpdateUser("CN=X,DC=lab,DC=test", UserUpdate{DisplayName: ptr("José")})
	if !strings.Contains(nonASCII.Preview().String(), "displayName:: Sm9zw6k=") {
		t.Errorf("non-ASCII values are base64 in LDIF:\n%s", nonASCII.Preview())
	}
}

func ptr(s string) *string { return &s }

func TestOperationValidation(t *testing.T) {
	bad := []func() (*Operation, error){
		func() (*Operation, error) {
			return CreateUser(NewUser{ParentDN: "OU=P,DC=x", CN: "a", SAMAccountName: "bad*name", UserPrincipalName: "a@x"})
		},
		func() (*Operation, error) {
			return CreateUser(NewUser{ParentDN: "OU=P,DC=x", CN: "a", SAMAccountName: "averyveryverylongname1", UserPrincipalName: "a@x"})
		},
		func() (*Operation, error) {
			return CreateUser(NewUser{ParentDN: "not a dn", CN: "a", SAMAccountName: "a", UserPrincipalName: "a@x"})
		},
		func() (*Operation, error) { return ResetPassword("CN=X,DC=x", "", false) },
		func() (*Operation, error) { return AddGroupMember("CN=G,DC=x", "garbage") },
		func() (*Operation, error) { return UpdateUser("CN=X,DC=x", UserUpdate{}) },
	}
	for i, f := range bad {
		if _, err := f(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
