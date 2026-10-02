//go:build lab

// Integration tests against the Samba lab (planning/docs/lab.md). They run
// on server-home (or anywhere that reaches the lab network) with:
//
//	AD_LAB_REALM, AD_LAB_DNS (comma-separated DC IPs), AD_LAB_CA (CA PEM path),
//	AD_LAB_ADMIN_USER / AD_LAB_ADMIN_PASSWORD (a Domain Admin),
//	AD_LAB_USER_PASSWORD (seeded users), AD_LAB_HELPDESK_PASSWORD,
//	AD_LAB_DC1_STOP / AD_LAB_DC1_START (shell commands, failover test).
//
// scripts/lab-test.sh sets all of them from the lab's secrets file. Tests
// that change data create and delete their own objects; reset.sh restores
// the seeded snapshot when needed.
package ad

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/ad/escape"
	"github.com/samba-conductor/ad/sid"
)

func labEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s not set", name)
	}
	return v
}

func labConfig(t *testing.T) Config {
	t.Helper()
	pemData, err := os.ReadFile(labEnv(t, "AD_LAB_CA"))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := CertPoolFromPEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Realm:    labEnv(t, "AD_LAB_REALM"),
		Resolver: NewDNSResolver(strings.Split(labEnv(t, "AD_LAB_DNS"), ",")...),
		RootCAs:  pool,
	}
}

func labCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// adminConn signs the test Domain Admin in with Kerberos and binds.
func adminConn(t *testing.T) *Conn {
	t.Helper()
	ctx := labCtx(t)
	cfg := labConfig(t)
	s, err := SignIn(ctx, cfg, labEnv(t, "AD_LAB_ADMIN_USER"), labEnv(t, "AD_LAB_ADMIN_PASSWORD"))
	if err != nil {
		t.Fatalf("admin sign-in: %v", err)
	}
	t.Cleanup(s.Close)
	c, err := Connect(ctx, cfg, KerberosAuth(s))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func randSuffix() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TestLabDiscovery(t *testing.T) {
	ctx := labCtx(t)
	cfg := labConfig(t)
	dcs, err := DiscoverDCs(ctx, cfg.Resolver, cfg.Realm, []string{"dc2." + strings.ToLower(cfg.Realm)})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DCs (dc2 preferred): %+v", dcs)
	if len(dcs) != 2 || !strings.HasPrefix(dcs[0].Host, "dc2.") {
		t.Fatalf("want dc2 first of 2 DCs, got %+v", dcs)
	}
	kdcs, err := DiscoverKDCs(ctx, cfg.Resolver, cfg.Realm, nil)
	if err != nil || len(kdcs) != 2 {
		t.Fatalf("KDCs %+v %v", kdcs, err)
	}
}

func TestLabKerberosSignIn(t *testing.T) {
	ctx := labCtx(t)
	cfg := labConfig(t)
	s, err := SignIn(ctx, cfg, "user0001", labEnv(t, "AD_LAB_USER_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t.Logf("principal %s, TGT valid until %s", s.Principal(), s.Expires().Format(time.RFC3339))
	c, err := Connect(ctx, cfg, KerberosAuth(s))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	who, err := c.WhoAmI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GSSAPI bind on %s as %q (base %s, functional level %d)", c.DC().Host, who, c.BaseDN(), c.DomainFunctionality())
	if !strings.Contains(strings.ToLower(who), "user0001") {
		t.Fatalf("whoami %q", who)
	}
	if c.DomainFunctionality() < 7 {
		t.Fatalf("functional level %d, want 2016 (7)", c.DomainFunctionality())
	}
}

func TestLabSimpleBind(t *testing.T) {
	ctx := labCtx(t)
	c, err := Connect(ctx, labConfig(t), SimpleAuth("user0001", labEnv(t, "AD_LAB_USER_PASSWORD")))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	who, _ := c.WhoAmI(ctx)
	t.Logf("simple bind over TLS on %s as %q", c.DC().Host, who)
}

func TestLabTLSPinning(t *testing.T) {
	// A CA that did not sign the DCs' certificates must be refused.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Other CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pool, _ := CertPoolFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	cfg := labConfig(t)
	cfg.RootCAs = pool
	_, err := Connect(labCtx(t), cfg, SimpleAuth("user0001", labEnv(t, "AD_LAB_USER_PASSWORD")))
	var fe *FailoverError
	if !errors.As(err, &fe) || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("want certificate rejection on every DC, got %v", err)
	}
	t.Logf("unpinned CA refused: %v", err)
}

type subCodeCase struct {
	user, password string
	reason         Reason
	verified       bool
}

func subCodeCases(t *testing.T) []subCodeCase {
	pw := labEnv(t, "AD_LAB_USER_PASSWORD")
	wrong := "Wrong-" + randSuffix() + "-Pw1"
	return []subCodeCase{
		{"user0002", wrong, ReasonInvalidCredentials, false},
		{"no.such.user", wrong, ReasonInvalidCredentials, false},
		{"must.change", pw, ReasonPasswordMustChange, true},
		{"must.change", wrong, ReasonInvalidCredentials, false},
		{"expired.password", pw, ReasonPasswordExpired, true},
		{"expired.password", wrong, ReasonInvalidCredentials, false},
		{"locked.user", pw, ReasonAccountLocked, false},
		{"disabled.user", pw, ReasonAccountDisabled, false},
		{"expired.account", pw, ReasonAccountExpired, false},
	}
}

func TestLabSubCodesSimpleBind(t *testing.T) {
	cfg := labConfig(t)
	for _, c := range subCodeCases(t) {
		_, err := Connect(labCtx(t), cfg, SimpleAuth(c.user, c.password))
		var ae *AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("%s: want AuthError, got %v", c.user, err)
		}
		t.Logf("simple   %-17s %-5s -> %-26s code=%-4s verified=%v", c.user, okWrong(c.password, t), ae.Reason, ae.Code, ae.PasswordVerified())
		if ae.Reason != c.reason || ae.PasswordVerified() != c.verified {
			t.Errorf("%s: got %v verified=%v, want %v verified=%v", c.user, ae.Reason, ae.PasswordVerified(), c.reason, c.verified)
		}
	}
}

func TestLabSubCodesKerberos(t *testing.T) {
	cfg := labConfig(t)
	for _, c := range subCodeCases(t) {
		_, err := SignIn(labCtx(t), cfg, c.user, c.password)
		var ae *AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("%s: want AuthError, got %v", c.user, err)
		}
		t.Logf("kerberos %-17s %-5s -> %-26s code=%s verified=%v", c.user, okWrong(c.password, t), ae.Reason, ae.Code, ae.PasswordVerified())
		if ae.Reason != c.reason || ae.PasswordVerified() != c.verified {
			t.Errorf("%s: got %v verified=%v, want %v verified=%v", c.user, ae.Reason, ae.PasswordVerified(), c.reason, c.verified)
		}
	}
}

func okWrong(pw string, t *testing.T) string {
	if pw == os.Getenv("AD_LAB_USER_PASSWORD") {
		return "right"
	}
	return "wrong"
}

func TestLabPaging(t *testing.T) {
	c := adminConn(t)
	ctx := labCtx(t)
	people := "OU=People,OU=Lab," + c.BaseDN()

	// Windows AD truncates unpaged searches at MaxPageSize (1000); Samba
	// returns everything. The library pages either way: one page here must
	// hold exactly PageSize entries and a cookie for the next one.
	res, err := c.l.Search(ldap.NewSearchRequest(people, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)", []string{"1.1"}, []ldap.Control{ldap.NewControlPaging(500)}))
	if err != nil {
		t.Fatal(err)
	}
	cookie := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging).Cookie
	t.Logf("first page: %d entries, cookie %d bytes", len(res.Entries), len(cookie))
	if len(res.Entries) != 500 || len(cookie) == 0 {
		t.Fatal("the server did not page")
	}

	n := 0
	start := time.Now()
	for u, err := range c.Users(ctx, people, nil) {
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Logf("first: %s %s uac=%s", u.SAMAccountName, u.DN, u.UAC)
		}
		n++
	}
	t.Logf("paged search (page size %d): %d users in %s", DefaultPageSize, n, time.Since(start).Round(time.Millisecond))
	if n != 2500 {
		t.Fatalf("want 2500 users, got %d", n)
	}

	// Breaking out early abandons the server-side result set; the connection
	// stays usable.
	k := 0
	for _, err := range c.Search(ctx, SearchRequest{BaseDN: people, Filter: escape.Eq("objectClass", "user"), Attributes: []string{"cn"}, PageSize: 300}) {
		if err != nil {
			t.Fatal(err)
		}
		if k++; k == 450 {
			break
		}
	}
	if _, err := c.FindUser(ctx, "user2500"); err != nil {
		t.Fatalf("connection unusable after early break: %v", err)
	}
}

func TestLabGroupsBySID(t *testing.T) {
	c := adminConn(t)
	ctx := labCtx(t)
	big, err := c.FindGroup(ctx, "Big-Group")
	if err != nil {
		t.Fatal(err)
	}
	members, err := c.GroupMembers(ctx, big.DN)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Big Group: %d members (ranged retrieval)", len(members))
	if len(members) != 1600 {
		t.Fatalf("want 1600 members, got %d", len(members))
	}

	allStaff, err := c.FindGroup(ctx, "All-Staff")
	if err != nil {
		t.Fatal(err)
	}
	u1, err := c.FindUser(ctx, "user0001")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.IsMemberOfSID(ctx, u1.DN, allStaff.SID)
	if err != nil || !ok {
		t.Fatalf("user0001 should be a nested member of All Staff (%s): %v %v", allStaff.SID, ok, err)
	}
	inChain := 0
	for _, err := range c.Search(ctx, SearchRequest{Filter: escape.And(escape.Eq("objectClass", "user"), escape.InChain("memberOf", allStaff.DN)), Attributes: []string{"1.1"}}) {
		if err != nil {
			t.Fatal(err)
		}
		inChain++
	}
	t.Logf("All Staff transitive user members (LDAP_MATCHING_RULE_IN_CHAIN): %d", inChain)
	if inChain != 2500 {
		t.Fatalf("want 2500, got %d", inChain)
	}

	da, err := c.WellKnownGroupSID(ctx, sid.RIDDomainAdmins)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := c.FindUser(ctx, labEnv(t, "AD_LAB_ADMIN_USER"))
	isAdmin, _ := c.IsMemberOfSID(ctx, admin.DN, da)
	notAdmin, _ := c.IsMemberOfSID(ctx, u1.DN, da)
	t.Logf("Domain Admins %s: %s=%v user0001=%v", da, admin.SAMAccountName, isAdmin, notAdmin)
	if !isAdmin || notAdmin {
		t.Fatal("Domain Admins membership by SID is wrong")
	}
}

func TestLabEscapedNames(t *testing.T) {
	c := adminConn(t)
	ctx := labCtx(t)
	u, err := c.FindUser(ctx, "escape.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("escape.test DN: %s", u.DN)
	again, err := c.GetUser(ctx, u.DN)
	if err != nil || again.SAMAccountName != "escape.test" {
		t.Fatalf("read back by DN: %v", err)
	}
	cn := `Escape, Test #1 + "q" <x>; \ =`
	found, err := c.SearchAll(ctx, SearchRequest{Filter: escape.Eq("cn", cn), Attributes: []string{"sAMAccountName"}})
	if err != nil || len(found) != 1 {
		t.Fatalf("search by special-character CN: %d %v", len(found), err)
	}
	// An injection attempt is just a literal value that matches nothing.
	inj, err := c.SearchAll(ctx, SearchRequest{Filter: escape.Eq("sAMAccountName", "*)(sAMAccountName=*"), Attributes: []string{"1.1"}})
	if err != nil || len(inj) != 0 {
		t.Fatalf("injection matched %d entries (%v)", len(inj), err)
	}
}

// newTempUser creates a user in OU=People (where Helpdesk is delegated) and
// registers its deletion.
func newTempUser(t *testing.T, admin *Conn, password string, mustChange bool) User {
	t.Helper()
	ctx := labCtx(t)
	sam := "tmp." + randSuffix()
	op, err := CreateUser(NewUser{ParentDN: "OU=Support,OU=People,OU=Lab," + admin.BaseDN(), CN: "Temp " + sam,
		SAMAccountName: sam, UserPrincipalName: sam + "@" + admin.DNSDomain(), GivenName: "Temp", Surname: sam,
		Password: password, MustChangePassword: mustChange})
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Apply(ctx, op); err != nil {
		t.Fatalf("create %s: %v", sam, err)
	}
	u, err := admin.FindUser(ctx, sam)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		del, _ := DeleteObject(u.DN)
		_ = admin.Apply(context.Background(), del)
	})
	return u
}

func TestLabOperations(t *testing.T) {
	admin := adminConn(t)
	ctx := labCtx(t)
	suffix := randSuffix()

	ouOp, _ := CreateOU(NewOU{ParentDN: "OU=Lab," + admin.BaseDN(), Name: "Ops Test " + suffix, Description: "integration test"})
	t.Logf("preview:\n%s", ouOp.Preview())
	if err := admin.Apply(ctx, ouOp); err != nil {
		t.Fatal(err)
	}
	ouDN := ouOp.Preview().Changes[0].DN
	t.Cleanup(func() { del, _ := DeleteObject(ouDN); _ = admin.Apply(context.Background(), del) })

	grpOp, _ := CreateGroup(NewGroup{ParentDN: ouDN, Name: "Ops Group " + suffix, SAMAccountName: "ops-" + suffix})
	if err := admin.Apply(ctx, grpOp); err != nil {
		t.Fatal(err)
	}
	grpDN := grpOp.Preview().Changes[0].DN
	t.Cleanup(func() { del, _ := DeleteObject(grpDN); _ = admin.Apply(context.Background(), del) })

	pw := "Init-" + randSuffix() + "-Pw1"
	userOp, err := CreateUser(NewUser{ParentDN: ouDN, CN: "Ops, User " + suffix, SAMAccountName: "ops.u" + suffix,
		UserPrincipalName: "ops.u" + suffix + "@" + admin.DNSDomain(), DisplayName: "Ops User", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("preview:\n%s", userOp.Preview())
	if strings.Contains(userOp.Preview().String(), pw) {
		t.Fatal("password in preview")
	}
	if err := admin.Apply(ctx, userOp); err != nil {
		t.Fatal(err)
	}
	u, err := admin.FindUser(ctx, "ops.u"+suffix)
	if err != nil {
		t.Fatal(err)
	}

	add, _ := AddGroupMember(grpDN, u.DN)
	if err := admin.Apply(ctx, add); err != nil {
		t.Fatal(err)
	}
	g, _ := admin.FindGroup(ctx, "ops-"+suffix)
	if in, _ := admin.IsMemberOfSID(ctx, u.DN, g.SID); !in {
		t.Fatal("membership not visible by SID")
	}

	dis, _ := SetUserEnabled(u, false)
	t.Logf("preview:\n%s", dis.Preview())
	if err := admin.Apply(ctx, dis); err != nil {
		t.Fatal(err)
	}
	// u is now a stale read (it still says "enabled"): a change computed
	// from it must not overwrite the newer state blindly.
	stale, _ := SetUserEnabled(u, false)
	err = admin.Apply(ctx, stale)
	t.Logf("change computed from a stale read: %v", err)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict from a stale read, got %v", err)
	}
	fresh, _ := admin.GetUser(ctx, u.DN)
	en, _ := SetUserEnabled(fresh, true)
	if err := admin.Apply(ctx, en); err != nil {
		t.Fatal(err)
	}

	title := "Integration " + suffix
	upd, _ := UpdateUser(u.DN, UserUpdate{Title: &title})
	if err := admin.Apply(ctx, upd); err != nil {
		t.Fatal(err)
	}

	mv, _ := MoveObject(u.DN, "OU=Support,OU=People,OU=Lab,"+admin.BaseDN())
	t.Logf("preview:\n%s", mv.Preview())
	if err := admin.Apply(ctx, mv); err != nil {
		t.Fatal(err)
	}
	moved, err := admin.FindUser(ctx, "ops.u"+suffix)
	if err != nil || !strings.Contains(moved.DN, "OU=Support") || moved.Title != title {
		t.Fatalf("after move: %+v %v", moved, err)
	}
	t.Cleanup(func() { del, _ := DeleteObject(moved.DN); _ = admin.Apply(context.Background(), del) })

	rm, _ := RemoveGroupMember(grpDN, moved.DN)
	if err := admin.Apply(ctx, rm); err != nil {
		t.Fatal(err)
	}

	// Lock the account with bad binds (domain threshold 10), then unlock.
	cfg := labConfig(t)
	cfg.DCs = []string{admin.DC().Host} // lockout state is per-DC until replicated
	for range 11 {
		_, _ = Connect(ctx, cfg, SimpleAuth(moved.SAMAccountName, "bad-"+randSuffix()))
	}
	locked, _ := admin.GetUser(ctx, moved.DN)
	t.Logf("after 11 bad binds: locked=%v lockoutTime=%s", locked.Locked(), locked.LockoutTime.Time().Format(time.RFC3339))
	if !locked.Locked() {
		t.Fatal("account not locked")
	}
	unlock, _ := UnlockUser(moved.DN)
	if err := admin.Apply(ctx, unlock); err != nil {
		t.Fatal(err)
	}
	if again, _ := admin.GetUser(ctx, moved.DN); again.Locked() {
		t.Fatal("still locked")
	}
	if _, err := Connect(ctx, cfg, SimpleAuth(moved.SAMAccountName, pw)); err != nil {
		t.Fatalf("sign-in after unlock: %v", err)
	}
}

func TestLabPasswordChangeVsReset(t *testing.T) {
	admin := adminConn(t)
	ctx := labCtx(t)
	cfg := labConfig(t)
	// Read-your-writes: the user is created on admin's DC; until it
	// replicates, only that DC (LDAP and KDC) knows it.
	cfg.Preferred = []string{admin.DC().Host}
	p1 := "First-" + randSuffix() + "-Pw1"
	u := newTempUser(t, admin, p1, false)

	// Self-service change over LDAP, bound as the user.
	self, err := Connect(ctx, cfg, SimpleAuth(u.SAMAccountName, p1))
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	wrongOld, _ := ChangePassword(u.DN, "Not-the-old-1", "Next-"+randSuffix()+"-Pw2")
	err = self.Apply(ctx, wrongOld)
	t.Logf("change with wrong old password: %v", err)
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("want ErrWrongPassword, got %v", err)
	}
	weak, _ := ChangePassword(u.DN, p1, "abc")
	err = self.Apply(ctx, weak)
	t.Logf("change to a weak password: %v", err)
	if !errors.Is(err, ErrPasswordPolicy) {
		t.Errorf("want ErrPasswordPolicy, got %v", err)
	}
	p2 := "Second-" + randSuffix() + "-Pw2"
	chg, _ := ChangePassword(u.DN, p1, p2)
	t.Logf("preview:\n%s", chg.Preview())
	if err := self.Apply(ctx, chg); err != nil {
		t.Fatalf("self change: %v", err)
	}
	if s, err := SignIn(ctx, cfg, u.SAMAccountName, p2); err != nil {
		t.Fatalf("Kerberos with the new password: %v", err)
	} else {
		s.Close()
	}

	// A plain user cannot reset someone else's password.
	other := newTempUser(t, admin, "Other-"+randSuffix()+"-Pw1", false)
	r, _ := ResetPassword(other.DN, "Hijack-"+randSuffix()+"-Pw1", false)
	err = self.Apply(ctx, r)
	t.Logf("plain user resetting another user: %v", err)
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied, got %v", err)
	}

	// Helpdesk (delegated on OU=People) resets and forces a change...
	hd, err := Connect(ctx, cfg, SimpleAuth("helpdesk.user", labEnv(t, "AD_LAB_HELPDESK_PASSWORD")))
	if err != nil {
		t.Fatal(err)
	}
	defer hd.Close()
	p3 := "Reset-" + randSuffix() + "-Pw3"
	reset, _ := ResetPassword(u.DN, p3, true)
	t.Logf("preview:\n%s", reset.Preview())
	if err := hd.Apply(ctx, reset); err != nil {
		t.Fatalf("helpdesk reset: %v", err)
	}
	// ...but has no rights outside OU=People (the Domain Admin test account).
	adminUser, _ := admin.FindUser(ctx, labEnv(t, "AD_LAB_ADMIN_USER"))
	steal, _ := ResetPassword(adminUser.DN, "Steal-"+randSuffix()+"-Pw1", false)
	err = hd.Apply(ctx, steal)
	t.Logf("helpdesk resetting a Domain Admin: %v", err)
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("want ErrAccessDenied, got %v", err)
	}

	// After the reset with must-change, LDAP says 773 (password verified)...
	_, err = Connect(ctx, cfg, SimpleAuth(u.SAMAccountName, p3))
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Reason != ReasonPasswordMustChange || !ae.PasswordVerified() {
		t.Fatalf("want must-change, got %v", err)
	}
	// ...and the user changes it through kpasswd, which needs no bind.
	p4 := "Fourth-" + randSuffix() + "-Pw4"
	if err := ChangePasswordKerberos(ctx, cfg, u.SAMAccountName, p3, p4); err != nil {
		t.Fatalf("kpasswd: %v", err)
	}
	err = ChangePasswordKerberos(ctx, cfg, u.SAMAccountName, "Wrong-old-"+randSuffix(), "Fifth-"+randSuffix()+"-Pw5")
	t.Logf("kpasswd with a wrong old password: %v", err)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials, got %v", err)
	}
	c, err := Connect(ctx, cfg, SimpleAuth(u.SAMAccountName, p4))
	if err != nil {
		t.Fatalf("bind after kpasswd: %v", err)
	}
	_ = c.Close()
	t.Log("reset (admin/helpdesk) and change (self, LDAP and kpasswd) behave as expected")
}

func TestLabZFailover(t *testing.T) {
	stop := labEnv(t, "AD_LAB_DC1_STOP")
	start := labEnv(t, "AD_LAB_DC1_START")
	ctx := labCtx(t)
	cfg := labConfig(t)
	cfg.Preferred = []string{"dc1." + strings.ToLower(cfg.Realm)}
	cfg.DialTimeout = 3 * time.Second

	run := func(cmd string) {
		out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("%q: %v %s", cmd, err, out)
		}
	}
	run(stop)
	t.Cleanup(func() { run(start) })
	t.Log("dc1 stopped")

	s, err := SignIn(ctx, cfg, "user0001", labEnv(t, "AD_LAB_USER_PASSWORD"))
	if err != nil {
		t.Fatalf("Kerberos sign-in with dc1 down: %v", err)
	}
	defer s.Close()
	c, err := Connect(ctx, cfg, KerberosAuth(s))
	if err != nil {
		t.Fatalf("connect with dc1 down: %v", err)
	}
	defer c.Close()
	t.Logf("dc1 preferred but down: bound to %s", c.DC().Host)
	if !strings.HasPrefix(c.DC().Host, "dc2.") {
		t.Fatalf("expected dc2, got %s", c.DC().Host)
	}
	if _, err := c.FindUser(ctx, "user2500"); err != nil {
		t.Fatal(err)
	}
}
