//go:build lab

// Integration test against the Samba lab
// (https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md),
// with the same environment as the ad package's lab tests: AD_LAB_REALM,
// AD_LAB_DNS, AD_LAB_CA, AD_LAB_ADMIN_USER, AD_LAB_ADMIN_PASSWORD and
// AD_LAB_USER_PASSWORD (scripts/lab-test.sh sets them). The seeded data
// has lab.admin in Domain Admins, helpdesk.user in the Helpdesk group that
// holds a Reset Password delegation on OU=People, and normal.user with no
// rights.
package privilege

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
)

func labEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s not set", name)
	}
	return v
}

func labConn(t *testing.T, ctx context.Context, user, password string) *ad.Conn {
	t.Helper()
	pemData, err := os.ReadFile(labEnv(t, "AD_LAB_CA"))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := ad.CertPoolFromPEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ad.Config{
		Realm:    labEnv(t, "AD_LAB_REALM"),
		Resolver: ad.NewDNSResolver(strings.Split(labEnv(t, "AD_LAB_DNS"), ",")...),
		RootCAs:  pool,
	}
	s, err := ad.SignIn(ctx, cfg, user, password)
	if err != nil {
		t.Fatalf("sign-in %s: %v", user, err)
	}
	t.Cleanup(s.Close)
	c, err := ad.Connect(ctx, cfg, ad.KerberosAuth(s))
	if err != nil {
		t.Fatalf("connect %s: %v", user, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestLabPrivilegeIndex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	accounts := map[string]*ad.Conn{
		// A Domain Admin, and an ordinary account: the index must build
		// with read access only.
		"admin":  labConn(t, ctx, labEnv(t, "AD_LAB_ADMIN_USER"), labEnv(t, "AD_LAB_ADMIN_PASSWORD")),
		"reader": labConn(t, ctx, "normal.user", labEnv(t, "AD_LAB_USER_PASSWORD")),
	}
	for name, c := range accounts {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			x, err := Build(ctx, c, Options{})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("index: %d SIDs, %d trustees, built in %s", x.Len(), len(x.TrusteeSIDs()), time.Since(start))
			for _, tc := range []struct {
				sam        string
				privileged bool
				kind       string
			}{
				{"lab.admin", true, KindGroup},
				{"helpdesk.user", true, KindACL},
				{"normal.user", false, ""},
			} {
				u, err := c.FindUser(ctx, tc.sam)
				if err != nil {
					t.Fatal(err)
				}
				reasons, err := x.Privileged(ctx, c, u.DN)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s: %v", tc.sam, reasons)
				if (len(reasons) > 0) != tc.privileged {
					t.Errorf("%s: privileged=%v, want %v (%v)", tc.sam, len(reasons) > 0, tc.privileged, reasons)
					continue
				}
				found := tc.kind == ""
				for _, r := range reasons {
					if r.Kind == tc.kind {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: no reason of kind %s in %v", tc.sam, tc.kind, reasons)
				}
			}
		})
	}
}
