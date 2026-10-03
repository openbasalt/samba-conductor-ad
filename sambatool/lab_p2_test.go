//go:build lab

package sambatool_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/sambatool"
)

// TestLabGPOWithUserCCache creates and deletes a GPO with samba-tool using
// only the signed-in user's Kerberos ticket (written by ad.Session as a
// ccache file): the path conductor uses, no password anywhere.
func TestLabGPOWithUserCCache(t *testing.T) {
	if os.Getenv("AD_LAB_SAMBATOOL") != "1" {
		t.Skip("AD_LAB_SAMBATOOL not set (run on a lab DC)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	realm := os.Getenv("AD_LAB_REALM")
	host, _ := os.Hostname()
	fqdn := strings.ToLower(strings.Split(host, ".")[0] + "." + realm)
	// Only the KDC is used here (no LDAP connection), so no CA is needed.
	cfg := ad.Config{Realm: realm, DCs: []string{fqdn}, InsecureSkipTLSVerifyForTestsOnly: true}
	s, err := ad.SignIn(ctx, cfg, os.Getenv("AD_LAB_ADMIN_USER"), os.Getenv("AD_LAB_ADMIN_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dir := t.TempDir()
	cc := filepath.Join(dir, "cc")
	if err := s.WriteCCache(cc); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	r := &sambatool.Runner{Credentials: sambatool.KerberosCCache{Path: cc}, Timeout: time.Minute,
		Env: []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=" + dir}}
	create := sambatool.GPOCreate{DisplayName: "P2 test " + hex.EncodeToString(b), URL: "ldap://" + fqdn}
	p, _ := sambatool.Preview(r, create)
	t.Logf("$ %s", p)
	id, err := sambatool.Run(ctx, r, create)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("created %s", id)
	if _, err := os.Stat("/var/lib/samba/sysvol/" + strings.ToLower(realm) + "/Policies/" + id); err != nil {
		t.Errorf("SYSVOL folder: %v", err)
	}
	del := sambatool.GPODelete{ID: id, URL: "ldap://" + fqdn}
	p, _ = sambatool.Preview(r, del)
	t.Logf("$ %s", p)
	if _, err := sambatool.Run(ctx, r, del); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/var/lib/samba/sysvol/" + strings.ToLower(realm) + "/Policies/" + id); !os.IsNotExist(err) {
		t.Errorf("SYSVOL folder left: %v", err)
	}
}
