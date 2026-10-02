package ad

import (
	"errors"
	"strings"
	"testing"
)

func strp(s string) *string { return &s }

func TestUpdateUserProfileAttributes(t *testing.T) {
	dn := "CN=Normal User,OU=Special,OU=Lab,DC=lab,DC=conductor,DC=test"
	op, err := UpdateUser(dn, UserUpdate{Mobile: strp("+55 11 5555-0000"), City: strp("Campinas"), Title: strp("")})
	if err != nil {
		t.Fatal(err)
	}
	got := op.Preview().String()
	for _, want := range []string{"replace: title\n-", "replace: mobile\nmobile: +55 11 5555-0000\n-", "replace: l\nl: Campinas\n-"} {
		if !strings.Contains(got, want) {
			t.Errorf("preview lacks %q:\n%s", want, got)
		}
	}
	// Order follows UserUpdateAttributes.
	if strings.Index(got, "title") > strings.Index(got, "mobile") || strings.Index(got, "mobile") > strings.Index(got, "replace: l\n") {
		t.Errorf("unexpected order:\n%s", got)
	}
	if _, err := UpdateUser(dn, UserUpdate{Mobile: strp("a\nb")}); err == nil {
		t.Error("control character accepted")
	}
	if _, err := UpdateUser(dn, UserUpdate{City: strp(strings.Repeat("x", 2000))}); err == nil {
		t.Error("oversized value accepted")
	}
	if _, err := UpdateUser(dn, UserUpdate{}); !errors.Is(err, ErrNoChange) {
		t.Errorf("empty update: %v", err)
	}
	attrs := UserUpdateAttributes()
	if len(attrs) != 17 || attrs[0] != "displayName" || attrs[len(attrs)-1] != "wWWHomePage" {
		t.Errorf("attributes %v", attrs)
	}
	for _, a := range attrs {
		found := false
		for _, r := range UserAttributes {
			if strings.EqualFold(a, r) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is writable but not read by UserAttributes", a)
		}
	}
}

func TestRenameObject(t *testing.T) {
	op, err := RenameObject("OU=Old Name,OU=Lab,DC=lab,DC=test", "New, Name")
	if err != nil {
		t.Fatal(err)
	}
	want := "dn: OU=Old Name,OU=Lab,DC=lab,DC=test\nchangetype: moddn\nnewrdn: OU=New\\, Name\ndeleteoldrdn: 1\n"
	if got := op.Preview().String(); !strings.HasSuffix(got, want) {
		t.Fatalf("preview:\n%s\nwant suffix:\n%s", got, want)
	}
	if _, err := RenameObject("OU=Same,DC=lab,DC=test", "Same"); !errors.Is(err, ErrNoChange) {
		t.Errorf("same name: %v", err)
	}
	if _, err := RenameObject("DC=test", "x"); err == nil {
		t.Error("renaming a root accepted")
	}
	if _, err := RenameObject("not a dn", "x"); err == nil {
		t.Error("invalid DN accepted")
	}
}

func TestSetComputerEnabled(t *testing.T) {
	ws := Computer{DN: "CN=WS0001,OU=Workstations,DC=lab,DC=test", SAMAccountName: "WS0001$", UAC: UACWorkstationTrustAccount}
	op, err := SetComputerEnabled(ws, false)
	if err != nil {
		t.Fatal(err)
	}
	p := op.Preview()
	if p.Changes[0].Assert == nil || !strings.Contains(p.String(), "userAccountControl: 4098") {
		t.Fatalf("preview:\n%s", p)
	}
	if _, err := SetComputerEnabled(ws, true); !errors.Is(err, ErrNoChange) {
		t.Errorf("enable an enabled computer: %v", err)
	}
	dc := Computer{DN: "CN=DC1,OU=Domain Controllers,DC=lab,DC=test", SAMAccountName: "DC1$", UAC: UACServerTrustAccount | UACTrustedForDelegation}
	if !dc.IsDomainController() || ws.IsDomainController() {
		t.Fatal("IsDomainController")
	}
	if _, err := SetComputerEnabled(dc, false); !errors.Is(err, ErrProtectedObject) {
		t.Errorf("disabling a DC: %v", err)
	}
}

func TestSortControlEncoding(t *testing.T) {
	// SEQUENCE { SEQUENCE { OCTET STRING "cn", [1] 0xFF } }
	got := sortControl{attr: "cn", reverse: true}.value()
	want := []byte{0x30, 0x09, 0x30, 0x07, 0x04, 0x02, 'c', 'n', 0x81, 0x01, 0xFF}
	if string(got) != string(want) {
		t.Fatalf("reverse key % x, want % x", got, want)
	}
	got = sortControl{attr: "cn"}.value()
	want = []byte{0x30, 0x06, 0x30, 0x04, 0x04, 0x02, 'c', 'n'}
	if string(got) != string(want) {
		t.Fatalf("forward key % x, want % x", got, want)
	}
	p := sortControl{attr: "cn"}.Encode()
	if len(p.Children) != 2 || p.Children[0].Value != "1.2.840.113556.1.4.473" {
		t.Fatalf("control packet %v", p.Children)
	}
}
