package ad

import (
	"errors"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-ad/escape"
)

const (
	gpoA = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	gpoB = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
	gpoC = "{C06BDED1-2AED-457F-BE21-3D4BA75B44CE}"
)

func gpoDN(id string) string { return "cn=" + id + ",cn=policies,cn=system,DC=lab,DC=example" }

func TestParseAndFormatGPLink(t *testing.T) {
	v := "[LDAP://" + gpoDN(gpoA) + ";0][LDAP://" + strings.ToUpper(gpoDN(gpoB)) + ";2]"
	links, err := ParseGPLink(v)
	if err != nil || len(links) != 2 {
		t.Fatalf("%v %v", links, err)
	}
	if links[0].GPOID() != gpoA || links[1].GPOID() != gpoB || !links[1].Enforced() || !links[0].Enabled() {
		t.Fatalf("links %+v", links)
	}
	if FormatGPLink(links) != v {
		t.Fatalf("format %q", FormatGPLink(links))
	}
	if l, err := ParseGPLink(" "); err != nil || len(l) != 0 {
		t.Fatal("empty gPLink")
	}
	for _, bad := range []string{"LDAP://x;0", "[LDAP://x]", "[ldap://x;9]", "[LDAP://x;0", "[http://x;0]"} {
		if _, err := ParseGPLink(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if LinkOrder(1, 2) != 1 || LinkOrder(0, 2) != 2 {
		t.Fatal("link order: the last stored link is order 1")
	}
}

func TestChangeGPLink(t *testing.T) {
	raw := "[LDAP://" + gpoDN(gpoA) + ";0][LDAP://" + gpoDN(gpoB) + ";0]"
	links, _ := ParseGPLink(raw)
	ou := GPContainer{DN: "OU=People,DC=lab,DC=example", Name: "People", Kind: "ou", GPLink: raw, Links: links}
	c := GPO{ID: gpoC, DN: gpoDN(gpoC), DisplayName: "New"}
	a := GPO{ID: gpoA, DN: gpoDN(gpoA), DisplayName: "A"}
	b := GPO{ID: gpoB, DN: gpoDN(gpoB), DisplayName: "B"}

	value := func(op *Operation) string {
		t.Helper()
		ch := op.Preview().Changes[0]
		if ch.Assert == nil || ch.Attrs[0].Op != ModReplace || ch.Attrs[0].Name != "gPLink" {
			t.Fatalf("change %+v", ch)
		}
		if f, _ := escape.Compile(ch.Assert); !strings.Contains(f, "gPLink=") {
			t.Fatalf("assertion %s", f)
		}
		if len(ch.Attrs[0].Values) == 0 {
			return ""
		}
		return ch.Attrs[0].Values[0]
	}
	op, err := ChangeGPLink(ou, c, GPLinkAdd)
	if err != nil {
		t.Fatal(err)
	}
	// A new link has the lowest precedence: stored first.
	if v := value(op); !strings.HasPrefix(v, "[LDAP://"+gpoDN(gpoC)+";0]") || !strings.HasSuffix(v, raw) {
		t.Fatalf("link: %s", v)
	}
	if _, err := ChangeGPLink(ou, a, GPLinkAdd); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("double link: %v", err)
	}
	if _, err := ChangeGPLink(ou, c, GPLinkRemove); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlink of a GPO not linked: %v", err)
	}
	op, _ = ChangeGPLink(ou, a, GPLinkRemove)
	if v := value(op); v != "[LDAP://"+gpoDN(gpoB)+";0]" {
		t.Fatalf("unlink: %s", v)
	}
	op, _ = ChangeGPLink(ou, a, GPLinkEnforce)
	if v := value(op); !strings.Contains(v, gpoDN(gpoA)+";2]") {
		t.Fatalf("enforce: %s", v)
	}
	op, _ = ChangeGPLink(ou, b, GPLinkDisable)
	if v := value(op); !strings.Contains(v, gpoDN(gpoB)+";1]") {
		t.Fatalf("disable: %s", v)
	}
	if _, err := ChangeGPLink(ou, b, GPLinkEnable); !errors.Is(err, ErrNoChange) {
		t.Fatalf("enable an enabled link: %v", err)
	}
	// A (order 2) moves up to order 1: stored last.
	op, _ = ChangeGPLink(ou, a, GPLinkMoveUp)
	if v := value(op); v != "[LDAP://"+gpoDN(gpoB)+";0][LDAP://"+gpoDN(gpoA)+";0]" {
		t.Fatalf("move up: %s", v)
	}
	if _, err := ChangeGPLink(ou, b, GPLinkMoveUp); !errors.Is(err, ErrNoChange) {
		t.Fatalf("order 1 cannot move up: %v", err)
	}
	if !strings.Contains(op.Preview().String(), "link order 1: "+gpoA) {
		t.Fatalf("preview:\n%s", op.Preview())
	}
	// Removing the last link removes the attribute; a container without
	// gPLink asserts its absence.
	single := GPContainer{DN: ou.DN, Name: "People", Kind: "ou", GPLink: "[LDAP://" + gpoDN(gpoA) + ";0]", Links: links[:1]}
	if op, _ := ChangeGPLink(single, a, GPLinkRemove); value(op) != "" {
		t.Fatal("unlink of the last link")
	}
	empty := GPContainer{DN: ou.DN, Name: "People", Kind: "ou"}
	op, _ = ChangeGPLink(empty, c, GPLinkAdd)
	if f, _ := escape.Compile(op.Preview().Changes[0].Assert); f != "(!(gPLink=*))" {
		t.Fatalf("assertion on an empty container: %s", f)
	}
	if _, err := ChangeGPLink(GPContainer{DN: "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=lab,DC=example", Kind: "site"}, c, GPLinkAdd); err == nil {
		t.Fatal("site link accepted")
	}
}

func TestSetBlockInheritance(t *testing.T) {
	ou := GPContainer{DN: "OU=Support,DC=lab,DC=example", Name: "Support", Kind: "ou"}
	op, err := SetBlockInheritance(ou, true)
	if err != nil || op.Preview().Changes[0].Attrs[0].Values[0] != "1" {
		t.Fatalf("%v %v", op, err)
	}
	ou.BlockInheritance, ou.GPOptions = true, "1"
	if _, err := SetBlockInheritance(ou, true); !errors.Is(err, ErrNoChange) {
		t.Fatal("no-op accepted")
	}
	op, _ = SetBlockInheritance(ou, false)
	if op.Preview().Changes[0].Attrs[0].Values[0] != "0" {
		t.Fatal("clear")
	}
}
