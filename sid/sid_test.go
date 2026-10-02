package sid

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	// objectSid of a domain admin group as returned by AD.
	raw, _ := hex.DecodeString("010500000000000515000000a065cf7e784b9b5fe77c8770" + "00020000")
	s, err := FromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := "S-1-5-21-2127521184-1604012920-1887927527-512"
	if s.String() != want {
		t.Fatalf("got %s want %s", s, want)
	}
	if !bytes.Equal(s.Bytes(), raw) {
		t.Fatal("bytes round trip")
	}
	p, err := Parse(want)
	if err != nil || !p.Equal(s) {
		t.Fatalf("parse: %v %v", p, err)
	}
	rid, ok := s.RID()
	if !ok || rid != RIDDomainAdmins {
		t.Fatalf("rid %d %v", rid, ok)
	}
	dom, _ := s.Domain()
	back, err := dom.WithRID(RIDDomainAdmins)
	if err != nil || !back.Equal(s) {
		t.Fatalf("WithRID: %v %v", back, err)
	}
}

func TestBuiltin(t *testing.T) {
	if BuiltinAdministrators.String() != "S-1-5-32-544" {
		t.Fatal(BuiltinAdministrators)
	}
	if _, ok := BuiltinAdministrators.RID(); ok {
		t.Fatal("BUILTIN is not a domain account SID")
	}
	if !Contains([]SID{Everyone, BuiltinAdministrators}, MustParse("S-1-5-32-544")) {
		t.Fatal("Contains")
	}
}

func TestInvalid(t *testing.T) {
	for _, s := range []string{"", "S-1", "S-2-5-1", "S-1-x-1", "S-1-5-01", "S-1-5-4294967296", "S-1-5--1",
		"S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
	for _, b := range [][]byte{nil, {1}, {1, 1, 0, 0, 0, 0, 0, 5}, {2, 0, 0, 0, 0, 0, 0, 5}} {
		if _, err := FromBytes(b); err == nil {
			t.Errorf("FromBytes(%x) accepted", b)
		}
	}
	if _, err := BuiltinAdministrators.WithRID(1); err == nil {
		t.Error("WithRID on a non-domain SID")
	}
}

func TestGUID(t *testing.T) {
	// The schema GUID of the user class, in AD's binary layout.
	raw, _ := hex.DecodeString("ba7a96bfe60dd011a28500aa003049e2")
	g, err := GUIDFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if g.String() != "bf967aba-0de6-11d0-a285-00aa003049e2" {
		t.Fatalf("got %s", g)
	}
	p, err := ParseGUID("{BF967ABA-0DE6-11D0-A285-00AA003049E2}")
	if err != nil || p != g {
		t.Fatalf("ParseGUID: %v %v", p, err)
	}
	if _, err := ParseGUID("nope"); err == nil {
		t.Fatal("accepted bad GUID")
	}
}

func FuzzSID(f *testing.F) {
	f.Add([]byte{1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := FromBytes(b)
		if err != nil {
			return
		}
		if !bytes.Equal(s.Bytes(), b) {
			t.Fatalf("bytes round trip %x", b)
		}
		p, err := Parse(s.String())
		if err != nil || !p.Equal(s) {
			t.Fatalf("string round trip %s: %v", s, err)
		}
	})
}
