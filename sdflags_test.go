package ad

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-ad/sd"
)

func TestSDFlagsControlEncoding(t *testing.T) {
	oid := hex.EncodeToString([]byte(ControlTypeSDFlags))
	for flags, value := range map[uint32]string{
		sd.FlagOwner | sd.FlagDACL:                              "3003020105",
		sd.FlagOwner | sd.FlagGroup | sd.FlagDACL | sd.FlagSACL: "300302010f",
	} {
		// SEQUENCE { type, criticality TRUE as 0xFF, OCTET STRING value }.
		want := "3022" + "0416" + oid + "0101ff" + "0405" + value
		got := hex.EncodeToString(sdFlagsControl{flags: flags}.Encode().Bytes())
		if got != want {
			t.Errorf("flags %#x:\n got %s\nwant %s", flags, got, want)
		}
	}
}

func TestParseSecurityDescriptor(t *testing.T) {
	h, err := os.ReadFile("sd/testdata/ou_people.hex")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(h)))
	if err != nil {
		t.Fatal(err)
	}
	e := ldap.NewEntry("OU=People,DC=example,DC=com", map[string][]string{"nTSecurityDescriptor": {string(raw)}})
	d, err := ParseSecurityDescriptor(e)
	if err != nil {
		t.Fatal(err)
	}
	if d.DACL == nil || len(d.DACL.ACEs) != 14 {
		t.Fatalf("DACL %+v", d.DACL)
	}
	empty := ldap.NewEntry("OU=People,DC=example,DC=com", nil)
	if _, err := ParseSecurityDescriptor(empty); !errors.Is(err, ErrNoSecurityDescriptor) {
		t.Fatalf("missing attribute: %v", err)
	}
	bad := ldap.NewEntry("OU=People,DC=example,DC=com", map[string][]string{"nTSecurityDescriptor": {string(raw[:30])}})
	if _, err := ParseSecurityDescriptor(bad); !errors.Is(err, sd.ErrMalformed) {
		t.Fatalf("truncated: %v", err)
	}
}
