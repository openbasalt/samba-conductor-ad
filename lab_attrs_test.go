//go:build lab

package ad

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// TestLabUserAttributes reads a user's raw attributes, edits allowlisted
// ones and checks the uidNumber uniqueness helper.
func TestLabUserAttributes(t *testing.T) {
	admin := adminConn(t)
	ctx := labCtx(t)
	suffix := randSuffix()
	var dns []string
	for i := range 2 {
		sam := "attrs." + suffix + strconv.Itoa(i)
		op, err := CreateUser(NewUser{ParentDN: "OU=Lab," + admin.BaseDN(), CN: "Attrs " + suffix + strconv.Itoa(i), SAMAccountName: sam,
			UserPrincipalName: sam + "@" + admin.DNSDomain(), Password: "Init-" + randSuffix() + "-Pw1"})
		if err != nil {
			t.Fatal(err)
		}
		if err := admin.Apply(ctx, op); err != nil {
			t.Fatal(err)
		}
		dn := op.Preview().Changes[0].DN
		dns = append(dns, dn)
		t.Cleanup(func() { del, _ := DeleteObject(dn); _ = admin.Apply(context.Background(), del) })
	}

	raw, err := admin.RawEntry(ctx, dns[0])
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]RawAttribute{}
	for _, a := range raw.Attributes {
		seen[strings.ToLower(a.Name)] = a
		if IsSecretAttribute(a.Name) && (!a.Hidden || len(a.Values) > 0) {
			t.Errorf("secret %s shown", a.Name)
		}
	}
	if a := seen["objectsid"]; len(a.Values) != 1 || !strings.HasPrefix(a.Values[0].Text, "S-1-5-21-") {
		t.Errorf("objectSid %+v", a)
	}
	if a := seen["samaccountname"]; len(a.Values) != 1 || a.Values[0].Text != "attrs."+suffix+"0" {
		t.Errorf("sAMAccountName %+v", a)
	}

	uid := strconv.Itoa(200000 + int(suffix[0])*100 + int(suffix[1]))
	op, err := UpdateUserAttributes(dns[0], []AttrReplace{{Name: "loginShell", After: []string{"/bin/bash"}}, {Name: "uidNumber", After: []string{uid}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("preview:\n%s", op.Preview())
	if err := admin.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	if in, err := admin.UIDNumberInUse(ctx, uid, dns[0]); err != nil || in {
		t.Fatalf("own uid counted as in use: %v %v", in, err)
	}
	if in, err := admin.UIDNumberInUse(ctx, uid, dns[1]); err != nil || !in {
		t.Fatalf("uid of another user not found: %v %v", in, err)
	}
	// A change computed from a stale read is refused by the assertion.
	stale, _ := UpdateUserAttributes(dns[0], []AttrReplace{{Name: "loginShell", After: []string{"/bin/zsh"}}})
	if err := admin.Apply(ctx, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale change: %v", err)
	}
	next, _ := UpdateUserAttributes(dns[0], []AttrReplace{{Name: "loginShell", Before: []string{"/bin/bash"}, After: []string{"/bin/zsh"}}})
	if err := admin.Apply(ctx, next); err != nil {
		t.Fatal(err)
	}
	e, err := admin.Get(ctx, dns[0], "loginShell", "uidNumber")
	if err != nil || e.GetAttributeValue("loginShell") != "/bin/zsh" || e.GetAttributeValue("uidNumber") != uid {
		t.Fatalf("after: %v %v", e, err)
	}
}
