//go:build lab

package ad

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/samba-conductor/ad/escape"
)

// userConn signs a seeded user in with Kerberos and binds.
func userConn(t *testing.T, sam, password string) *Conn {
	t.Helper()
	ctx := labCtx(t)
	cfg := labConfig(t)
	s, err := SignIn(ctx, cfg, sam, password)
	if err != nil {
		t.Fatalf("%s sign-in: %v", sam, err)
	}
	t.Cleanup(s.Close)
	c, err := Connect(ctx, cfg, KerberosAuth(s))
	if err != nil {
		t.Fatalf("%s connect: %v", sam, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// selfWritable is what Samba's default security descriptor lets a user
// write on their own account (SELF: Personal Information, Phone and Mail
// Options, Web Information property sets). Established by
// TestLabSelfWritableAttributes and used by conductor's self-service.
var selfWritable = []string{"telephoneNumber", "mobile", "homePhone", "physicalDeliveryOfficeName",
	"streetAddress", "l", "st", "postalCode", "wWWHomePage"}

func TestLabSelfWritableAttributes(t *testing.T) {
	ctx := labCtx(t)
	c := userConn(t, "normal.user", labEnv(t, "AD_LAB_USER_PASSWORD"))
	me, err := c.FindUser(ctx, "normal.user")
	if err != nil {
		t.Fatal(err)
	}
	var allowed, denied []string
	for _, attr := range UserUpdateAttributes() {
		v := "Lab " + attr
		if attr == "mail" {
			v = "normal.user.alt@lab.conductor.test"
		}
		u := UserUpdate{}
		setUpdateField(&u, attr, &v)
		op, err := UpdateUser(me.DN, u)
		if err != nil {
			t.Fatal(err)
		}
		err = c.Apply(ctx, op)
		switch {
		case err == nil:
			allowed = append(allowed, attr)
			// Put the original value back.
			orig := originalValue(me, attr)
			u2 := UserUpdate{}
			setUpdateField(&u2, attr, &orig)
			if op2, err := UpdateUser(me.DN, u2); err == nil {
				if err := c.Apply(ctx, op2); err != nil {
					t.Errorf("restore %s: %v", attr, err)
				}
			}
		case errors.Is(err, ErrAccessDenied):
			denied = append(denied, attr)
		default:
			t.Errorf("%s: unexpected error %v", attr, err)
		}
	}
	t.Logf("SELF may write: %s", strings.Join(allowed, ", "))
	t.Logf("SELF may not write: %s", strings.Join(denied, ", "))
	if !slices.Equal(allowed, selfWritable) {
		t.Fatalf("self-writable set changed: got %v want %v", allowed, selfWritable)
	}
}

func setUpdateField(u *UserUpdate, attr string, v *string) {
	m := map[string]**string{"displayName": &u.DisplayName, "givenName": &u.GivenName, "sn": &u.Surname,
		"mail": &u.Mail, "description": &u.Description, "department": &u.Department, "title": &u.Title,
		"telephoneNumber": &u.TelephoneNumber, "mobile": &u.Mobile, "homePhone": &u.HomePhone,
		"physicalDeliveryOfficeName": &u.Office, "company": &u.Company, "streetAddress": &u.StreetAddress,
		"l": &u.City, "st": &u.State, "postalCode": &u.PostalCode, "wWWHomePage": &u.HomePage}
	*m[attr] = v
}

func originalValue(u User, attr string) string {
	switch attr {
	case "telephoneNumber":
		return u.TelephoneNumber
	case "mobile":
		return u.Mobile
	case "homePhone":
		return u.HomePhone
	case "physicalDeliveryOfficeName":
		return u.Office
	case "streetAddress":
		return u.StreetAddress
	case "l":
		return u.City
	case "st":
		return u.State
	case "postalCode":
		return u.PostalCode
	case "wWWHomePage":
		return u.HomePage
	case "company":
		return u.Company
	case "title":
		return u.Title
	case "displayName":
		return u.DisplayName
	case "mail":
		return u.Mail
	}
	return ""
}

func TestLabSortedWindow(t *testing.T) {
	ctx := labCtx(t)
	c := adminConn(t)
	base := "OU=People,OU=Lab," + c.BaseDN()
	req := SearchRequest{BaseDN: base, Filter: userClass, Attributes: []string{"sAMAccountName"}, SortBy: "sAMAccountName"}
	var names []string
	for e, err := range c.Search(ctx, req) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, e.GetAttributeValue("sAMAccountName"))
	}
	if len(names) < 2500 || !slices.IsSorted(names) {
		t.Fatalf("sorted paged search: %d names, sorted=%v (first %v)", len(names), slices.IsSorted(names), names[:5])
	}
	t.Logf("sorted paged search over %d users: first %s, last %s", len(names), names[0], names[len(names)-1])
	req.SortReverse = true
	win, more, err := c.SearchWindow(ctx, req, 1000, 3)
	if err != nil || !more || len(win) != 3 {
		t.Fatalf("window: %d more=%v %v", len(win), more, err)
	}
	got := []string{win[0].GetAttributeValue("sAMAccountName"), win[2].GetAttributeValue("sAMAccountName")}
	if got[0] != names[len(names)-1001] || got[1] != names[len(names)-1003] {
		t.Fatalf("reverse window %v", got)
	}
	t.Logf("reverse window [1000,1003): %v", got)
	n, err := c.Count(ctx, SearchRequest{BaseDN: base, Filter: userClass})
	if err != nil || n != len(names) {
		t.Fatalf("count %d %v", n, err)
	}
	last, more, err := c.SearchWindow(ctx, SearchRequest{BaseDN: base, Filter: userClass, Attributes: []string{"1.1"}}, n-2, 5)
	if err != nil || more || len(last) != 2 {
		t.Fatalf("tail window: %d more=%v %v", len(last), more, err)
	}
}

func TestLabRenameAndComputer(t *testing.T) {
	ctx := labCtx(t)
	c := adminConn(t)
	sfx := randSuffix()
	parent := "OU=Lab," + c.BaseDN()
	op, err := CreateOU(NewOU{ParentDN: parent, Name: "Rename Test " + sfx})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	ouDN := op.Preview().Changes[0].DN
	ren, err := RenameObject(ouDN, "Renamed, "+sfx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("preview:\n%s", ren.Preview())
	if err := c.Apply(ctx, ren); err != nil {
		t.Fatal(err)
	}
	newDN, _ := escape.ChildDN("OU", "Renamed, "+sfx, parent)
	if _, err := c.Get(ctx, newDN, "ou"); err != nil {
		t.Fatalf("renamed OU: %v", err)
	}

	// A workstation account inside the renamed OU.
	name := strings.ToUpper("WS" + sfx)
	cdn, _ := escape.ChildDN("CN", name, newDN)
	add := &Operation{preview: Preview{Summary: "create computer", Changes: []Change{{Type: ChangeAdd, DN: cdn, Attrs: []AttrChange{
		{Name: "objectClass", Values: []string{"top", "person", "organizationalPerson", "user", "computer"}},
		{Name: "cn", Values: []string{name}},
		{Name: "sAMAccountName", Values: []string{name + "$"}},
		{Name: "userAccountControl", Values: []string{fmt.Sprint(uint32(UACWorkstationTrustAccount))}},
	}}}}}
	if err := c.Apply(ctx, add); err != nil {
		t.Fatal(err)
	}
	var comp Computer
	for x, err := range c.Computers(ctx, newDN, nil) {
		if err != nil {
			t.Fatal(err)
		}
		comp = x
	}
	if comp.DN == "" || !comp.Enabled() || comp.IsDomainController() {
		t.Fatalf("computer %+v", comp)
	}
	dis, _ := SetComputerEnabled(comp, false)
	if err := c.Apply(ctx, dis); err != nil {
		t.Fatal(err)
	}
	// The stale read is now a conflict.
	if err := c.Apply(ctx, dis); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale disable: %v", err)
	}
	var dcs []Computer
	for x, err := range c.Computers(ctx, "OU=Domain Controllers,"+c.BaseDN(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		dcs = append(dcs, x)
	}
	if len(dcs) < 2 || !dcs[0].IsDomainController() {
		t.Fatalf("DC accounts %+v", dcs)
	}
	if _, err := SetComputerEnabled(dcs[0], false); !errors.Is(err, ErrProtectedObject) {
		t.Fatalf("DC disable: %v", err)
	}
	// Non-empty OU cannot be deleted; empty it first.
	del, _ := DeleteObject(newDN)
	if err := c.Apply(ctx, del); err == nil {
		t.Fatal("deleted a non-empty OU")
	}
	n, err := c.Count(ctx, SearchRequest{BaseDN: newDN, Scope: ScopeOneLevel, Filter: escape.RawFilter("(objectClass=*)")})
	if err != nil || n != 1 {
		t.Fatalf("children %d %v", n, err)
	}
	for _, dn := range []string{cdn, newDN} {
		d, _ := DeleteObject(dn)
		if err := c.Apply(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("OU renamed, computer created/disabled/deleted, DC protected (%d DCs)", len(dcs))
}
