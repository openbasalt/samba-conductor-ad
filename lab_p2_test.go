//go:build lab

package ad

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/samba-conductor/ad/escape"
)

// labDNSLookup resolves name through the DC's own DNS server (what clients
// of the domain see).
func labDNSLookup(t *testing.T, dc, name string) []string {
	t.Helper()
	r := NewDNSResolver(dc)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, _ := r.LookupHost(ctx, name)
	return addrs
}

func TestLabDNSReadSeeded(t *testing.T) {
	ctx := labCtx(t)
	c := adminConn(t)
	zones, err := c.DNSZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]DNSZone{}
	for _, z := range zones {
		byName[z.Name] = z
		t.Logf("zone %s (%s) reverse=%v", z.Name, z.Partition, z.Reverse())
	}
	for name, part := range map[string]string{"lab.conductor.test": DNSPartitionDomain, "_msdcs.lab.conductor.test": DNSPartitionForest,
		"apps.conductor.test": DNSPartitionDomain, "0.93.10.in-addr.arpa": DNSPartitionDomain} {
		if byName[name].Partition != part {
			t.Errorf("zone %s: %+v", name, byName[name])
		}
	}
	pol, err := c.DNSPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("policy %+v", pol)
	if !slices.Contains(pol.DCHosts, "dc1.lab.conductor.test") || !slices.Contains(pol.DCHosts, "dc2.lab.conductor.test") {
		t.Fatalf("DCs not discovered: %v", pol.DCHosts)
	}
	// Every record of the AD zones decodes, and the classification holds.
	for _, zn := range []string{"lab.conductor.test", "_msdcs.lab.conductor.test", "apps.conductor.test"} {
		z := byName[zn]
		for skip := 0; ; skip += 100 {
			nodes, more, err := c.DNSNodes(ctx, z, "", skip, 100)
			if err != nil {
				t.Fatalf("%s: %v", zn, err)
			}
			for _, n := range nodes {
				for _, r := range n.Records {
					if strings.HasPrefix(r.Data, `\#`) {
						t.Errorf("%s %s: undecoded %s", zn, n.Name, r)
					}
				}
			}
			if !more {
				break
			}
		}
	}
	apps := byName["apps.conductor.test"]
	page, more, err := c.DNSNodes(ctx, apps, "", 0, 50)
	if err != nil || len(page) != 50 || !more {
		t.Fatalf("apps page 1: %d more=%v %v", len(page), more, err)
	}
	www, err := c.DNSNodeByName(ctx, apps, "www")
	if err != nil || len(www.Records) != 2 {
		t.Fatalf("www: %+v %v", www, err)
	}
	if pol.ProtectedNode(apps.Name, www) {
		t.Fatal("a user record shown as protected")
	}
	srv, _ := c.DNSNodeByName(ctx, byName["lab.conductor.test"], "_ldap._tcp")
	if !pol.ProtectedNode("lab.conductor.test", srv) || len(srv.Records) < 2 {
		t.Fatalf("_ldap._tcp: %+v", srv)
	}
}

func TestLabDNSZoneLifecycle(t *testing.T) {
	ctx := labCtx(t)
	c := adminConn(t)
	pol, err := c.DNSPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	container, err := c.DNSPartitionDN(DNSPartitionDomain)
	if err != nil {
		t.Fatal(err)
	}
	name := "p2-" + randSuffix() + ".test"
	op, err := CreateDNSZone(container, name, c.DCHostName(), pol)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("preview:\n%s", op.Preview())
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	z, err := c.DNSZoneByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if op, err := DeleteDNSZone(z, pol, 0); err == nil {
			_ = c.Apply(context.Background(), op)
		}
	}()
	// Ask the DNS server of the DC that took the writes.
	ips, err := NewDNSResolver(strings.Split(labEnv(t, "AD_LAB_DNS"), ",")...).LookupHost(ctx, c.DC().Host)
	if err != nil || len(ips) == 0 {
		t.Fatalf("address of %s: %v", c.DC().Host, err)
	}
	dcAddr := ips[0]
	apex, err := c.DNSNodeByName(ctx, z, "@")
	if err != nil || len(apex.Records) != 2 {
		t.Fatalf("apex %+v %v", apex, err)
	}
	// Add: the DC's DNS server answers right away.
	rec, _ := NewDNSRecord(DNSTypeA, "192.0.2.77", 300)
	node, _ := c.DNSNodeByName(ctx, z, "www")
	op, err = AddDNSRecord(z, pol, apex, node, rec)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("preview:\n%s", op.Preview())
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	if got := labDNSLookup(t, dcAddr, "www."+name); !slices.Contains(got, "192.0.2.77") {
		t.Fatalf("DNS answer after add: %v", got)
	}
	// The SOA serial moved from 1 to 2.
	apex, _ = c.DNSNodeByName(ctx, z, "@")
	for _, r := range apex.Records {
		if r.Type == DNSTypeSOA {
			if s, _ := soaSerial(r); s != 2 {
				t.Fatalf("SOA serial %d", s)
			}
		}
	}
	// A stale apex (old serial) is a conflict, not an overwrite.
	stale := apex
	stale.Records = slices.Clone(apex.Records)
	for i, r := range stale.Records {
		if r.Type == DNSTypeSOA {
			stale.Records[i] = withSOASerial(r, 1)
			stale.Records[i].raw, _ = EncodeDNSRecord(stale.Records[i])
		}
	}
	node, _ = c.DNSNodeByName(ctx, z, "www")
	rec2, _ := NewDNSRecord(DNSTypeA, "192.0.2.78", 300)
	if op, err := AddDNSRecord(z, pol, stale, node, rec2); err == nil {
		if err := c.Apply(ctx, op); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale SOA: %v", err)
		}
	}
	// Update, then a second type at the same name.
	op, err = UpdateDNSRecord(z, pol, apex, node, node.Records[0], rec2)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	if got := labDNSLookup(t, dcAddr, "www."+name); !slices.Contains(got, "192.0.2.78") || slices.Contains(got, "192.0.2.77") {
		t.Fatalf("DNS answer after update: %v", got)
	}
	for _, typed := range []struct {
		t    DNSType
		name string
		data string
	}{{DNSTypeTXT, "@", "v=spf1 -all"}, {DNSTypeMX, "@", "10 mail." + name}, {DNSTypeCNAME, "app", "www." + name},
		{DNSTypeSRV, "_http._tcp", "0 5 80 www." + name}, {DNSTypeAAAA, "www", "2001:db8::77"}} {
		apex, _ = c.DNSNodeByName(ctx, z, "@")
		n, _ := c.DNSNodeByName(ctx, z, typed.name)
		r, err := NewDNSRecord(typed.t, typed.data, 0)
		if err != nil {
			t.Fatal(err)
		}
		op, err := AddDNSRecord(z, pol, apex, n, r)
		if err != nil {
			t.Fatalf("%s: %v", typed.t, err)
		}
		if err := c.Apply(ctx, op); err != nil {
			t.Fatalf("%s: %v", typed.t, err)
		}
		back, _ := c.DNSNodeByName(ctx, z, typed.name)
		if !slices.ContainsFunc(back.Records, func(x DNSRecord) bool { return x.Equal(r) }) {
			t.Fatalf("%s not read back: %+v", typed.t, back.Records)
		}
	}
	// Delete the last record of a name: the name goes away.
	apex, _ = c.DNSNodeByName(ctx, z, "@")
	app, _ := c.DNSNodeByName(ctx, z, "app")
	op, err = DeleteDNSRecord(z, pol, apex, app, app.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	if gone, _ := c.DNSNodeByName(ctx, z, "app"); gone.Exists {
		t.Fatal("name kept after its last record")
	}
	// Delete the zone with everything in it.
	n, _ := c.CountDNSNodes(ctx, z)
	op, err = DeleteDNSZone(z, pol, n)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DNSZoneByName(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zone still there: %v", err)
	}
	if got := labDNSLookup(t, dcAddr, "www."+name); len(got) != 0 {
		t.Fatalf("deleted zone still answers: %v", got)
	}
}

func TestLabGPOLinks(t *testing.T) {
	ctx := labCtx(t)
	c := adminConn(t)
	gpos, err := c.GPOs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]GPO{}
	for _, g := range gpos {
		byName[g.DisplayName] = g
		t.Logf("GPO %s %s flags=%d version=%d/%d", g.ID, g.DisplayName, g.Flags, g.UserVersion(), g.ComputerVersion())
	}
	for _, n := range []string{"Default Domain Policy", "Lab Baseline", "Lab People Policy", "Lab Disabled Link", "Lab Unlinked"} {
		if byName[n].ID == "" {
			t.Fatalf("GPO %q missing", n)
		}
	}
	containers, err := c.GPContainers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, gc := range containers {
		t.Logf("%s %s links=%d block=%v", gc.Kind, gc.DN, len(gc.Links), gc.BlockInheritance)
	}
	if len(LinksTo(containers, byName["Lab Unlinked"].ID)) != 0 || len(LinksTo(containers, byName["Lab Baseline"].ID)) != 1 {
		t.Fatal("seeded links")
	}
	// A temporary OU: link, enforce, disable, reorder, unlink; block inheritance.
	ouName := "GPO Test " + randSuffix()
	op, _ := CreateOU(NewOU{ParentDN: "OU=Lab," + c.BaseDN(), Name: ouName})
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	ouDN := op.Preview().Changes[0].DN
	defer func() {
		if op, err := DeleteObject(ouDN); err == nil {
			_ = c.Apply(context.Background(), op)
		}
	}()
	step := func(g GPO, a GPLinkAction) GPContainer {
		t.Helper()
		gc, err := c.GPContainerByDN(ctx, ouDN)
		if err != nil {
			t.Fatal(err)
		}
		op, err := ChangeGPLink(gc, g, a)
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		if err := c.Apply(ctx, op); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		gc, _ = c.GPContainerByDN(ctx, ouDN)
		return gc
	}
	gc := step(byName["Lab Unlinked"], GPLinkAdd)
	gc = step(byName["Lab People Policy"], GPLinkAdd)
	if len(gc.Links) != 2 || gc.Links[1].GPOID() != byName["Lab Unlinked"].ID {
		t.Fatalf("after two links: %+v", gc.Links)
	}
	gc = step(byName["Lab People Policy"], GPLinkMoveUp)
	if gc.Links[1].GPOID() != byName["Lab People Policy"].ID {
		t.Fatalf("order: %+v", gc.Links)
	}
	gc = step(byName["Lab Unlinked"], GPLinkEnforce)
	gc = step(byName["Lab Unlinked"], GPLinkDisable)
	if gc.Links[0].Options != GPLinkDisabled|GPLinkEnforced {
		t.Fatalf("options: %+v", gc.Links)
	}
	// A stale gPLink is a conflict.
	stale := gc
	stale.GPLink = "[LDAP://" + byName["Lab Unlinked"].DN + ";0]"
	stale.Links, _ = ParseGPLink(stale.GPLink)
	if op, err := ChangeGPLink(stale, byName["Lab Unlinked"], GPLinkRemove); err == nil {
		if err := c.Apply(ctx, op); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale gPLink: %v", err)
		}
	}
	gc = step(byName["Lab Unlinked"], GPLinkRemove)
	gc = step(byName["Lab People Policy"], GPLinkRemove)
	if gc.GPLink != "" && len(gc.Links) != 0 {
		t.Fatalf("links left: %q", gc.GPLink)
	}
	op, err = SetBlockInheritance(gc, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	gc, _ = c.GPContainerByDN(ctx, ouDN)
	if !gc.BlockInheritance {
		t.Fatal("block inheritance not set")
	}
}

func TestLabPasswordPolicies(t *testing.T) {
	ctx := labCtx(t)
	c := adminConn(t)
	d, err := c.DomainPasswordPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("domain policy %+v", d.Policy)
	if d.Policy.LockoutThreshold != 10 || d.Policy.MaxAge != 0 || d.Policy.MinLength != 7 {
		t.Fatalf("seeded domain policy %+v", d.Policy)
	}
	// Change and restore one setting, asserting the old values.
	next := d.Policy
	next.MinLength = 8
	op, err := UpdateDomainPasswordPolicy(d, next)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("preview:\n%s", op.Preview())
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	d2, _ := c.DomainPasswordPolicy(ctx)
	if d2.Policy.MinLength != 8 {
		t.Fatal("not applied")
	}
	// d is stale now: restoring from it would assert min length 7.
	if op, err := UpdateDomainPasswordPolicy(d, func() PasswordPolicy { p := d.Policy; p.MinLength = 9; return p }()); err == nil {
		if err := c.Apply(ctx, op); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale domain policy: %v", err)
		}
	}
	op, _ = UpdateDomainPasswordPolicy(d2, d.Policy)
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}

	psos, err := c.PSOs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(psos, func(p PSO) bool { return p.Name == "lab-staff-20d" && p.Policy.MaxAge == 20*24*time.Hour }) {
		t.Fatalf("seeded PSOs %+v", psos)
	}
	// The seeded user's effective policy is the 20-day PSO.
	u, err := c.FindUser(ctx, "user0101")
	if err != nil {
		t.Fatal(err)
	}
	ep, err := c.EffectivePasswordPolicy(ctx, u.DN)
	if err != nil || ep.PSO == nil || ep.PSO.Name != "lab-staff-20d" {
		t.Fatalf("effective policy of user0101: %+v %v", ep, err)
	}
	if ep.PasswordExpires.IsZero() || ep.PasswordExpires.After(time.Now().Add(21*24*time.Hour)) {
		t.Fatalf("expiry %v", ep.PasswordExpires)
	}
	e, err := c.Get(ctx, u.DN, UserExpiryAttributes...)
	if err != nil || UserFromEntry(e).PasswordExpires().IsZero() {
		t.Fatalf("msDS-UserPasswordExpiryTimeComputed not read: %v", err)
	}
	// A temporary PSO applied to a temporary user wins over the domain.
	tmp := newTempUser(t, c, labEnv(t, "AD_LAB_USER_PASSWORD"), false)
	ep, _ = c.EffectivePasswordPolicy(ctx, tmp.DN)
	if ep.PSODN != "" {
		t.Fatalf("temp user starts with a PSO: %+v", ep)
	}
	pol := PasswordPolicy{MinLength: 12, History: 5, Complexity: true, MaxAge: 30 * 24 * time.Hour, LockoutThreshold: 4,
		LockoutDuration: 15 * time.Minute, ObservationWindow: 15 * time.Minute}
	name := "p2-test-" + randSuffix()
	op, err = CreatePSO(c.PSOContainerDN(), name, 5, pol, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	psoDN := op.Preview().Changes[0].DN
	defer func() {
		if op, err := DeleteObject(psoDN); err == nil {
			_ = c.Apply(context.Background(), op)
		}
	}()
	pso, err := c.PSOByDN(ctx, psoDN)
	if err != nil || pso.Policy != pol {
		t.Fatalf("read back %+v %v", pso, err)
	}
	op, _ = ApplyPSO(pso, tmp.DN)
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	ep, _ = c.EffectivePasswordPolicy(ctx, tmp.DN)
	if ep.PSO == nil || !escape.EqualDN(ep.PSODN, psoDN) || ep.Policy.MinLength != 12 {
		t.Fatalf("effective after apply: %+v", ep)
	}
	pso, _ = c.PSOByDN(ctx, psoDN)
	np := pol
	np.MinLength = 14
	op, err = UpdatePSO(pso, 6, np)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	pso, _ = c.PSOByDN(ctx, psoDN)
	if pso.Precedence != 6 || pso.Policy.MinLength != 14 {
		t.Fatalf("update %+v", pso)
	}
	op, _ = UnapplyPSO(pso, tmp.DN)
	if err := c.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	if ep, _ = c.EffectivePasswordPolicy(ctx, tmp.DN); ep.PSODN != "" {
		t.Fatalf("still applied: %+v", ep)
	}
}

func TestLabDomainControllersAndPerDCState(t *testing.T) {
	ctx := labCtx(t)
	c := adminConn(t)
	dcs, err := c.DomainControllers(ctx)
	if err != nil || len(dcs) != 2 {
		t.Fatalf("DCs %+v %v", dcs, err)
	}
	// badPwdCount is per DC: read locked.user on each DC.
	cfg := labConfig(t)
	s, err := SignIn(ctx, cfg, labEnv(t, "AD_LAB_ADMIN_USER"), labEnv(t, "AD_LAB_ADMIN_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, dc := range dcs {
		one := cfg
		one.DCs = []string{dc.DNSHost}
		dconn, err := Connect(ctx, one, KerberosAuth(s))
		if err != nil {
			t.Fatalf("%s: %v", dc.DNSHost, err)
		}
		u, err := dconn.FindUser(ctx, "locked.user")
		_ = dconn.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: locked=%v lockoutTime=%v badPwdCount=%d", dc.DNSHost, u.Locked(), u.LockoutTime.Time(), u.BadPwdCount)
		if !u.Locked() {
			t.Errorf("%s: locked.user not locked", dc.DNSHost)
		}
	}
}
