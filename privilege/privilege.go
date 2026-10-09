// Package privilege tells whether a directory object holds privileged
// rights in the domain. Privileged means any of:
//
//   - membership, direct or nested (primary group included), of a
//     well-known administrative group (Domain Admins, Enterprise Admins,
//     Schema Admins, Group Policy Creator Owners, Domain Controllers,
//     Read-only Domain Controllers, Administrators, Account, Server,
//     Print and Backup Operators) or of a caller-supplied group;
//   - adminCount set to 1;
//   - an allow entry granting more than read, or ownership, on the domain
//     head, an organizational unit, AdminSDHolder or a Group Policy
//     object, held by the object or one of its groups.
//
// Samba does not run SDProp, so AdminSDHolder does not protect these
// objects there. Callers that write on behalf of others (a provisioning
// service, a sync engine, a password reset flow) build an Index and refuse
// to act on any object it reports.
//
// Every read uses the caller's connection; an account that can only read
// the directory is enough. A read that fails makes Build fail: the index
// is never built from partial data.
package privilege

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sd"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

// Reason kinds.
const (
	// KindGroup: member of a privileged group; Detail is the group's SID.
	KindGroup = "group"
	// KindAdminCount: adminCount is 1; Detail is the object's DN.
	KindAdminCount = "adminCount"
	// KindACL: an allow entry granting more than read on a protected
	// object; Detail is "<object DN>: <SDDL of the entry>".
	KindACL = "acl"
	// KindOwner: owner of a protected object; Detail is the object's DN.
	KindOwner = "owner"
)

// Reason says why a SID is privileged.
type Reason struct {
	Kind   string
	Detail string
}

// Options tune Build.
type Options struct {
	// ExtraGroupSIDs are further groups whose members are privileged, such
	// as an application's administrator, helpdesk and auditor role groups.
	ExtraGroupSIDs []sid.SID
}

// Index is the set of privileged SIDs with their reasons, built at one
// point in time. It is safe for concurrent reads.
type Index struct {
	builtAt  time.Time
	reasons  map[string][]Reason
	trustees map[string]sid.SID
}

// Well-known domain groups (RIDs on the domain SID).
var privilegedRIDs = []uint32{
	sid.RIDDomainAdmins,
	sid.RIDEnterpriseAdmins,
	sid.RIDSchemaAdmins,
	sid.RIDGroupPolicyCreatorOwners,
	sid.RIDDomainControllers,
	sid.RIDReadOnlyDomainControllers,
}

// Well-known BUILTIN groups.
var privilegedBuiltin = []sid.SID{
	sid.BuiltinAdministrators,
	sid.BuiltinAccountOperators,
	sid.BuiltinServerOperators,
	sid.BuiltinPrintOperators,
	sid.BuiltinBackupOperators,
}

// Trustees that are not privileged by holding rights on a protected
// object: every object grants SELF and CREATOR OWNER rights on itself,
// SYSTEM and ENTERPRISE DOMAIN CONTROLLERS are the DCs, and Pre-Windows
// 2000 Compatible Access and Anonymous only appear for compatibility reads.
var alwaysNormal = []sid.SID{
	sid.MustParse("S-1-5-10"),     // SELF (PRINCIPAL_SELF)
	sid.MustParse("S-1-3-0"),      // CREATOR OWNER
	sid.MustParse("S-1-5-18"),     // SYSTEM
	sid.MustParse("S-1-5-9"),      // ENTERPRISE DOMAIN CONTROLLERS
	sid.MustParse("S-1-5-32-554"), // Pre-Windows 2000 Compatible Access
	sid.MustParse("S-1-5-7"),      // ANONYMOUS LOGON
}

// Trustees that are normal only in object entries restricted to one
// object type (a property, an extended right or a validated write, such as
// the change-password right every user has). An unrestricted write for
// them is a misconfiguration and is reported.
var normalWhenRestricted = []sid.SID{sid.Everyone, sid.AuthenticatedUsers}

// Build reads the directory through conn and returns the index.
func Build(ctx context.Context, conn *ad.Conn, opt Options) (*Index, error) {
	return build(ctx, connDir{c: conn}, opt, time.Now())
}

// Privileged reports why the object at dn is privileged, or nil when it is
// not. It re-reads the object's own objectSid, adminCount and tokenGroups
// (computed by the DC: nested and primary groups) through conn, so a
// change of membership since the index was built is seen at once.
func (x *Index) Privileged(ctx context.Context, conn *ad.Conn, dn string) ([]Reason, error) {
	return x.privileged(ctx, connDir{c: conn}, dn)
}

// PrivilegedSID returns the reasons recorded for s in the index (no
// directory lookup), or nil.
func (x *Index) PrivilegedSID(s sid.SID) []Reason {
	return slices.Clone(x.reasons[s.String()])
}

// TrusteeSIDs returns the SIDs privileged directly by an entry or by
// ownership on a protected object (not the members of those groups),
// sorted by their string form.
func (x *Index) TrusteeSIDs() []sid.SID {
	keys := make([]string, 0, len(x.trustees))
	for k := range x.trustees {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]sid.SID, 0, len(keys))
	for _, k := range keys {
		out = append(out, x.trustees[k])
	}
	return out
}

// BuiltAt returns when Build started reading the directory.
func (x *Index) BuiltAt() time.Time { return x.builtAt }

// Len returns how many SIDs the index holds.
func (x *Index) Len() int { return len(x.reasons) }

func (x *Index) add(s sid.SID, r Reason) {
	if s.IsZero() {
		return
	}
	k := s.String()
	if slices.Contains(x.reasons[k], r) {
		return
	}
	x.reasons[k] = append(x.reasons[k], r)
}

func (x *Index) privileged(ctx context.Context, dir directory, dn string) ([]Reason, error) {
	o, err := dir.object(ctx, dn)
	if err != nil {
		return nil, err
	}
	groups, err := dir.tokenGroups(ctx, dn)
	if err != nil {
		return nil, err
	}
	var out []Reason
	push := func(rs ...Reason) {
		for _, r := range rs {
			if !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	if o.AdminCount {
		push(Reason{Kind: KindAdminCount, Detail: o.DN})
	}
	if !o.SID.IsZero() {
		push(x.reasons[o.SID.String()]...)
	}
	for _, g := range groups {
		push(x.reasons[g.String()]...)
	}
	return out, nil
}

// builder carries the state of one Build.
type builder struct {
	dir       directory
	domain    sid.SID
	idx       *Index
	expanded  map[string][]object
	resolved  map[string]bool
	protected []securedObject
}

func build(ctx context.Context, dir directory, opt Options, now time.Time) (*Index, error) {
	domain, err := dir.domainSID(ctx)
	if err != nil {
		return nil, fmt.Errorf("privilege: domain SID: %w", err)
	}
	b := &builder{
		dir:      dir,
		domain:   domain,
		idx:      &Index{builtAt: now, reasons: map[string][]Reason{}, trustees: map[string]sid.SID{}},
		expanded: map[string][]object{},
		resolved: map[string]bool{},
	}
	groups := slices.Clone(privilegedBuiltin)
	for _, rid := range privilegedRIDs {
		g, err := domain.WithRID(rid)
		if err != nil {
			return nil, fmt.Errorf("privilege: %w", err)
		}
		groups = append(groups, g)
	}
	groups = append(groups, opt.ExtraGroupSIDs...)
	for _, g := range groups {
		if err := b.groupMembers(ctx, g, Reason{Kind: KindGroup, Detail: g.String()}); err != nil {
			return nil, err
		}
	}
	marked, err := dir.adminCountObjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("privilege: adminCount: %w", err)
	}
	for _, o := range marked {
		b.idx.add(o.SID, Reason{Kind: KindAdminCount, Detail: o.DN})
	}
	if err := b.descriptors(ctx); err != nil {
		return nil, err
	}
	return b.idx, nil
}

// groupMembers adds g itself and every direct, nested and primary-group
// member of g with reason r. A SID that names no object (a group that
// does not exist in this domain, a well-known SID) adds only itself.
func (b *builder) groupMembers(ctx context.Context, g sid.SID, r Reason) error {
	b.idx.add(g, r)
	members, err := b.expand(ctx, g)
	if err != nil {
		return err
	}
	for _, m := range members {
		b.idx.add(m.SID, r)
	}
	return nil
}

// expand returns the members of the group with SID g (memoized), or nil
// when g is not a group of the directory.
func (b *builder) expand(ctx context.Context, g sid.SID) ([]object, error) {
	key := g.String()
	if b.resolved[key] {
		return b.expanded[key], nil
	}
	b.resolved[key] = true
	dn, err := b.dir.findBySID(ctx, g)
	if errors.Is(err, ad.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("privilege: find %s: %w", g, err)
	}
	o, err := b.dir.object(ctx, dn)
	if err != nil {
		return nil, fmt.Errorf("privilege: read %s: %w", dn, err)
	}
	if !o.Group {
		return nil, nil
	}
	// Walk the member values instead of one LDAP_MATCHING_RULE_IN_CHAIN
	// search: Samba evaluates that rule by scanning every object (seconds
	// per group on a domain of a few thousand users), while reading the
	// groups themselves costs one lookup per member.
	members, err := b.walkMembers(ctx, dn)
	if err != nil {
		return nil, fmt.Errorf("privilege: members of %s: %w", dn, err)
	}
	// Primary group membership is not in member/memberOf: add the objects
	// whose primaryGroupID is the group or one of its nested groups.
	var rids []uint32
	for _, s := range append([]sid.SID{g}, groupSIDs(members)...) {
		if d, ok := s.Domain(); ok && d.Equal(b.domain) {
			rid, _ := s.RID()
			rids = append(rids, rid)
		}
	}
	if len(rids) > 0 {
		primary, err := b.dir.primaryGroupMembers(ctx, rids)
		if err != nil {
			return nil, fmt.Errorf("privilege: primary group members of %s: %w", dn, err)
		}
		members = append(members, primary...)
	}
	b.expanded[key] = members
	return members, nil
}

func groupSIDs(objs []object) []sid.SID {
	var out []sid.SID
	for _, o := range objs {
		if o.Group && !o.SID.IsZero() {
			out = append(out, o.SID)
		}
	}
	return out
}

// walkMembers follows member values breadth-first and returns every direct
// and nested member of the group.
func (b *builder) walkMembers(ctx context.Context, groupDN string) ([]object, error) {
	var out []object
	seen := map[string]bool{escape.NormalizeDN(groupDN): true}
	queue := []string{groupDN}
	for len(queue) > 0 {
		dn := queue[0]
		queue = queue[1:]
		values, err := b.dir.directMembers(ctx, dn)
		if err != nil {
			return nil, err
		}
		for _, m := range values {
			k := escape.NormalizeDN(m)
			if seen[k] {
				continue
			}
			seen[k] = true
			o, err := b.dir.object(ctx, m)
			if errors.Is(err, ad.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, o)
			if o.Group {
				queue = append(queue, m)
			}
		}
	}
	return out, nil
}

// descriptors reads the owner and DACL of the domain head, every OU,
// AdminSDHolder and every Group Policy object and indexes the trustees
// that hold more than read and the owners.
func (b *builder) descriptors(ctx context.Context) error {
	base := b.dir.baseDN()
	for _, dn := range []string{base, "CN=AdminSDHolder,CN=System," + base} {
		d, err := b.dir.descriptor(ctx, dn)
		if errors.Is(err, ad.ErrNotFound) && dn != base {
			continue
		}
		if err != nil {
			return fmt.Errorf("privilege: security descriptor of %s: %w", dn, err)
		}
		b.protected = append(b.protected, securedObject{DN: dn, SD: d})
	}
	for _, q := range []struct{ base, class string }{
		{base, "organizationalUnit"},
		{"CN=Policies,CN=System," + base, "groupPolicyContainer"},
	} {
		objs, err := b.dir.descriptorsByClass(ctx, q.base, q.class)
		if errors.Is(err, ad.ErrNotFound) && q.base != base {
			continue
		}
		if err != nil {
			return fmt.Errorf("privilege: security descriptors of %s objects: %w", q.class, err)
		}
		b.protected = append(b.protected, objs...)
	}
	for _, p := range b.protected {
		if err := b.secured(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) secured(ctx context.Context, p securedObject) error {
	if p.SD == nil {
		return fmt.Errorf("privilege: %s: no security descriptor", p.DN)
	}
	if o := p.SD.Owner; !o.IsZero() && !sid.Contains(alwaysNormal, o) {
		if err := b.trustee(ctx, o, Reason{Kind: KindOwner, Detail: p.DN}); err != nil {
			return err
		}
	}
	if p.SD.NullDACL() {
		return b.trustee(ctx, sid.Everyone, Reason{Kind: KindACL, Detail: p.DN + ": D:NO_ACCESS_CONTROL"})
	}
	if p.SD.DACL == nil {
		return nil
	}
	for i := range p.SD.DACL.ACEs {
		a := &p.SD.DACL.ACEs[i]
		if !a.GrantsMoreThanRead() || normalTrustee(a) {
			continue
		}
		if err := b.trustee(ctx, a.Trustee, Reason{Kind: KindACL, Detail: p.DN + ": " + a.SDDL()}); err != nil {
			return err
		}
	}
	return nil
}

// trustee indexes a trustee and, when it is a group, its members.
func (b *builder) trustee(ctx context.Context, s sid.SID, r Reason) error {
	b.idx.trustees[s.String()] = s
	return b.groupMembers(ctx, s, r)
}

// normalTrustee reports whether an allow entry's trustee is exempt.
func normalTrustee(a *sd.ACE) bool {
	if sid.Contains(alwaysNormal, a.Trustee) {
		return true
	}
	return sid.Contains(normalWhenRestricted, a.Trustee) && a.IsObject() && a.ObjectType != ""
}
