package ad

import (
	"context"
	"fmt"
	"iter"

	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

var (
	userClass     = escape.And(escape.Eq("objectCategory", "person"), escape.Eq("objectClass", "user"))
	groupClass    = escape.Eq("objectClass", "group")
	ouClass       = escape.Eq("objectClass", "organizationalUnit")
	computerClass = escape.Eq("objectClass", "computer")
)

func withClass(class, extra escape.Filter) escape.Filter {
	if extra == nil {
		return class
	}
	return escape.And(class, extra)
}

// Users streams user accounts below base (domain root when empty), optionally
// narrowed by an extra filter.
func (c *Conn) Users(ctx context.Context, base string, extra escape.Filter) iter.Seq2[User, error] {
	return func(yield func(User, error) bool) {
		for e, err := range c.Search(ctx, SearchRequest{BaseDN: base, Filter: withClass(userClass, extra), Attributes: UserAttributes}) {
			if err != nil {
				yield(User{}, err)
				return
			}
			if !yield(UserFromEntry(e), nil) {
				return
			}
		}
	}
}

// Groups streams groups below base.
func (c *Conn) Groups(ctx context.Context, base string, extra escape.Filter) iter.Seq2[Group, error] {
	return func(yield func(Group, error) bool) {
		for e, err := range c.Search(ctx, SearchRequest{BaseDN: base, Filter: withClass(groupClass, extra), Attributes: GroupAttributes}) {
			if err != nil {
				yield(Group{}, err)
				return
			}
			if !yield(GroupFromEntry(e), nil) {
				return
			}
		}
	}
}

// OUs streams organizational units below base.
func (c *Conn) OUs(ctx context.Context, base string, extra escape.Filter) iter.Seq2[OU, error] {
	return func(yield func(OU, error) bool) {
		for e, err := range c.Search(ctx, SearchRequest{BaseDN: base, Filter: withClass(ouClass, extra), Attributes: OUAttributes}) {
			if err != nil {
				yield(OU{}, err)
				return
			}
			if !yield(OUFromEntry(e), nil) {
				return
			}
		}
	}
}

// Computers streams computer accounts below base.
func (c *Conn) Computers(ctx context.Context, base string, extra escape.Filter) iter.Seq2[Computer, error] {
	return func(yield func(Computer, error) bool) {
		for e, err := range c.Search(ctx, SearchRequest{BaseDN: base, Filter: withClass(computerClass, extra), Attributes: ComputerAttributes}) {
			if err != nil {
				yield(Computer{}, err)
				return
			}
			if !yield(ComputerFromEntry(e), nil) {
				return
			}
		}
	}
}

// FindUser looks a user up by sAMAccountName.
func (c *Conn) FindUser(ctx context.Context, samAccountName string) (User, error) {
	for u, err := range c.Users(ctx, "", escape.Eq("sAMAccountName", samAccountName)) {
		return u, err
	}
	return User{}, fmt.Errorf("%w: user %q", ErrNotFound, samAccountName)
}

// GetUser reads a user by DN.
func (c *Conn) GetUser(ctx context.Context, dn string) (User, error) {
	e, err := c.Get(ctx, dn, UserAttributes...)
	if err != nil {
		return User{}, err
	}
	return UserFromEntry(e), nil
}

// FindGroup looks a group up by sAMAccountName.
func (c *Conn) FindGroup(ctx context.Context, samAccountName string) (Group, error) {
	for g, err := range c.Groups(ctx, "", escape.Eq("sAMAccountName", samAccountName)) {
		return g, err
	}
	return Group{}, fmt.Errorf("%w: group %q", ErrNotFound, samAccountName)
}

// FindBySID looks any object up by SID and returns its DN.
func (c *Conn) FindBySID(ctx context.Context, s sid.SID) (string, error) {
	entries, err := c.SearchAll(ctx, SearchRequest{Filter: escape.EqBytes("objectSid", s.Bytes()), Attributes: []string{"1.1"}, Limit: 1})
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("%w: SID %s", ErrNotFound, s)
	}
	return entries[0].DN, nil
}

// DomainSID returns the domain's SID (objectSid of the naming context).
func (c *Conn) DomainSID(ctx context.Context) (sid.SID, error) {
	e, err := c.Get(ctx, c.baseDN, "objectSid")
	if err != nil {
		return sid.SID{}, err
	}
	return sid.FromBytes(e.GetRawAttributeValue("objectSid"))
}

// WellKnownGroupSID returns the SID of a domain group by RID (e.g.
// sid.RIDDomainAdmins).
func (c *Conn) WellKnownGroupSID(ctx context.Context, rid uint32) (sid.SID, error) {
	d, err := c.DomainSID(ctx)
	if err != nil {
		return sid.SID{}, err
	}
	return d.WithRID(rid)
}

// TokenGroups returns the SIDs of every group the object is a member of,
// transitively, including its primary group (computed by the DC).
func (c *Conn) TokenGroups(ctx context.Context, dn string) ([]sid.SID, error) {
	e, err := c.Get(ctx, dn, "tokenGroups")
	if err != nil {
		return nil, err
	}
	raw := e.GetRawAttributeValues("tokenGroups")
	out := make([]sid.SID, 0, len(raw))
	for _, b := range raw {
		s, err := sid.FromBytes(b)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// IsMemberOfSID reports whether the object behind dn is a direct or nested
// member of the group with SID group. This is the check to use for
// authorization (admin = member of Domain Admins, RID 512): it compares SIDs
// computed by the DC, never names or DN substrings.
func (c *Conn) IsMemberOfSID(ctx context.Context, dn string, group sid.SID) (bool, error) {
	groups, err := c.TokenGroups(ctx, dn)
	if err != nil {
		return false, err
	}
	return sid.Contains(groups, group), nil
}

// GroupMembers returns the DNs of the direct members of a group, following
// ranged retrieval for large groups.
func (c *Conn) GroupMembers(ctx context.Context, groupDN string) ([]string, error) {
	return c.RangedValues(ctx, groupDN, "member")
}
