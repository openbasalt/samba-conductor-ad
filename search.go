package ad

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-ad/escape"
)

// Scope of a search.
type Scope int

// Search scopes.
const (
	ScopeSubtree Scope = iota
	ScopeOneLevel
	ScopeBase
)

func (s Scope) ldap() int {
	switch s {
	case ScopeOneLevel:
		return ldap.ScopeSingleLevel
	case ScopeBase:
		return ldap.ScopeBaseObject
	default:
		return ldap.ScopeWholeSubtree
	}
}

// DefaultPageSize is used when SearchRequest.PageSize is 0. AD's default
// MaxPageSize is 1000; smaller pages keep memory flat.
const DefaultPageSize = 500

// SearchRequest is a typed search. The filter can only be built with the
// escape package.
type SearchRequest struct {
	// BaseDN defaults to the domain's defaultNamingContext.
	BaseDN     string
	Scope      Scope
	Filter     escape.Filter
	Attributes []string
	// PageSize for RFC 2696 paged results (always used).
	PageSize uint32
	// Limit stops after this many entries (0 = no limit). Enforced on the
	// client so it works across pages.
	Limit int
	// SortBy asks the DC to sort by this attribute (RFC 2891 server-side
	// sort control, non-critical: a DC that cannot sort returns the entries
	// unsorted). SortReverse sorts descending.
	SortBy      string
	SortReverse bool
}

// Search runs a paged search (RFC 2696) and streams entries page by page.
// Breaking out of the loop abandons the paged search on the server.
//
//	for e, err := range conn.Search(ctx, req) { ... }
func (c *Conn) Search(ctx context.Context, req SearchRequest) iter.Seq2[*ldap.Entry, error] {
	return func(yield func(*ldap.Entry, error) bool) {
		filter, err := escape.Compile(req.Filter)
		if err != nil {
			yield(nil, err)
			return
		}
		for _, a := range req.Attributes {
			if !escape.ValidAttribute(a) && a != "*" && a != "+" {
				yield(nil, fmt.Errorf("%w: %q", escape.ErrInvalidAttribute, a))
				return
			}
		}
		base := req.BaseDN
		if base == "" {
			base = c.baseDN
		}
		size := req.PageSize
		if size == 0 {
			size = DefaultPageSize
		}
		paging := ldap.NewControlPaging(size)
		controls := []ldap.Control{paging}
		if req.SortBy != "" {
			if !escape.ValidAttribute(req.SortBy) {
				yield(nil, fmt.Errorf("%w: %q", escape.ErrInvalidAttribute, req.SortBy))
				return
			}
			controls = append(controls, sortControl{attr: req.SortBy, reverse: req.SortReverse})
		}
		count := 0
		for {
			sr := ldap.NewSearchRequest(base, req.Scope.ldap(), ldap.NeverDerefAliases, 0, 0, false,
				filter, req.Attributes, controls)
			var res *ldap.SearchResult
			err := c.guard(ctx, func() error {
				var serr error
				res, serr = c.l.Search(sr)
				return serr
			})
			if err != nil {
				if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
					err = fmt.Errorf("%w: %s", ErrNotFound, base)
				}
				yield(nil, err)
				return
			}
			for _, e := range res.Entries {
				count++
				if !yield(e, nil) {
					c.abandonPaging(ctx, base, req.Scope, filter, paging)
					return
				}
				if req.Limit > 0 && count >= req.Limit {
					c.abandonPaging(ctx, base, req.Scope, filter, paging)
					return
				}
			}
			ctrl, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
			if !ok || len(ctrl.Cookie) == 0 {
				return
			}
			paging.SetCookie(ctrl.Cookie)
		}
	}
}

// abandonPaging tells the server to drop the paged result set (size 0 with
// the last cookie, RFC 2696 section 3).
func (c *Conn) abandonPaging(ctx context.Context, base string, scope Scope, filter string, paging *ldap.ControlPaging) {
	if len(paging.Cookie) == 0 {
		return
	}
	paging.PagingSize = 0
	sr := ldap.NewSearchRequest(base, scope.ldap(), ldap.NeverDerefAliases, 0, 0, false, filter, []string{"1.1"}, []ldap.Control{paging})
	_ = c.guard(ctx, func() error { _, err := c.l.Search(sr); return err })
}

// SearchAll collects a search into a slice (convenient for small results).
func (c *Conn) SearchAll(ctx context.Context, req SearchRequest) ([]*ldap.Entry, error) {
	var out []*ldap.Entry
	for e, err := range c.Search(ctx, req) {
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// Count returns how many entries match the search, reading no attributes
// (paged like every search).
func (c *Conn) Count(ctx context.Context, req SearchRequest) (int, error) {
	req.Attributes = []string{"1.1"}
	req.SortBy = ""
	n := 0
	for _, err := range c.Search(ctx, req) {
		if err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

// SearchWindow returns entries [skip, skip+n) of a search and whether more
// entries follow, for page-numbered lists in a UI. The DC still pages the
// result (RFC 2696); the skipped entries are read and dropped on the client,
// so use it with SortBy and a narrow attribute list.
func (c *Conn) SearchWindow(ctx context.Context, req SearchRequest, skip, n int) ([]*ldap.Entry, bool, error) {
	if skip < 0 || n <= 0 {
		return nil, false, errors.New("ad: invalid window")
	}
	req.Limit = skip + n + 1
	var out []*ldap.Entry
	i, more := 0, false
	for e, err := range c.Search(ctx, req) {
		if err != nil {
			return nil, false, err
		}
		switch {
		case i < skip:
		case i < skip+n:
			out = append(out, e)
		default:
			more = true
		}
		i++
	}
	return out, more, nil
}

// Get reads one object by DN (base search). ErrNotFound if it does not exist.
func (c *Conn) Get(ctx context.Context, dn string, attributes ...string) (*ldap.Entry, error) {
	if _, err := escape.ParseDN(dn); err != nil {
		return nil, err
	}
	entries, err := c.SearchAll(ctx, SearchRequest{BaseDN: dn, Scope: ScopeBase,
		Filter: escape.RawFilter("(objectClass=*)"), Attributes: attributes})
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, dn)
	}
	return entries[0], nil
}

// RangedValues reads every value of a multi-valued attribute of one object,
// following AD's ranged retrieval ("member;range=0-1499") when the server
// splits the values.
func (c *Conn) RangedValues(ctx context.Context, dn, attr string) ([]string, error) {
	if !escape.ValidAttribute(attr) || strings.Contains(attr, ";") {
		return nil, fmt.Errorf("%w: %q", escape.ErrInvalidAttribute, attr)
	}
	var out []string
	start := 0
	for range 10000 {
		req := fmt.Sprintf("%s;range=%d-*", attr, start)
		e, err := c.Get(ctx, dn, req)
		if err != nil {
			return nil, err
		}
		var got *ldap.EntryAttribute
		for _, a := range e.Attributes {
			name := strings.ToLower(a.Name)
			if name == strings.ToLower(attr) || strings.HasPrefix(name, strings.ToLower(attr)+";range=") {
				got = a
				break
			}
		}
		if got == nil {
			return out, nil
		}
		out = append(out, got.Values...)
		_, rng, ranged := strings.Cut(got.Name, ";range=")
		if !ranged {
			return out, nil
		}
		_, end, _ := strings.Cut(rng, "-")
		if end == "*" {
			return out, nil
		}
		n, err := strconv.Atoi(end)
		if err != nil || n < start {
			return nil, errors.New("ad: malformed range in " + got.Name)
		}
		start = n + 1
	}
	return nil, errors.New("ad: too many ranges")
}
