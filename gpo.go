package ad

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-ad/escape"
)

// Group Policy as stored in the directory (MS-GPOL 2.2): a GPO is a
// groupPolicyContainer under CN=Policies,CN=System (its settings live in
// SYSVOL), and a container (the domain, an OU, a site) links GPOs through
// its gPLink attribute and blocks inheritance through gPOptions. This file
// manages GPOs and their links over LDAP; creating and deleting a GPO also
// needs SYSVOL, which sambatool.GPOCreate/GPODelete do.

// GPO status flags (the "flags" attribute).
const (
	GPOFlagUserDisabled     = 1
	GPOFlagComputerDisabled = 2
)

// GPO is a groupPolicyContainer.
type GPO struct {
	DN          string
	ID          string // "{XXXXXXXX-…}" (the cn)
	DisplayName string
	Flags       int
	// Version is versionNumber: user settings version in the high 16 bits,
	// computer settings version in the low 16 bits.
	Version     uint32
	FileSysPath string
	WhenChanged string
}

// UserVersion and ComputerVersion split Version.
func (g GPO) UserVersion() uint32     { return g.Version >> 16 }
func (g GPO) ComputerVersion() uint32 { return g.Version & 0xffff }

// UserEnabled and ComputerEnabled read the status flags.
func (g GPO) UserEnabled() bool     { return g.Flags&GPOFlagUserDisabled == 0 }
func (g GPO) ComputerEnabled() bool { return g.Flags&GPOFlagComputerDisabled == 0 }

var gpoAttrs = []string{"cn", "displayName", "flags", "versionNumber", "gPCFileSysPath", "whenChanged"}

var gpoIDRE = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// ValidGPOID checks the "{GUID}" form of a GPO name.
func ValidGPOID(id string) bool { return gpoIDRE.MatchString(id) }

func gpoFromEntry(e *ldap.Entry) GPO {
	return GPO{DN: e.DN, ID: strings.ToUpper(e.GetAttributeValue("cn")), DisplayName: e.GetAttributeValue("displayName"),
		Flags: int(attrInt64(e, "flags")), Version: uint32(attrInt64(e, "versionNumber")),
		FileSysPath: e.GetAttributeValue("gPCFileSysPath"), WhenChanged: e.GetAttributeValue("whenChanged")}
}

// PoliciesDN returns CN=Policies,CN=System,<domain>.
func (c *Conn) PoliciesDN() string { return "CN=Policies,CN=System," + c.baseDN }

// GPOs lists the domain's GPOs sorted by display name.
func (c *Conn) GPOs(ctx context.Context) ([]GPO, error) {
	var out []GPO
	for e, err := range c.Search(ctx, SearchRequest{BaseDN: c.PoliciesDN(), Scope: ScopeOneLevel,
		Filter: escape.Eq("objectClass", "groupPolicyContainer"), Attributes: gpoAttrs}) {
		if err != nil {
			return nil, err
		}
		out = append(out, gpoFromEntry(e))
	}
	slices.SortFunc(out, func(a, b GPO) int {
		return strings.Compare(strings.ToLower(a.DisplayName), strings.ToLower(b.DisplayName))
	})
	return out, nil
}

// GPOByID reads one GPO by its "{GUID}".
func (c *Conn) GPOByID(ctx context.Context, id string) (GPO, error) {
	if !ValidGPOID(id) {
		return GPO{}, fmt.Errorf("%w: GPO %q", ErrNotFound, id)
	}
	for e, err := range c.Search(ctx, SearchRequest{BaseDN: c.PoliciesDN(), Scope: ScopeOneLevel,
		Filter: escape.And(escape.Eq("objectClass", "groupPolicyContainer"), escape.Eq("cn", id)), Attributes: gpoAttrs}) {
		if err != nil {
			return GPO{}, err
		}
		return gpoFromEntry(e), nil
	}
	return GPO{}, fmt.Errorf("%w: GPO %s", ErrNotFound, id)
}

// GPLink options (per link in gPLink).
const (
	GPLinkDisabled = 1
	GPLinkEnforced = 2
)

// GPLink is one link of a container's gPLink.
type GPLink struct {
	GPODN   string // as written in the link (cn={GUID},cn=policies,cn=system,DC=…)
	Options int
}

// GPOID returns the "{GUID}" of the linked GPO, or "" when the DN does not
// have the expected shape.
func (l GPLink) GPOID() string {
	parsed, err := escape.ParseDN(l.GPODN)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) != 1 {
		return ""
	}
	id := strings.ToUpper(parsed.RDNs[0].Attributes[0].Value)
	if !ValidGPOID(id) {
		return ""
	}
	return id
}

// Enabled and Enforced read the link options.
func (l GPLink) Enabled() bool  { return l.Options&GPLinkDisabled == 0 }
func (l GPLink) Enforced() bool { return l.Options&GPLinkEnforced != 0 }

// ParseGPLink splits a gPLink value: "[LDAP://<dn>;<options>]…". The list is
// returned in stored order; the LAST entry has the highest precedence
// (link order 1), the way GPMC numbers links.
func ParseGPLink(v string) ([]GPLink, error) {
	v = strings.TrimSpace(v)
	var out []GPLink
	for v != "" {
		if !strings.HasPrefix(v, "[") {
			return nil, fmt.Errorf("%w: malformed gPLink", ErrInvalid)
		}
		end := strings.IndexByte(v, ']')
		if end < 0 {
			return nil, fmt.Errorf("%w: malformed gPLink", ErrInvalid)
		}
		entry := v[1:end]
		v = strings.TrimSpace(v[end+1:])
		semi := strings.LastIndexByte(entry, ';')
		if semi < 0 || len(entry) < 7 || !strings.EqualFold(entry[:7], "LDAP://") {
			return nil, fmt.Errorf("%w: malformed gPLink entry", ErrInvalid)
		}
		opts, err := strconv.Atoi(entry[semi+1:])
		if err != nil || opts < 0 || opts > 3 {
			return nil, fmt.Errorf("%w: gPLink options %q", ErrInvalid, entry[semi+1:])
		}
		out = append(out, GPLink{GPODN: entry[7:semi], Options: opts})
	}
	return out, nil
}

// FormatGPLink renders links back to the gPLink syntax.
func FormatGPLink(links []GPLink) string {
	var sb strings.Builder
	for _, l := range links {
		fmt.Fprintf(&sb, "[LDAP://%s;%d]", l.GPODN, l.Options)
	}
	return sb.String()
}

// LinkOrder converts a stored index to GPMC's link order (1 = highest
// precedence = last stored).
func LinkOrder(index, count int) int { return count - index }

// GPContainer is a domain, OU or site with its GPO links.
type GPContainer struct {
	DN     string
	Name   string
	Kind   string // "domain", "ou", "site"
	GUID   string
	GPLink string // raw value as read (the precondition of every change)
	Links  []GPLink
	// BlockInheritance is gPOptions bit 1.
	BlockInheritance bool
	GPOptions        string // raw value as read
}

func containerFromEntry(e *ldap.Entry, base string) GPContainer {
	c := GPContainer{DN: e.DN, GPLink: e.GetAttributeValue("gPLink"), GPOptions: e.GetAttributeValue("gPOptions")}
	c.Links, _ = ParseGPLink(c.GPLink)
	c.BlockInheritance = attrInt64(e, "gPOptions")&1 != 0
	c.GUID = attrGUID(e).String()
	classes := e.GetAttributeValues("objectClass")
	switch {
	case escape.EqualDN(e.DN, base):
		c.Kind, c.Name = "domain", dnsNameOfDN(base)
	case slices.ContainsFunc(classes, func(s string) bool { return strings.EqualFold(s, "site") }):
		c.Kind, c.Name = "site", e.GetAttributeValue("cn")
	default:
		c.Kind, c.Name = "ou", e.GetAttributeValue("ou")
	}
	return c
}

var gpContainerAttrs = []string{"objectClass", "objectGUID", "ou", "cn", "gPLink", "gPOptions"}

// GPContainers returns every container that links at least one GPO or
// blocks inheritance: the domain, OUs and (read-only here) sites.
func (c *Conn) GPContainers(ctx context.Context) ([]GPContainer, error) {
	var out []GPContainer
	f := escape.Or(escape.Present("gPLink"), escape.Present("gPOptions"))
	for _, base := range []string{c.baseDN, "CN=Sites," + c.configDN} {
		for e, err := range c.Search(ctx, SearchRequest{BaseDN: base, Filter: f, Attributes: gpContainerAttrs}) {
			if err != nil {
				if base != c.baseDN {
					break // sites are optional here
				}
				return nil, err
			}
			gc := containerFromEntry(e, c.baseDN)
			if gc.GPLink == "" && !gc.BlockInheritance {
				continue
			}
			out = append(out, gc)
		}
	}
	return out, nil
}

// GPContainerByDN reads one container (domain or OU) with its links.
func (c *Conn) GPContainerByDN(ctx context.Context, dn string) (GPContainer, error) {
	e, err := c.Get(ctx, dn, gpContainerAttrs...)
	if err != nil {
		return GPContainer{}, err
	}
	return containerFromEntry(e, c.baseDN), nil
}

// LinksTo returns, for a GPO, the containers linking it.
func LinksTo(containers []GPContainer, id string) []GPContainer {
	var out []GPContainer
	for _, gc := range containers {
		for _, l := range gc.Links {
			if strings.EqualFold(l.GPOID(), id) {
				out = append(out, gc)
				break
			}
		}
	}
	return out
}

// GPLinkAction is a change to one container's links.
type GPLinkAction string

// Link actions.
const (
	GPLinkAdd      GPLinkAction = "link"
	GPLinkRemove   GPLinkAction = "unlink"
	GPLinkEnable   GPLinkAction = "enable"
	GPLinkDisable  GPLinkAction = "disable"
	GPLinkEnforce  GPLinkAction = "enforce"
	GPLinkUnforce  GPLinkAction = "unenforce"
	GPLinkMoveUp   GPLinkAction = "up"   // towards link order 1 (more precedence)
	GPLinkMoveDown GPLinkAction = "down" // away from link order 1
)

// ChangeGPLink builds the replace of a container's gPLink for one action on
// the link of gpo. The current raw value is asserted (and re-read before
// the write), so a concurrent change fails with ErrConflict instead of
// being overwritten. A new link gets the lowest precedence, like GPMC.
func ChangeGPLink(gc GPContainer, gpo GPO, action GPLinkAction) (*Operation, error) {
	if gc.Kind == "site" {
		return nil, fmt.Errorf("%w: site links are managed with the AD sites tools", ErrInvalid)
	}
	if err := checkDN(gc.DN); err != nil {
		return nil, err
	}
	if !ValidGPOID(gpo.ID) || gpo.DN == "" {
		return nil, fmt.Errorf("%w: GPO", ErrInvalid)
	}
	links := slices.Clone(gc.Links)
	idx := slices.IndexFunc(links, func(l GPLink) bool { return strings.EqualFold(l.GPOID(), gpo.ID) })
	if action != GPLinkAdd && idx < 0 {
		return nil, fmt.Errorf("%w: %s is not linked to %s", ErrNotFound, gpo.DisplayName, gc.Name)
	}
	var verb string
	switch action {
	case GPLinkAdd:
		if idx >= 0 {
			return nil, fmt.Errorf("%w: %s is already linked to %s", ErrAlreadyExists, gpo.DisplayName, gc.Name)
		}
		links = append([]GPLink{{GPODN: gpo.DN, Options: 0}}, links...)
		verb = "link"
	case GPLinkRemove:
		links = slices.Delete(links, idx, idx+1)
		verb = "unlink"
	case GPLinkEnable, GPLinkDisable, GPLinkEnforce, GPLinkUnforce:
		o := links[idx].Options
		switch action {
		case GPLinkEnable:
			o &^= GPLinkDisabled
		case GPLinkDisable:
			o |= GPLinkDisabled
		case GPLinkEnforce:
			o |= GPLinkEnforced
		case GPLinkUnforce:
			o &^= GPLinkEnforced
		}
		if o == links[idx].Options {
			return nil, ErrNoChange
		}
		links[idx].Options = o
		verb = string(action) + " the link of"
	case GPLinkMoveUp, GPLinkMoveDown:
		// Up = more precedence = later in the stored list.
		j := idx + 1
		if action == GPLinkMoveDown {
			j = idx - 1
		}
		if j < 0 || j >= len(links) {
			return nil, ErrNoChange
		}
		links[idx], links[j] = links[j], links[idx]
		verb = "move " + string(action) + " the link of"
	default:
		return nil, fmt.Errorf("%w: link action %q", ErrInvalid, action)
	}
	newValue := FormatGPLink(links)
	var assert escape.Filter
	if gc.GPLink == "" {
		assert = escape.Not(escape.Present("gPLink"))
	} else {
		assert = escape.Eq("gPLink", gc.GPLink)
	}
	attr := AttrChange{Op: ModReplace, Name: "gPLink"}
	if newValue != "" {
		attr.Values = []string{newValue}
	}
	notes := []string{fmt.Sprintf("%s %s (%s) %s %s", verb, gpo.DisplayName, gpo.ID, map[bool]string{true: "to", false: "on"}[action == GPLinkAdd], gc.Name)}
	for i, l := range links {
		state := []string{}
		if !l.Enabled() {
			state = append(state, "link disabled")
		}
		if l.Enforced() {
			state = append(state, "enforced")
		}
		notes = append(notes, fmt.Sprintf("link order %d: %s %s", LinkOrder(i, len(links)), l.GPOID(), strings.Join(state, ", ")))
	}
	return &Operation{preview: Preview{Summary: notes[0], Changes: []Change{{Type: ChangeModify, DN: gc.DN,
		Assert: assert, Notes: notes, Attrs: []AttrChange{attr}}}}}, nil
}

// SetBlockInheritance sets or clears gPOptions bit 1 on an OU (or the
// domain), asserting the value as read.
func SetBlockInheritance(gc GPContainer, block bool) (*Operation, error) {
	if gc.Kind == "site" {
		return nil, fmt.Errorf("%w: sites have no inheritance", ErrInvalid)
	}
	if err := checkDN(gc.DN); err != nil {
		return nil, err
	}
	if gc.BlockInheritance == block {
		return nil, ErrNoChange
	}
	cur, _ := strconv.ParseInt(gc.GPOptions, 10, 32)
	next := cur &^ 1
	verb := "allow inheritance on " + gc.Name
	if block {
		next = cur | 1
		verb = "block inheritance on " + gc.Name
	}
	var assert escape.Filter
	if gc.GPOptions == "" {
		assert = escape.Not(escape.Present("gPOptions"))
	} else {
		assert = escape.Eq("gPOptions", gc.GPOptions)
	}
	return &Operation{preview: Preview{Summary: verb, Changes: []Change{{Type: ChangeModify, DN: gc.DN, Assert: assert,
		Notes: []string{verb}, Attrs: []AttrChange{{Op: ModReplace, Name: "gPOptions", Values: []string{strconv.FormatInt(next, 10)}}}}}}}, nil
}
