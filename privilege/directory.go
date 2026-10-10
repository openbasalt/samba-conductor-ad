package privilege

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sd"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

// object is what the index needs to know about a directory object.
type object struct {
	DN         string
	SID        sid.SID // zero when the object has no objectSid
	Group      bool
	AdminCount bool
}

// securedObject is a protected object with its owner and DACL.
type securedObject struct {
	DN string
	SD *sd.Descriptor
}

// directory is the small set of reads the index is built from. connDir
// implements it over an *ad.Conn; tests use an in-memory fake.
type directory interface {
	baseDN() string
	domainSID(ctx context.Context) (sid.SID, error)
	// findBySID returns the DN of the object with that SID (ad.ErrNotFound
	// when there is none).
	findBySID(ctx context.Context, s sid.SID) (string, error)
	// object reads one object by DN (ad.ErrNotFound when it does not exist).
	object(ctx context.Context, dn string) (object, error)
	// directMembers returns the DNs in the group's member attribute.
	directMembers(ctx context.Context, groupDN string) ([]string, error)
	// primaryGroupMembers returns the objects whose primaryGroupID is one
	// of rids.
	primaryGroupMembers(ctx context.Context, rids []uint32) ([]object, error)
	// adminCountObjects returns every object with adminCount=1.
	adminCountObjects(ctx context.Context) ([]object, error)
	// descriptor reads the owner and DACL of one object.
	descriptor(ctx context.Context, dn string) (*sd.Descriptor, error)
	// descriptorsByClass reads the owner and DACL of every object of the
	// class below base.
	descriptorsByClass(ctx context.Context, base, class string) ([]securedObject, error)
	// tokenGroups returns the SIDs of every group the object belongs to,
	// transitively, as computed by the DC.
	tokenGroups(ctx context.Context, dn string) ([]sid.SID, error)
}

// connDir reads through an *ad.Conn.
type connDir struct {
	c *ad.Conn
}

var objectAttributes = []string{"objectSid", "objectClass", "adminCount"}

const sdFlags = sd.FlagOwner | sd.FlagDACL

func objectFromEntry(e *ldap.Entry) object {
	o := object{DN: e.DN, AdminCount: e.GetAttributeValue("adminCount") == "1"}
	if raw := e.GetRawAttributeValue("objectSid"); len(raw) > 0 {
		if s, err := sid.FromBytes(raw); err == nil {
			o.SID = s
		}
	}
	o.Group = slices.ContainsFunc(e.GetAttributeValues("objectClass"), func(c string) bool {
		return strings.EqualFold(c, "group")
	})
	return o
}

func (d connDir) baseDN() string { return d.c.BaseDN() }

func (d connDir) domainSID(ctx context.Context) (sid.SID, error) { return d.c.DomainSID(ctx) }

func (d connDir) findBySID(ctx context.Context, s sid.SID) (string, error) {
	return d.c.FindBySID(ctx, s)
}

func (d connDir) object(ctx context.Context, dn string) (object, error) {
	e, err := d.c.Get(ctx, dn, objectAttributes...)
	if err != nil {
		return object{}, err
	}
	return objectFromEntry(e), nil
}

func (d connDir) objects(ctx context.Context, req ad.SearchRequest) ([]object, error) {
	req.Attributes = objectAttributes
	var out []object
	for e, err := range d.c.Search(ctx, req) {
		if err != nil {
			return nil, err
		}
		out = append(out, objectFromEntry(e))
	}
	return out, nil
}

func (d connDir) directMembers(ctx context.Context, groupDN string) ([]string, error) {
	return d.c.GroupMembers(ctx, groupDN)
}

func (d connDir) primaryGroupMembers(ctx context.Context, rids []uint32) ([]object, error) {
	parts := make([]escape.Filter, 0, len(rids))
	for _, r := range rids {
		parts = append(parts, escape.Eq("primaryGroupID", strconv.FormatUint(uint64(r), 10)))
	}
	return d.objects(ctx, ad.SearchRequest{Filter: escape.Or(parts...)})
}

func (d connDir) adminCountObjects(ctx context.Context) ([]object, error) {
	return d.objects(ctx, ad.SearchRequest{Filter: escape.Eq("adminCount", "1")})
}

func (d connDir) descriptor(ctx context.Context, dn string) (*sd.Descriptor, error) {
	return d.c.SecurityDescriptor(ctx, dn, sdFlags)
}

func (d connDir) descriptorsByClass(ctx context.Context, base, class string) ([]securedObject, error) {
	var out []securedObject
	for e, err := range d.c.Search(ctx, ad.SearchRequest{BaseDN: base, Filter: escape.Eq("objectClass", class),
		Attributes: []string{"nTSecurityDescriptor"}, SecurityDescriptorFlags: sdFlags}) {
		if err != nil {
			return nil, err
		}
		s, err := ad.ParseSecurityDescriptor(e)
		if err != nil {
			return nil, err
		}
		out = append(out, securedObject{DN: e.DN, SD: s})
	}
	return out, nil
}

func (d connDir) tokenGroups(ctx context.Context, dn string) ([]sid.SID, error) {
	return d.c.TokenGroups(ctx, dn)
}
