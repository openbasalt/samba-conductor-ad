package ad

import (
	"fmt"
	"slices"
	"strings"

	"github.com/openbasalt/samba-conductor-ad/escape"
)

// protectedAttrs may never be written through ExtraAttributes or
// ReplaceAttributes: identity, security, membership and password
// attributes have their own constructors or are never written.
var protectedAttrs = []string{"objectclass", "objectcategory", "objectsid", "objectguid", "samaccountname",
	"userprincipalname", "cn", "name", "distinguishedname", "unicodepwd", "userpassword", "dbcspwd", "ntpwdhistory",
	"lmpwdhistory", "supplementalcredentials", "useraccountcontrol", "pwdlastset", "lockouttime", "admincount",
	"member", "memberof", "primarygroupid", "ntsecuritydescriptor", "serviceprincipalname", "sidhistory",
	"msds-allowedtodelegateto", "msds-allowedtoactonbehalfofotheridentity", "altsecurityidentities",
	"msds-keycredentiallink", "scriptpath", "homedirectory", "profilepath"}

// maxExtraValues bounds the values of one attribute.
const maxExtraValues = 256

func checkExtraAttr(name string, values []string) error {
	if !escape.ValidAttribute(name) || strings.Contains(name, ";") {
		return fmt.Errorf("%w: attribute name %q", ErrInvalid, name)
	}
	if slices.Contains(protectedAttrs, strings.ToLower(name)) {
		return fmt.Errorf("%w: %s cannot be written this way", ErrInvalid, name)
	}
	if len(values) > maxExtraValues {
		return fmt.Errorf("%w: too many values for %s", ErrInvalid, name)
	}
	for _, v := range values {
		if v == "" {
			return fmt.Errorf("%w: empty value for %s", ErrInvalid, name)
		}
		if err := validAttrValue(name, v); err != nil {
			return err
		}
	}
	return nil
}

// AttrReplace replaces one attribute: Before are the values the caller
// read (the write is conditional on the entry still holding each of them,
// or none when Before is empty), After the new values (none removes it).
type AttrReplace struct {
	Name   string
	Before []string
	After  []string
}

// ReplaceAttributes builds one modify replacing the given string
// attributes of an object, conditional (RFC 4528 assertion, checked by a
// read on Samba) on their current values. Identity, security, password
// and membership attributes are refused.
func ReplaceAttributes(dn string, changes []AttrReplace) (*Operation, error) {
	if err := checkDN(dn); err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, ErrNoChange
	}
	var attrs []AttrChange
	var asserts []escape.Filter
	seen := map[string]bool{}
	for _, c := range changes {
		if seen[strings.ToLower(c.Name)] {
			return nil, fmt.Errorf("%w: %s listed twice", ErrInvalid, c.Name)
		}
		seen[strings.ToLower(c.Name)] = true
		if err := checkExtraAttr(c.Name, c.After); err != nil {
			return nil, err
		}
		if err := checkExtraAttr(c.Name, c.Before); err != nil {
			return nil, err
		}
		attrs = append(attrs, AttrChange{Op: ModReplace, Name: c.Name, Values: slices.Clone(c.After)})
		if len(c.Before) == 0 {
			asserts = append(asserts, escape.Not(escape.Present(c.Name)))
		}
		for _, v := range c.Before {
			asserts = append(asserts, escape.Eq(c.Name, v))
		}
	}
	return &Operation{preview: Preview{Summary: "replace attributes", Changes: []Change{{Type: ChangeModify, DN: dn,
		Assert: escape.And(asserts...), Attrs: attrs}}}}, nil
}
