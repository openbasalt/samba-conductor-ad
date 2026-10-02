package escape

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ErrInvalidDN is returned for a distinguished name that does not parse.
var ErrInvalidDN = errors.New("escape: invalid DN")

// RDN renders one relative DN component "attr=value" with the value escaped.
func RDN(attr, value string) (string, error) {
	if err := checkAttr(attr); err != nil {
		return "", err
	}
	if strings.Contains(attr, ";") {
		return "", fmt.Errorf("%w: options are not allowed in a DN: %q", ErrInvalidAttribute, attr)
	}
	if value == "" {
		return "", errors.New("escape: empty RDN value")
	}
	return attr + "=" + DNValue(value), nil
}

// ChildDN returns the DN of a new child "attr=value" under parent. The parent
// must already be a valid DN (it typically comes from the directory).
func ChildDN(attr, value, parent string) (string, error) {
	rdn, err := RDN(attr, value)
	if err != nil {
		return "", err
	}
	if _, err := ParseDN(parent); err != nil {
		return "", err
	}
	if strings.TrimSpace(parent) == "" {
		return rdn, nil
	}
	return rdn + "," + parent, nil
}

// ParseDN parses a DN, wrapping go-ldap's RFC 4514 parser with a typed error.
func ParseDN(dn string) (*ldap.DN, error) {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDN, err)
	}
	return parsed, nil
}

// ParentDN returns the DN without its first RDN, and the first RDN's value.
func ParentDN(dn string) (parent string, firstValue string, err error) {
	parsed, err := ParseDN(dn)
	if err != nil {
		return "", "", err
	}
	if len(parsed.RDNs) == 0 {
		return "", "", fmt.Errorf("%w: empty DN", ErrInvalidDN)
	}
	first := parsed.RDNs[0]
	if len(first.Attributes) != 1 {
		return "", "", fmt.Errorf("%w: multi-valued RDN", ErrInvalidDN)
	}
	parts := make([]string, 0, len(parsed.RDNs)-1)
	for _, r := range parsed.RDNs[1:] {
		comps := make([]string, 0, len(r.Attributes))
		for _, a := range r.Attributes {
			comps = append(comps, a.Type+"="+DNValue(a.Value))
		}
		parts = append(parts, strings.Join(comps, "+"))
	}
	return strings.Join(parts, ","), first.Attributes[0].Value, nil
}

// EqualDN compares two DNs semantically (case-insensitive types and values,
// escaping differences ignored), as AD does for most naming attributes.
func EqualDN(a, b string) bool {
	da, err := ldap.ParseDN(a)
	if err != nil {
		return false
	}
	db, err := ldap.ParseDN(b)
	if err != nil {
		return false
	}
	return da.EqualFold(db)
}
