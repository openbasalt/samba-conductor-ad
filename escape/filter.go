package escape

import (
	"errors"
	"strconv"
	"strings"
)

// Matching rule OIDs used by Active Directory.
const (
	// MatchingRuleBitAnd matches when all bits of the mask are set.
	MatchingRuleBitAnd = "1.2.840.113556.1.4.803"
	// MatchingRuleBitOr matches when any bit of the mask is set.
	MatchingRuleBitOr = "1.2.840.113556.1.4.804"
	// MatchingRuleInChain walks nested membership (LDAP_MATCHING_RULE_IN_CHAIN).
	MatchingRuleInChain = "1.2.840.113556.1.4.1941"
)

// Filter is an LDAP search filter built from typed parts. Build one with the
// constructors of this package and render it with [Compile]; the interface is
// sealed so callers cannot smuggle an unescaped string in.
type Filter interface {
	write(sb *strings.Builder) error
}

// Compile validates the filter and renders its RFC 4515 string form.
func Compile(f Filter) (string, error) {
	if f == nil {
		return "", errors.New("escape: nil filter")
	}
	var sb strings.Builder
	if err := f.write(&sb); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// MustCompile is Compile for filters built only from constants; it panics on
// an invalid attribute name (a programming error).
func MustCompile(f Filter) string {
	s, err := Compile(f)
	if err != nil {
		panic(err)
	}
	return s
}

type cmp struct {
	attr, op, value string
	binary          []byte
	isBinary        bool
}

func (c cmp) write(sb *strings.Builder) error {
	if err := checkAttr(c.attr); err != nil {
		return err
	}
	sb.WriteByte('(')
	sb.WriteString(c.attr)
	sb.WriteString(c.op)
	if c.isBinary {
		sb.WriteString(FilterBytes(c.binary))
	} else {
		sb.WriteString(FilterValue(c.value))
	}
	sb.WriteByte(')')
	return nil
}

// Eq matches attr equal to value: (attr=value).
func Eq(attr, value string) Filter { return cmp{attr: attr, op: "=", value: value} }

// EqBytes matches a binary attribute (objectSid, objectGUID) exactly.
func EqBytes(attr string, value []byte) Filter {
	return cmp{attr: attr, op: "=", binary: append([]byte(nil), value...), isBinary: true}
}

// GreaterOrEqual matches (attr>=value).
func GreaterOrEqual(attr, value string) Filter { return cmp{attr: attr, op: ">=", value: value} }

// LessOrEqual matches (attr<=value).
func LessOrEqual(attr, value string) Filter { return cmp{attr: attr, op: "<=", value: value} }

// Approx matches (attr~=value).
func Approx(attr, value string) Filter { return cmp{attr: attr, op: "~=", value: value} }

type present struct{ attr string }

func (p present) write(sb *strings.Builder) error {
	if err := checkAttr(p.attr); err != nil {
		return err
	}
	sb.WriteByte('(')
	sb.WriteString(p.attr)
	sb.WriteString("=*)")
	return nil
}

// Present matches entries that have attr: (attr=*).
func Present(attr string) Filter { return present{attr: attr} }

type substring struct {
	attr, initial, final string
	any                  []string
}

func (s substring) write(sb *strings.Builder) error {
	if err := checkAttr(s.attr); err != nil {
		return err
	}
	if s.initial == "" && s.final == "" && len(s.any) == 0 {
		return errors.New("escape: empty substring filter")
	}
	for _, a := range s.any {
		if a == "" {
			return errors.New("escape: empty 'any' part in substring filter")
		}
	}
	sb.WriteByte('(')
	sb.WriteString(s.attr)
	sb.WriteByte('=')
	sb.WriteString(FilterValue(s.initial))
	sb.WriteByte('*')
	for _, a := range s.any {
		sb.WriteString(FilterValue(a))
		sb.WriteByte('*')
	}
	sb.WriteString(FilterValue(s.final))
	sb.WriteByte(')')
	return nil
}

// Substring matches (attr=initial*any1*any2*final); any part may be empty
// except the "any" elements.
func Substring(attr, initial string, anyParts []string, final string) Filter {
	return substring{attr: attr, initial: initial, any: append([]string(nil), anyParts...), final: final}
}

// Prefix matches values starting with v: (attr=v*).
func Prefix(attr, v string) Filter { return substring{attr: attr, initial: v} }

// Contains matches values containing v: (attr=*v*).
func Contains(attr, v string) Filter { return substring{attr: attr, any: []string{v}} }

type extensible struct {
	attr, rule, value string
}

func (e extensible) write(sb *strings.Builder) error {
	if err := checkAttr(e.attr); err != nil {
		return err
	}
	if !validOID(e.rule) {
		return errors.New("escape: invalid matching rule OID")
	}
	sb.WriteByte('(')
	sb.WriteString(e.attr)
	sb.WriteByte(':')
	sb.WriteString(e.rule)
	sb.WriteString(":=")
	sb.WriteString(FilterValue(e.value))
	sb.WriteByte(')')
	return nil
}

// BitAnd matches when every bit of mask is set in attr (for example
// userAccountControl with 0x2 for disabled accounts).
func BitAnd(attr string, mask uint32) Filter {
	return extensible{attr: attr, rule: MatchingRuleBitAnd, value: strconv.FormatUint(uint64(mask), 10)}
}

// BitOr matches when any bit of mask is set in attr.
func BitOr(attr string, mask uint32) Filter {
	return extensible{attr: attr, rule: MatchingRuleBitOr, value: strconv.FormatUint(uint64(mask), 10)}
}

// InChain matches nested membership, e.g. InChain("memberOf", groupDN) finds
// every direct or transitive member of the group.
func InChain(attr, dn string) Filter {
	return extensible{attr: attr, rule: MatchingRuleInChain, value: dn}
}

type composite struct {
	op    byte
	parts []Filter
}

func (c composite) write(sb *strings.Builder) error {
	if len(c.parts) == 0 {
		return errors.New("escape: empty AND/OR filter")
	}
	sb.WriteByte('(')
	sb.WriteByte(c.op)
	for _, p := range c.parts {
		if p == nil {
			return errors.New("escape: nil filter inside AND/OR")
		}
		if err := p.write(sb); err != nil {
			return err
		}
	}
	sb.WriteByte(')')
	return nil
}

// And matches when every part matches.
func And(parts ...Filter) Filter { return composite{op: '&', parts: parts} }

// Or matches when any part matches.
func Or(parts ...Filter) Filter { return composite{op: '|', parts: parts} }

type not struct{ f Filter }

func (n not) write(sb *strings.Builder) error {
	if n.f == nil {
		return errors.New("escape: nil filter inside NOT")
	}
	sb.WriteString("(!")
	if err := n.f.write(sb); err != nil {
		return err
	}
	sb.WriteByte(')')
	return nil
}

// Not negates a filter.
func Not(f Filter) Filter { return not{f: f} }

// RawFilter is a filter string written by the programmer, for trusted
// compile-time constants only (for example "(objectClass=*)"). Never build a
// RawFilter from user input: use the typed constructors instead. Its syntax is
// checked only for balanced parentheses.
type RawFilter string

func (r RawFilter) write(sb *strings.Builder) error {
	s := string(r)
	if len(s) < 3 || s[0] != '(' || s[len(s)-1] != ')' {
		return errors.New("escape: RawFilter must be parenthesized")
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i += 2
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return errors.New("escape: unbalanced RawFilter")
			}
		}
	}
	if depth != 0 {
		return errors.New("escape: unbalanced RawFilter")
	}
	sb.WriteString(s)
	return nil
}
