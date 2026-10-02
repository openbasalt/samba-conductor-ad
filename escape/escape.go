// Package escape builds LDAP search filters (RFC 4515) and distinguished
// names (RFC 4514) from untrusted values.
//
// Every value that reaches a filter or a DN goes through this package. There
// is no function that accepts a raw filter string, except [RawFilter], which
// exists for trusted compile-time constants and is deliberately named so it
// stands out in review.
package escape

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// FilterValue escapes an assertion value for use inside an LDAP filter
// (RFC 4515 section 3): NUL, '(', ')', '*' and '\' always, and additionally
// every byte outside printable ASCII, so the result is plain ASCII whatever
// the input (including invalid UTF-8).
func FilterValue(v string) string {
	return filterBytes([]byte(v))
}

// FilterBytes escapes a binary assertion value (for example an objectSid or
// objectGUID) as a sequence of \XX escapes.
func FilterBytes(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 3)
	for _, c := range b {
		sb.WriteByte('\\')
		sb.WriteByte(hexDigits[c>>4])
		sb.WriteByte(hexDigits[c&0x0f])
	}
	return sb.String()
}

func filterBytes(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		if c < 0x20 || c >= 0x7f || c == '(' || c == ')' || c == '*' || c == '\\' {
			sb.WriteByte('\\')
			sb.WriteByte(hexDigits[c>>4])
			sb.WriteByte(hexDigits[c&0x0f])
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// DNValue escapes an attribute value for use in a distinguished name
// (RFC 4514 section 2.4): '"', '+', ',', ';', '<', '>', '\' and '=' anywhere,
// a leading '#' or space, a trailing space, and control bytes or invalid UTF-8
// as \XX. Valid non-ASCII UTF-8 is kept as is.
func DNValue(v string) string {
	var sb strings.Builder
	sb.Grow(len(v) + 8)
	for i := 0; i < len(v); {
		r, size := utf8.DecodeRuneInString(v[i:])
		c := v[i]
		switch {
		case r == utf8.RuneError && size <= 1:
			writeHex(&sb, c)
		case c < 0x20 || c == 0x7f:
			writeHex(&sb, c)
		case strings.IndexByte(`"+,;<>\=`, c) >= 0 && size == 1:
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case i == 0 && (c == '#' || c == ' '):
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case i+size == len(v) && c == ' ':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		default:
			sb.WriteString(v[i : i+size])
		}
		i += size
	}
	return sb.String()
}

func writeHex(sb *strings.Builder, c byte) {
	sb.WriteByte('\\')
	sb.WriteByte(hexDigits[c>>4])
	sb.WriteByte(hexDigits[c&0x0f])
}

// ErrInvalidAttribute is returned for an attribute description that is not a
// valid LDAP descriptor or numeric OID (RFC 4512 section 1.4).
var ErrInvalidAttribute = errors.New("escape: invalid attribute name")

// ValidAttribute reports whether name is an LDAP attribute description: a
// descriptor (letter, then letters, digits or '-') or a numeric OID, with
// optional ";option" suffixes (for example "member;range=0-1499").
func ValidAttribute(name string) bool {
	base, opts, _ := strings.Cut(name, ";")
	if !validDescriptor(base) && !validOID(base) {
		return false
	}
	if opts == "" {
		return !strings.HasSuffix(name, ";")
	}
	for _, o := range strings.Split(opts, ";") {
		if o == "" {
			return false
		}
		for _, c := range []byte(o) {
			// '=' and '*' appear in AD's ranged retrieval option "range=0-*".
			if !isAlnum(c) && c != '-' && c != '=' && c != '*' {
				return false
			}
		}
	}
	return true
}

func validDescriptor(s string) bool {
	if s == "" || !isAlpha(s[0]) || len(s) > 256 {
		return false
	}
	for _, c := range []byte(s) {
		if !isAlnum(c) && c != '-' {
			return false
		}
	}
	return true
}

func validOID(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, c := range []byte(part) {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return strings.Contains(s, ".")
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isAlpha(c) || (c >= '0' && c <= '9') }

func checkAttr(name string) error {
	if !ValidAttribute(name) {
		return fmt.Errorf("%w: %q", ErrInvalidAttribute, name)
	}
	return nil
}
