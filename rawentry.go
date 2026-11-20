package ad

import (
	"context"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

// Bounds of a raw read (RawEntry): values shown per attribute and bytes
// shown per value.
const (
	MaxRawValues     = 50
	MaxRawValueBytes = 1024
)

// RawValue is one attribute value as RawEntry shows it.
type RawValue struct {
	// Text is the readable value (cut at MaxRawValueBytes); empty when
	// Binary is set.
	Text string
	// Binary: the value is not valid UTF-8 or holds control or format
	// characters, so only its length is shown, never its content.
	Binary bool
	// Len is the length in bytes of the value as the server sent it.
	Len int
	// Truncated: Text is a prefix of the value.
	Truncated bool
}

// RawAttribute is one attribute of a raw read.
type RawAttribute struct {
	Name string
	// Hidden: the attribute carries secrets (password hashes, keys,
	// recovery passwords, security descriptors); its values are dropped
	// even when the server sent them.
	Hidden bool
	Values []RawValue
	// More counts the values left out beyond MaxRawValues.
	More int
}

// RawEntry is every readable attribute of one object, made safe to show.
type RawEntry struct {
	DN         string
	Attributes []RawAttribute
}

// secretAttrs are never shown with content (lower case). Matched on the
// attribute name without its options ("unicodePwd;binary").
var secretAttrs = []string{
	"unicodepwd", "dbcspwd", "userpassword", "unixuserpassword", "ntpwdhistory", "lmpwdhistory",
	"supplementalcredentials", "msds-managedpassword", "ms-mcs-admpwd", "ms-mcs-admpwdhistory",
	"msds-keycredentiallink", "ntsecuritydescriptor", "mssfu30password", "userpkcs12",
	// Trust secrets (trustedDomain and secret objects).
	"currentvalue", "priorvalue", "trustauthincoming", "trustauthoutgoing", "initialauthincoming", "initialauthoutgoing",
	// Credential roaming (DPAPI master keys, private keys).
	"mspkiaccountcredentials", "mspkidpapimasterkeys", "mspkiroamingtimestamp",
	// KDS root keys (gMSA passwords derive from them).
	"mskds-rootkeydata",
	"msds-executescriptpassword",
}

// secretAttrPrefixes hide whole families (lower case): Windows LAPS,
// BitLocker recovery data, TPM owner information.
var secretAttrPrefixes = []string{"mslaps-", "msfve-", "mstpm-"}

// sidAttrs and guidAttrs are decoded to their string forms (lower case).
var (
	sidAttrs  = []string{"objectsid", "sidhistory", "ms-ds-creatorsid"}
	guidAttrs = []string{"objectguid"}
)

// IsSecretAttribute reports whether an attribute is never shown with its
// values (case-insensitive; options such as ";binary" are ignored).
func IsSecretAttribute(name string) bool {
	n, _, _ := strings.Cut(strings.ToLower(name), ";")
	if slices.Contains(secretAttrs, n) || strings.HasSuffix(n, "pwdhistory") {
		return true
	}
	for _, p := range secretAttrPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// RawEntry reads every attribute the signed-in identity may read of one
// object (a base search for "*"), with secrets hidden and values bounded:
// see RawEntryFrom.
func (c *Conn) RawEntry(ctx context.Context, dn string) (RawEntry, error) {
	e, err := c.Get(ctx, dn, "*")
	if err != nil {
		return RawEntry{}, err
	}
	return RawEntryFrom(e), nil
}

// RawEntryFrom turns an entry into a RawEntry: attributes sorted by name
// (case-insensitive), objectSid and objectGUID in their string forms,
// secret attributes hidden (IsSecretAttribute), binary values reduced to
// their length, at most MaxRawValues values per attribute and
// MaxRawValueBytes bytes per value.
func RawEntryFrom(e *ldap.Entry) RawEntry {
	out := RawEntry{DN: e.DN, Attributes: make([]RawAttribute, 0, len(e.Attributes))}
	for _, a := range e.Attributes {
		ra := RawAttribute{Name: a.Name}
		if IsSecretAttribute(a.Name) {
			ra.Hidden = true
			out.Attributes = append(out.Attributes, ra)
			continue
		}
		vals := a.ByteValues
		if len(vals) > MaxRawValues {
			ra.More = len(vals) - MaxRawValues
			vals = vals[:MaxRawValues]
		}
		base, _, _ := strings.Cut(strings.ToLower(a.Name), ";")
		for _, v := range vals {
			ra.Values = append(ra.Values, rawValue(base, v))
		}
		out.Attributes = append(out.Attributes, ra)
	}
	slices.SortStableFunc(out.Attributes, func(x, y RawAttribute) int {
		return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
	})
	return out
}

// rawValue renders one value of the attribute named base (lower case,
// without options).
func rawValue(base string, v []byte) RawValue {
	rv := RawValue{Len: len(v)}
	switch {
	case slices.Contains(sidAttrs, base):
		if s, err := sid.FromBytes(v); err == nil {
			rv.Text = s.String()
			return rv
		}
		rv.Binary = true
		return rv
	case slices.Contains(guidAttrs, base):
		if g, err := sid.GUIDFromBytes(v); err == nil {
			rv.Text = g.String()
			return rv
		}
		rv.Binary = true
		return rv
	}
	if !displayable(v) {
		rv.Binary = true
		return rv
	}
	if len(v) > MaxRawValueBytes {
		cut := MaxRawValueBytes
		// Never split a UTF-8 sequence.
		for cut > 0 && !utf8.RuneStart(v[cut]) {
			cut--
		}
		rv.Text, rv.Truncated = string(v[:cut]), true
		return rv
	}
	rv.Text = string(v)
	return rv
}

// displayable reports valid UTF-8 without control or format characters
// (C0, DEL, C1, bidirectional overrides, zero-width characters).
func displayable(v []byte) bool {
	if !utf8.Valid(v) {
		return false
	}
	for _, r := range string(v) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
