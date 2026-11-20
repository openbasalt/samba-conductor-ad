package ad

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/openbasalt/samba-conductor-ad/escape"
)

// EditableAttribute is one attribute UpdateUserAttributes may write.
type EditableAttribute struct {
	Name string
	// Multi: the attribute holds several values (at most MaxValues).
	Multi     bool
	MaxValues int
}

// editableUserAttrs is the allowlist of UpdateUserAttributes, in display
// order. Anything else is refused there, whatever ReplaceAttributes would
// accept.
var editableUserAttrs = []EditableAttribute{
	{Name: "loginShell", MaxValues: 1},
	{Name: "unixHomeDirectory", MaxValues: 1},
	{Name: "uidNumber", MaxValues: 1},
	{Name: "gidNumber", MaxValues: 1},
	{Name: "gecos", MaxValues: 1},
	{Name: "otherMailbox", Multi: true, MaxValues: 16},
}

// EditableUserAttributes returns the allowlist of UpdateUserAttributes.
func EditableUserAttributes() []EditableAttribute { return slices.Clone(editableUserAttrs) }

// editableUserAttr finds an allowlisted attribute (case-insensitive).
func editableUserAttr(name string) (EditableAttribute, bool) {
	for _, a := range editableUserAttrs {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return EditableAttribute{}, false
}

// Reasons of an AttrError (stable codes a UI can translate).
const (
	AttrNotEditable  = "not_editable"
	AttrTooLong      = "too_long"
	AttrNotAbsolute  = "not_absolute"
	AttrBadChars     = "bad_chars"
	AttrDotDot       = "dot_dot"
	AttrNotNumber    = "not_number"
	AttrOutOfRange   = "out_of_range"
	AttrNotPrintable = "not_printable"
	AttrColon        = "colon"
	AttrTooMany      = "too_many"
	AttrNotEmail     = "not_email"
	AttrDuplicate    = "duplicate"
)

// AttrError is a value UpdateUserAttributes refuses. It matches ErrInvalid.
type AttrError struct {
	Attr   string
	Reason string
}

func (e *AttrError) Error() string { return fmt.Sprintf("ad: invalid %s: %s", e.Attr, e.Reason) }

// Unwrap makes errors.Is(err, ErrInvalid) true.
func (e *AttrError) Unwrap() error { return ErrInvalid }

// Bounds of the allowlisted values.
const (
	maxPathAttr  = 255
	maxGecos     = 255
	maxMailbox   = 254
	minPosixID   = 1000
	maxPosixID   = 2147483647
	pathAttrChar = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_.+-"
)

// ValidateUserAttribute checks the values an allowlisted attribute would
// get (none removes it). The error is an *AttrError.
func ValidateUserAttribute(name string, values []string) error {
	a, ok := editableUserAttr(name)
	if !ok {
		return &AttrError{Attr: name, Reason: AttrNotEditable}
	}
	if len(values) > a.MaxValues {
		return &AttrError{Attr: a.Name, Reason: AttrTooMany}
	}
	seen := map[string]bool{}
	for _, v := range values {
		var reason string
		switch strings.ToLower(a.Name) {
		case "loginshell", "unixhomedirectory":
			reason = checkPathValue(v)
		case "uidnumber", "gidnumber":
			reason = checkPosixID(v)
		case "gecos":
			reason = checkGecos(v)
		case "othermailbox":
			reason = checkMailbox(v)
			if reason == "" && seen[strings.ToLower(v)] {
				reason = AttrDuplicate
			}
			seen[strings.ToLower(v)] = true
		}
		if reason != "" {
			return &AttrError{Attr: a.Name, Reason: reason}
		}
	}
	return nil
}

// checkPathValue: an absolute path of [A-Za-z0-9/_.+-], no ".." segment,
// at most 255 bytes.
func checkPathValue(v string) string {
	switch {
	case len(v) > maxPathAttr:
		return AttrTooLong
	case !strings.HasPrefix(v, "/"):
		return AttrNotAbsolute
	case strings.Trim(v, pathAttrChar) != "":
		return AttrBadChars
	case slices.Contains(strings.Split(v, "/"), ".."):
		return AttrDotDot
	}
	return ""
}

// checkPosixID: decimal, no sign or leading zero, 1000..2147483647.
func checkPosixID(v string) string {
	if v == "" || v[0] == '0' || strings.Trim(v, "0123456789") != "" {
		return AttrNotNumber
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < minPosixID || n > maxPosixID {
		return AttrOutOfRange
	}
	return ""
}

// checkGecos: printable UTF-8, no ':' (the passwd field separator), at
// most 255 bytes.
func checkGecos(v string) string {
	switch {
	case len(v) > maxGecos:
		return AttrTooLong
	case !utf8.ValidString(v) || strings.ContainsFunc(v, func(r rune) bool { return !unicode.IsPrint(r) }):
		return AttrNotPrintable
	case strings.Contains(v, ":"):
		return AttrColon
	}
	return ""
}

// checkMailbox: a plain address, local@domain: one '@', printable ASCII
// without spaces or quoting characters, a domain of letters, digits,
// hyphens and dots, at most 254 bytes.
func checkMailbox(v string) string {
	if len(v) > maxMailbox {
		return AttrTooLong
	}
	local, domain, ok := strings.Cut(v, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return AttrNotEmail
	}
	for _, r := range local {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune(`"(),:;<>[\]`, r) {
			return AttrNotEmail
		}
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || strings.Trim(label, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" ||
			strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return AttrNotEmail
		}
	}
	return ""
}

// sameValues compares two value lists as sets (case-sensitive: the stored
// form is what changes).
func sameValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// UpdateUserAttributes builds one conditional modify of allowlisted user
// attributes (EditableUserAttributes): Before are the values read, After
// the wanted ones (none removes the attribute). Unchanged attributes are
// left out; ErrNoChange when nothing changes. Every value is validated
// (ValidateUserAttribute); an attribute outside the allowlist is refused
// with an *AttrError. The write is conditional on the Before values (see
// ReplaceAttributes), and the preview notes old and new values.
func UpdateUserAttributes(dn string, edits []AttrReplace) (*Operation, error) {
	if err := checkDN(dn); err != nil {
		return nil, err
	}
	var changes []AttrReplace
	var notes []string
	seen := map[string]bool{}
	for _, e := range edits {
		a, ok := editableUserAttr(e.Name)
		if !ok {
			return nil, &AttrError{Attr: e.Name, Reason: AttrNotEditable}
		}
		if seen[strings.ToLower(a.Name)] {
			return nil, fmt.Errorf("%w: %s listed twice", ErrInvalid, a.Name)
		}
		seen[strings.ToLower(a.Name)] = true
		if err := ValidateUserAttribute(a.Name, e.After); err != nil {
			return nil, err
		}
		if sameValues(e.Before, e.After) {
			continue
		}
		changes = append(changes, AttrReplace{Name: a.Name, Before: slices.Clone(e.Before), After: slices.Clone(e.After)})
		notes = append(notes, fmt.Sprintf("%s: %s -> %s", a.Name, noteValues(e.Before), noteValues(e.After)))
	}
	if len(changes) == 0 {
		return nil, ErrNoChange
	}
	op, err := ReplaceAttributes(dn, changes)
	if err != nil {
		return nil, err
	}
	op.preview.Summary = "update user attributes"
	op.preview.Changes[0].Notes = notes
	return op, nil
}

func noteValues(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return strings.Join(v, ", ")
}

// UIDNumberInUse reports whether an object of the domain other than
// exceptDN carries uidNumber uid (as far as the bound identity can read).
func (c *Conn) UIDNumberInUse(ctx context.Context, uid, exceptDN string) (bool, error) {
	if checkPosixID(uid) != "" {
		return false, &AttrError{Attr: "uidNumber", Reason: AttrNotNumber}
	}
	for e, err := range c.Search(ctx, SearchRequest{Filter: escape.Eq("uidNumber", uid), Attributes: []string{"1.1"}, Limit: 2}) {
		if err != nil {
			return false, err
		}
		if !escape.EqualDN(e.DN, exceptDN) {
			return true, nil
		}
	}
	return false, nil
}
