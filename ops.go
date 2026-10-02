package ad

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/ad/escape"
)

// ChangeType is the kind of one LDAP write.
type ChangeType string

// Change types (LDIF changetype names).
const (
	ChangeAdd    ChangeType = "add"
	ChangeModify ChangeType = "modify"
	ChangeDelete ChangeType = "delete"
	ChangeModDN  ChangeType = "moddn"
)

// ModOp is an attribute modification operation.
type ModOp string

// Modification operations.
const (
	ModAdd     ModOp = "add"
	ModDelete  ModOp = "delete"
	ModReplace ModOp = "replace"
)

// AttrChange is one attribute of an add, or one modification of a modify.
type AttrChange struct {
	Op     ModOp // empty for ChangeAdd
	Name   string
	Values []string
	// Sensitive values (unicodePwd) are sent but never rendered; Values then
	// holds a placeholder.
	Sensitive bool
	secret    []string
	// Display holds a readable form of binary values (shown as LDIF
	// comments next to their base64 encoding); never sent.
	Display []string
}

// Change is one LDAP write request.
type Change struct {
	Type  ChangeType
	DN    string
	Attrs []AttrChange
	// ModDN only.
	NewRDN       string
	NewSuperior  string
	DeleteOldRDN bool
	// Assert, when set, is an RFC 4528 assertion sent with the request: the
	// server applies the change only if the entry still matches it
	// (optimistic concurrency); otherwise the result is ErrConflict.
	Assert escape.Filter
	// TreeDelete (ChangeDelete only) deletes the entry with its whole
	// subtree (LDAP_SERVER_TREE_DELETE_OID). Only constructors that show
	// the subtree in the preview set it (a DNS zone with its records).
	TreeDelete bool
	// Notes are human-readable lines rendered as LDIF comments under the
	// dn (e.g. the decoded form of a binary dnsRecord value). They are not
	// sent to the server.
	Notes []string
}

// assertionControlOID is the LDAP Assertion Control (RFC 4528).
const assertionControlOID = "1.3.6.1.1.12"

// treeDeleteControlOID is LDAP_SERVER_TREE_DELETE_OID (MS-ADTS 3.1.1.3.4.1.15).
const treeDeleteControlOID = "1.2.840.113556.1.4.805"

// Preview is the exact list of LDAP writes an Operation performs, in order.
// Show it to the user before calling Apply; Apply sends exactly this.
type Preview struct {
	Summary string
	Changes []Change
}

// redacted is shown in place of sensitive values.
const redacted = "<redacted>"

// String renders the preview as LDIF (RFC 2849), sensitive values redacted.
func (p Preview) String() string {
	var sb strings.Builder
	if p.Summary != "" {
		fmt.Fprintf(&sb, "# %s\n", p.Summary)
	}
	for i, c := range p.Changes {
		if i > 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "dn: %s\n", c.DN)
		for _, n := range c.Notes {
			fmt.Fprintf(&sb, "# %s\n", strings.ReplaceAll(n, "\n", " "))
		}
		if c.Assert != nil {
			f, _ := escape.Compile(c.Assert)
			fmt.Fprintf(&sb, "# only if the entry still matches %s\ncontrol: %s true\n", f, assertionControlOID)
		}
		if c.TreeDelete {
			fmt.Fprintf(&sb, "# the entry and everything below it\ncontrol: %s true\n", treeDeleteControlOID)
		}
		fmt.Fprintf(&sb, "changetype: %s\n", c.Type)
		switch c.Type {
		case ChangeAdd:
			for _, a := range c.Attrs {
				writeAttrValues(&sb, a)
			}
		case ChangeModify:
			for _, a := range c.Attrs {
				fmt.Fprintf(&sb, "%s: %s\n", a.Op, a.Name)
				writeAttrValues(&sb, a)
				sb.WriteString("-\n")
			}
		case ChangeModDN:
			fmt.Fprintf(&sb, "newrdn: %s\ndeleteoldrdn: %d\n", c.NewRDN, boolInt(c.DeleteOldRDN))
			if c.NewSuperior != "" {
				fmt.Fprintf(&sb, "newsuperior: %s\n", c.NewSuperior)
			}
		}
	}
	return sb.String()
}

// writeAttrValues writes the values of one attribute, each preceded by its
// readable form when the attribute carries one.
func writeAttrValues(sb *strings.Builder, a AttrChange) {
	for i, v := range a.Values {
		if i < len(a.Display) && a.Display[i] != "" {
			fmt.Fprintf(sb, "# %s: %s\n", a.Name, strings.ReplaceAll(a.Display[i], "\n", " "))
		}
		writeLDIFValue(sb, a.Name, v)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// writeLDIFValue writes "name: value", or base64 ("name:: …") when the value
// is not a safe LDIF string.
func writeLDIFValue(sb *strings.Builder, name, v string) {
	safe := v == redacted || (v != "" && v[0] != ' ' && v[0] != ':' && v[0] != '<' && v[len(v)-1] != ' ')
	for i := 0; safe && i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			safe = false
		}
	}
	if v == "" {
		safe = true
	}
	if safe {
		fmt.Fprintf(sb, "%s: %s\n", name, v)
		return
	}
	fmt.Fprintf(sb, "%s:: %s\n", name, base64Std(v))
}

// Operation is a validated set of LDAP writes. Build one with the
// constructors of this file, show Preview() to the user, then Apply it with
// a connection bound as the user.
type Operation struct {
	preview Preview
}

// Preview returns the exact changes the operation will send.
func (o *Operation) Preview() Preview { return o.preview }

// Apply sends the operation's changes in order on c. A failure stops at the
// failing change (earlier changes stay applied; operations built here are a
// single change unless documented otherwise). Errors are classified
// (ErrAccessDenied, ErrPasswordPolicy, ErrConflict, ErrNotFound, …).
func (c *Conn) Apply(ctx context.Context, op *Operation) error {
	if op == nil || len(op.preview.Changes) == 0 {
		return ErrNoChange
	}
	for _, ch := range op.preview.Changes {
		if ch.Assert != nil {
			// The assertion control makes the write conditional on servers
			// that implement RFC 4528 (Windows AD). Samba 4.22 accepts the
			// control but does not evaluate it, so the precondition is also
			// checked by a read right before the write. On Samba a narrow
			// race remains between that read and the write.
			if err := c.checkPrecondition(ctx, ch.DN, ch.Assert); err != nil {
				return fmt.Errorf("ad: %s %s: %w", ch.Type, ch.DN, err)
			}
		}
		err := c.guard(ctx, func() error { return c.applyChange(ch) })
		if err != nil {
			return fmt.Errorf("ad: %s %s: %w", ch.Type, ch.DN, classifyWriteError(err))
		}
	}
	return nil
}

func (c *Conn) checkPrecondition(ctx context.Context, dn string, f escape.Filter) error {
	entries, err := c.SearchAll(ctx, SearchRequest{BaseDN: dn, Scope: ScopeBase, Filter: f, Attributes: []string{"1.1"}})
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("%w: precondition no longer holds", ErrConflict)
	}
	return nil
}

func (c *Conn) applyChange(ch Change) error {
	var controls []ldap.Control
	if ch.Assert != nil {
		ctrl, err := assertionControl(ch.Assert)
		if err != nil {
			return err
		}
		controls = append(controls, ctrl)
	}
	values := func(a AttrChange) []string {
		if a.Sensitive {
			return a.secret
		}
		return a.Values
	}
	switch ch.Type {
	case ChangeAdd:
		req := ldap.NewAddRequest(ch.DN, controls)
		for _, a := range ch.Attrs {
			req.Attribute(a.Name, values(a))
		}
		return c.l.Add(req)
	case ChangeModify:
		req := ldap.NewModifyRequest(ch.DN, controls)
		for _, a := range ch.Attrs {
			switch a.Op {
			case ModAdd:
				req.Add(a.Name, values(a))
			case ModDelete:
				req.Delete(a.Name, values(a))
			case ModReplace:
				req.Replace(a.Name, values(a))
			default:
				return fmt.Errorf("ad: unknown modification %q", a.Op)
			}
		}
		return c.l.Modify(req)
	case ChangeDelete:
		if ch.TreeDelete {
			controls = append(controls, &ldap.ControlString{ControlType: treeDeleteControlOID, Criticality: true})
		}
		return c.l.Del(ldap.NewDelRequest(ch.DN, controls))
	case ChangeModDN:
		req := ldap.NewModifyDNRequest(ch.DN, ch.NewRDN, ch.DeleteOldRDN, ch.NewSuperior)
		req.Controls = controls
		return c.l.ModifyDN(req)
	default:
		return fmt.Errorf("ad: unknown change type %q", ch.Type)
	}
}

// assertionControl encodes an RFC 4528 assertion: the control value is the
// BER encoding of the filter.
func assertionControl(f escape.Filter) (ldap.Control, error) {
	s, err := escape.Compile(f)
	if err != nil {
		return nil, err
	}
	p, err := ldap.CompileFilter(s)
	if err != nil {
		return nil, err
	}
	return &ldap.ControlString{ControlType: assertionControlOID, Criticality: true, ControlValue: string(p.Bytes())}, nil
}

// encodePassword renders a password for unicodePwd: the quoted string in
// UTF-16LE.
func encodePassword(pw string) string {
	u := utf16.Encode([]rune("\"" + pw + "\""))
	b := make([]byte, 2*len(u))
	for i, r := range u {
		b[2*i] = byte(r)
		b[2*i+1] = byte(r >> 8)
	}
	return string(b)
}

func passwordAttr(op ModOp, pw string) AttrChange {
	return AttrChange{Op: op, Name: "unicodePwd", Values: []string{redacted}, Sensitive: true, secret: []string{encodePassword(pw)}}
}

func checkDN(dn string) error {
	_, err := escape.ParseDN(dn)
	return err
}

var errEmptyPassword = errors.New("ad: empty password")

// validSAM checks a sAMAccountName (MS-ADTS: at most 20 characters for
// users, none of "/\[]:;|=,+*?<>@ and not ending with '.').
func validSAM(s string, maxLen int) error {
	if s == "" || len([]rune(s)) > maxLen {
		return fmt.Errorf("ad: sAMAccountName must be 1-%d characters", maxLen)
	}
	if strings.ContainsAny(s, "\"/\\[]:;|=,+*?<>@") || strings.HasSuffix(s, ".") || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 }) {
		return fmt.Errorf("ad: invalid sAMAccountName %q", s)
	}
	return nil
}

// NewUser describes a user to create.
type NewUser struct {
	ParentDN          string // OU or container
	CN                string // common name (RDN value)
	SAMAccountName    string
	UserPrincipalName string // e.g. "jdoe@lab.example"; required
	GivenName         string
	Surname           string
	DisplayName       string
	Mail              string
	Description       string
	// Password is set in the same request (TLS required). Empty creates the
	// account disabled and without a password.
	Password string
	// MustChangePassword sets pwdLastSet=0.
	MustChangePassword bool
	// Disabled creates the account disabled even with a password.
	Disabled bool
}

// CreateUser builds the add of a user, password included, as one request.
func CreateUser(u NewUser) (*Operation, error) {
	if err := validSAM(u.SAMAccountName, 20); err != nil {
		return nil, err
	}
	dn, err := escape.ChildDN("CN", u.CN, u.ParentDN)
	if err != nil {
		return nil, err
	}
	if u.UserPrincipalName == "" || strings.Count(u.UserPrincipalName, "@") != 1 {
		return nil, errors.New("ad: UserPrincipalName must be name@suffix")
	}
	uac := UACNormalAccount
	if u.Disabled || u.Password == "" {
		uac |= UACAccountDisable
	}
	attrs := []AttrChange{
		{Name: "objectClass", Values: []string{"top", "person", "organizationalPerson", "user"}},
		{Name: "cn", Values: []string{u.CN}},
		{Name: "sAMAccountName", Values: []string{u.SAMAccountName}},
		{Name: "userPrincipalName", Values: []string{u.UserPrincipalName}},
	}
	for _, kv := range [][2]string{{"givenName", u.GivenName}, {"sn", u.Surname}, {"displayName", u.DisplayName},
		{"mail", u.Mail}, {"description", u.Description}} {
		if kv[1] != "" {
			attrs = append(attrs, AttrChange{Name: kv[0], Values: []string{kv[1]}})
		}
	}
	if u.Password != "" {
		attrs = append(attrs, passwordAttr("", u.Password))
	}
	attrs = append(attrs, AttrChange{Name: "userAccountControl", Values: []string{strconv.FormatUint(uint64(uac), 10)}})
	if u.MustChangePassword {
		attrs = append(attrs, AttrChange{Name: "pwdLastSet", Values: []string{"0"}})
	}
	return &Operation{preview: Preview{
		Summary: fmt.Sprintf("create user %s (%s)", u.SAMAccountName, uac),
		Changes: []Change{{Type: ChangeAdd, DN: dn, Attrs: attrs}},
	}}, nil
}

// UserUpdate lists the profile attributes an update may change. Nil leaves
// the attribute untouched; a pointer to "" removes it.
type UserUpdate struct {
	DisplayName     *string
	GivenName       *string
	Surname         *string
	Mail            *string
	Description     *string
	Department      *string
	Title           *string
	TelephoneNumber *string
	Mobile          *string
	HomePhone       *string
	Office          *string // physicalDeliveryOfficeName
	Company         *string
	StreetAddress   *string
	City            *string // l
	State           *string // st
	PostalCode      *string
	HomePage        *string // wWWHomePage
}

// userUpdateField pairs an LDAP attribute with its UserUpdate field.
type userUpdateField struct {
	Attr string
	v    *string
}

func (u UserUpdate) fields() []userUpdateField {
	return []userUpdateField{{"displayName", u.DisplayName}, {"givenName", u.GivenName}, {"sn", u.Surname},
		{"mail", u.Mail}, {"description", u.Description}, {"department", u.Department}, {"title", u.Title},
		{"telephoneNumber", u.TelephoneNumber}, {"mobile", u.Mobile}, {"homePhone", u.HomePhone},
		{"physicalDeliveryOfficeName", u.Office}, {"company", u.Company}, {"streetAddress", u.StreetAddress},
		{"l", u.City}, {"st", u.State}, {"postalCode", u.PostalCode}, {"wWWHomePage", u.HomePage}}
}

// UserUpdateAttributes lists the LDAP attributes UserUpdate can write, in the
// order they appear in a preview.
func UserUpdateAttributes() []string {
	f := UserUpdate{}.fields()
	out := make([]string, len(f))
	for i, x := range f {
		out[i] = x.Attr
	}
	return out
}

// maxAttrValue bounds a profile value (AD's rangeUpper for these attributes
// is at most 1024; most are 64-256 and the DC enforces the exact limit).
const maxAttrValue = 1024

// UpdateUser builds a replace of the given profile attributes.
func UpdateUser(dn string, u UserUpdate) (*Operation, error) {
	if err := checkDN(dn); err != nil {
		return nil, err
	}
	var attrs []AttrChange
	for _, kv := range u.fields() {
		if kv.v == nil {
			continue
		}
		if len(*kv.v) > maxAttrValue || strings.ContainsFunc(*kv.v, func(r rune) bool { return r < 0x20 }) {
			return nil, fmt.Errorf("ad: invalid value for %s", kv.Attr)
		}
		vals := []string{*kv.v}
		if *kv.v == "" {
			vals = nil
		}
		attrs = append(attrs, AttrChange{Op: ModReplace, Name: kv.Attr, Values: vals})
	}
	if len(attrs) == 0 {
		return nil, ErrNoChange
	}
	return &Operation{preview: Preview{Summary: "update user profile", Changes: []Change{{Type: ChangeModify, DN: dn, Attrs: attrs}}}}, nil
}

// SetUserEnabled enables or disables an account. It needs the user as just
// read (its current userAccountControl): the replace carries an RFC 4528
// assertion on that value, so it fails with ErrConflict if someone changed
// the account in between instead of silently overwriting their change.
func SetUserEnabled(u User, enabled bool) (*Operation, error) {
	return setEnabled(u.DN, "user", u.SAMAccountName, u.UAC, enabled)
}

// SetComputerEnabled enables or disables a computer account, with the same
// precondition as SetUserEnabled. Domain controllers are refused: disabling a
// DC's account breaks replication and sign-in.
func SetComputerEnabled(c Computer, enabled bool) (*Operation, error) {
	if c.IsDomainController() {
		return nil, fmt.Errorf("%w: %s is a domain controller", ErrProtectedObject, c.SAMAccountName)
	}
	return setEnabled(c.DN, "computer", c.SAMAccountName, c.UAC, enabled)
}

func setEnabled(dn, kind, name string, uac UAC, enabled bool) (*Operation, error) {
	if err := checkDN(dn); err != nil {
		return nil, err
	}
	next := uac | UACAccountDisable
	verb := "disable"
	if enabled {
		next = uac &^ UACAccountDisable
		verb = "enable"
	}
	if next == uac {
		return nil, ErrNoChange
	}
	return &Operation{preview: Preview{
		Summary: fmt.Sprintf("%s %s %s (%s -> %s)", verb, kind, name, uac, next),
		Changes: []Change{{Type: ChangeModify, DN: dn,
			Assert: escape.Eq("userAccountControl", strconv.FormatUint(uint64(uac), 10)),
			Attrs: []AttrChange{
				{Op: ModReplace, Name: "userAccountControl", Values: []string{strconv.FormatUint(uint64(next), 10)}},
			}}},
	}}, nil
}

// UnlockUser clears a lockout (lockoutTime = 0).
func UnlockUser(dn string) (*Operation, error) {
	if err := checkDN(dn); err != nil {
		return nil, err
	}
	return &Operation{preview: Preview{Summary: "unlock user", Changes: []Change{{Type: ChangeModify, DN: dn,
		Attrs: []AttrChange{{Op: ModReplace, Name: "lockoutTime", Values: []string{"0"}}}}}}}, nil
}

// ResetPassword is the administrative reset: it replaces the password
// without knowing the old one (needs the Reset Password right), optionally
// forcing a change at next sign-in.
func ResetPassword(dn, newPassword string, mustChange bool) (*Operation, error) {
	if err := checkDN(dn); err != nil {
		return nil, err
	}
	if newPassword == "" {
		return nil, errEmptyPassword
	}
	attrs := []AttrChange{passwordAttr(ModReplace, newPassword)}
	if mustChange {
		attrs = append(attrs, AttrChange{Op: ModReplace, Name: "pwdLastSet", Values: []string{"0"}})
	}
	return &Operation{preview: Preview{Summary: "reset password (administrative)", Changes: []Change{{Type: ChangeModify, DN: dn, Attrs: attrs}}}}, nil
}

// ChangePassword is the self-service change: delete the old value and add
// the new one in one modify, which AD treats as a user password change
// (old password checked, history and minimum age enforced). Apply it on a
// connection bound as that user. Users who must change their password or
// whose password expired cannot bind; use ChangePasswordKerberos for them.
func ChangePassword(dn, oldPassword, newPassword string) (*Operation, error) {
	if err := checkDN(dn); err != nil {
		return nil, err
	}
	if oldPassword == "" || newPassword == "" {
		return nil, errEmptyPassword
	}
	return &Operation{preview: Preview{Summary: "change own password", Changes: []Change{{Type: ChangeModify, DN: dn,
		Attrs: []AttrChange{passwordAttr(ModDelete, oldPassword), passwordAttr(ModAdd, newPassword)}}}}}, nil
}

// MoveObject moves an object under a new parent, keeping its RDN.
func MoveObject(dn, newParentDN string) (*Operation, error) {
	parsed, err := escape.ParseDN(dn)
	if err != nil {
		return nil, err
	}
	if err := checkDN(newParentDN); err != nil {
		return nil, err
	}
	if len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) != 1 {
		return nil, fmt.Errorf("%w: cannot move %q", escape.ErrInvalidDN, dn)
	}
	first := parsed.RDNs[0].Attributes[0]
	rdn, err := escape.RDN(first.Type, first.Value)
	if err != nil {
		return nil, err
	}
	return &Operation{preview: Preview{Summary: "move object", Changes: []Change{{Type: ChangeModDN, DN: dn, NewRDN: rdn,
		DeleteOldRDN: true, NewSuperior: newParentDN}}}}, nil
}

// RenameObject changes the RDN value of an object in place (same parent,
// same RDN attribute), e.g. renames an OU. For users and groups this changes
// the CN only, not sAMAccountName.
func RenameObject(dn, newName string) (*Operation, error) {
	parsed, err := escape.ParseDN(dn)
	if err != nil {
		return nil, err
	}
	if len(parsed.RDNs) < 2 || len(parsed.RDNs[0].Attributes) != 1 {
		return nil, fmt.Errorf("%w: cannot rename %q", escape.ErrInvalidDN, dn)
	}
	first := parsed.RDNs[0].Attributes[0]
	if first.Value == newName {
		return nil, ErrNoChange
	}
	rdn, err := escape.RDN(first.Type, newName)
	if err != nil {
		return nil, err
	}
	return &Operation{preview: Preview{Summary: fmt.Sprintf("rename %q to %q", first.Value, newName),
		Changes: []Change{{Type: ChangeModDN, DN: dn, NewRDN: rdn, DeleteOldRDN: true}}}}, nil
}

// AddGroupMember adds memberDN to the group.
func AddGroupMember(groupDN, memberDN string) (*Operation, error) {
	return memberChange(groupDN, memberDN, ModAdd, "add member")
}

// RemoveGroupMember removes memberDN from the group.
func RemoveGroupMember(groupDN, memberDN string) (*Operation, error) {
	return memberChange(groupDN, memberDN, ModDelete, "remove member")
}

func memberChange(groupDN, memberDN string, op ModOp, summary string) (*Operation, error) {
	if err := checkDN(groupDN); err != nil {
		return nil, err
	}
	if err := checkDN(memberDN); err != nil {
		return nil, err
	}
	return &Operation{preview: Preview{Summary: summary, Changes: []Change{{Type: ChangeModify, DN: groupDN,
		Attrs: []AttrChange{{Op: op, Name: "member", Values: []string{memberDN}}}}}}}, nil
}

// NewGroup describes a group to create.
type NewGroup struct {
	ParentDN       string
	Name           string // CN
	SAMAccountName string // defaults to Name
	Description    string
	// Scope: GroupTypeGlobal (default), GroupTypeDomainLocal or GroupTypeUniversal.
	Scope GroupType
	// Distribution creates a distribution (non-security) group.
	Distribution bool
}

// CreateGroup builds the add of a group.
func CreateGroup(g NewGroup) (*Operation, error) {
	sam := g.SAMAccountName
	if sam == "" {
		sam = g.Name
	}
	if err := validSAM(sam, 64); err != nil {
		return nil, err
	}
	dn, err := escape.ChildDN("CN", g.Name, g.ParentDN)
	if err != nil {
		return nil, err
	}
	scope := g.Scope
	if scope == 0 {
		scope = GroupTypeGlobal
	}
	if scope != GroupTypeGlobal && scope != GroupTypeDomainLocal && scope != GroupTypeUniversal {
		return nil, errors.New("ad: invalid group scope")
	}
	gt := scope
	if !g.Distribution {
		gt |= GroupTypeSecurity
	}
	attrs := []AttrChange{
		{Name: "objectClass", Values: []string{"top", "group"}},
		{Name: "cn", Values: []string{g.Name}},
		{Name: "sAMAccountName", Values: []string{sam}},
		{Name: "groupType", Values: []string{strconv.FormatInt(int64(gt), 10)}},
	}
	if g.Description != "" {
		attrs = append(attrs, AttrChange{Name: "description", Values: []string{g.Description}})
	}
	return &Operation{preview: Preview{Summary: "create group " + sam, Changes: []Change{{Type: ChangeAdd, DN: dn, Attrs: attrs}}}}, nil
}

// NewOU describes an organizational unit to create.
type NewOU struct {
	ParentDN    string
	Name        string
	Description string
}

// CreateOU builds the add of an OU.
func CreateOU(o NewOU) (*Operation, error) {
	dn, err := escape.ChildDN("OU", o.Name, o.ParentDN)
	if err != nil {
		return nil, err
	}
	attrs := []AttrChange{{Name: "objectClass", Values: []string{"top", "organizationalUnit"}}, {Name: "ou", Values: []string{o.Name}}}
	if o.Description != "" {
		attrs = append(attrs, AttrChange{Name: "description", Values: []string{o.Description}})
	}
	return &Operation{preview: Preview{Summary: "create OU " + o.Name, Changes: []Change{{Type: ChangeAdd, DN: dn, Attrs: attrs}}}}, nil
}

// DeleteObject deletes one leaf object (a user, a group, an empty OU). It is
// never recursive: deleting a non-empty OU fails.
func DeleteObject(dn string) (*Operation, error) {
	if err := checkDN(dn); err != nil {
		return nil, err
	}
	return &Operation{preview: Preview{Summary: "delete object", Changes: []Change{{Type: ChangeDelete, DN: dn}}}}, nil
}

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
