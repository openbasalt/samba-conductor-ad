package ad

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/ad/escape"
)

// Password and lockout policy: the domain's default policy lives on the
// domain object (minPwdLength, maxPwdAge, lockoutThreshold…); fine-grained
// password policies (PSOs, msDS-PasswordSettings objects in the Password
// Settings Container) override it for the users and groups they apply to.
// The policy that applies to a user is the constructed msDS-ResultantPSO
// (or the domain policy when it is empty).

// PasswordPolicy is a password and lockout policy, domain-wide or a PSO.
// Durations are whole; 0 has a special meaning where noted.
type PasswordPolicy struct {
	MinLength            int
	History              int
	Complexity           bool
	ReversibleEncryption bool
	MinAge               time.Duration // 0 = may change at once
	MaxAge               time.Duration // 0 = never expires
	LockoutThreshold     int           // 0 = never lock out
	LockoutDuration      time.Duration // 0 = until an administrator unlocks
	ObservationWindow    time.Duration
}

// Limits enforced before anything is sent (AD enforces its own as well).
const (
	maxPolicyMinLength = 255
	maxPolicyHistory   = 24
	maxPolicyThreshold = 999
	maxPolicyAge       = 999 * 24 * time.Hour
	maxLockoutMinutes  = 99999 * time.Minute
)

// Validate checks the policy's values and their relations.
func (p PasswordPolicy) Validate() error {
	var errs []string
	if p.MinLength < 0 || p.MinLength > maxPolicyMinLength {
		errs = append(errs, "minimum length must be 0-255")
	}
	if p.History < 0 || p.History > maxPolicyHistory {
		errs = append(errs, "history must be 0-24")
	}
	if p.MaxAge < 0 || p.MaxAge > maxPolicyAge || p.MinAge < 0 || p.MinAge > maxPolicyAge {
		errs = append(errs, "ages must be 0-999 days")
	}
	if p.MaxAge > 0 && p.MinAge >= p.MaxAge {
		errs = append(errs, "the minimum age must be below the maximum age")
	}
	if p.LockoutThreshold < 0 || p.LockoutThreshold > maxPolicyThreshold {
		errs = append(errs, "lockout threshold must be 0-999")
	}
	if p.LockoutDuration < 0 || p.LockoutDuration > maxLockoutMinutes || p.ObservationWindow < time.Minute || p.ObservationWindow > maxLockoutMinutes {
		errs = append(errs, "lockout duration and observation window must be 1-99999 minutes (duration 0 = until unlocked)")
	}
	if p.LockoutDuration > 0 && p.ObservationWindow > p.LockoutDuration {
		errs = append(errs, "the observation window cannot exceed the lockout duration")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(errs, "; "))
	}
	return nil
}

// LockoutDisabled reports the risky default (Samba provisions threshold 0:
// accounts never lock, so passwords can be guessed without limit).
func (p PasswordPolicy) LockoutDisabled() bool { return p.LockoutThreshold == 0 }

// intervalNever is the AD "forever" interval (maxPwdAge "never",
// lockoutDuration "until an administrator unlocks").
const intervalNever = math.MinInt64

// encodeInterval renders an AD negative 100 ns interval; 0 with never=true
// becomes the "forever" value.
func encodeInterval(d time.Duration, never bool) string {
	if d == 0 && never {
		return strconv.FormatInt(intervalNever, 10)
	}
	return strconv.FormatInt(-int64(d/100), 10)
}

// decodeInterval reads an AD interval; 0 and the "forever" value read as 0.
func decodeInterval(v string) time.Duration {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n == intervalNever || n == 0 {
		return 0
	}
	if n < 0 {
		n = -n
	}
	return time.Duration(n) * 100
}

// Domain policy attributes, in preview order.
var domainPolicyAttrs = []string{"minPwdLength", "pwdHistoryLength", "pwdProperties", "minPwdAge", "maxPwdAge",
	"lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"}

// pwdProperties bits (MS-SAMR 2.2.1.8).
const (
	pwdComplex         = 0x1
	pwdStoreCleartext  = 0x10
	pwdPropertiesKnown = pwdComplex | pwdStoreCleartext
)

// DomainPasswordPolicy is the domain's default policy as read.
type DomainPasswordPolicy struct {
	DN     string
	Policy PasswordPolicy
	raw    map[string]string
}

// DomainPasswordPolicy reads the domain object's policy attributes.
func (c *Conn) DomainPasswordPolicy(ctx context.Context) (DomainPasswordPolicy, error) {
	e, err := c.Get(ctx, c.baseDN, domainPolicyAttrs...)
	if err != nil {
		return DomainPasswordPolicy{}, err
	}
	return domainPolicyFromEntry(e), nil
}

func domainPolicyFromEntry(e *ldap.Entry) DomainPasswordPolicy {
	raw := map[string]string{}
	for _, a := range domainPolicyAttrs {
		raw[a] = e.GetAttributeValue(a)
	}
	props := attrInt64(e, "pwdProperties")
	return DomainPasswordPolicy{DN: e.DN, raw: raw, Policy: PasswordPolicy{
		MinLength:            int(attrInt64(e, "minPwdLength")),
		History:              int(attrInt64(e, "pwdHistoryLength")),
		Complexity:           props&pwdComplex != 0,
		ReversibleEncryption: props&pwdStoreCleartext != 0,
		MinAge:               decodeInterval(raw["minPwdAge"]),
		MaxAge:               decodeInterval(raw["maxPwdAge"]),
		LockoutThreshold:     int(attrInt64(e, "lockoutThreshold")),
		LockoutDuration:      decodeInterval(raw["lockoutDuration"]),
		ObservationWindow:    decodeInterval(raw["lockOutObservationWindow"]),
	}}
}

// policyValues renders a policy into the attribute names of names (the
// domain's or a PSO's), in the same order.
type policyField struct {
	attr  string
	label string
	value func(PasswordPolicy) string
	show  func(PasswordPolicy) string
}

func days(d time.Duration) string { return strconv.FormatInt(int64(d/(24*time.Hour)), 10) }
func mins(d time.Duration) string { return strconv.FormatInt(int64(d/time.Minute), 10) }

func showAge(d time.Duration) string {
	if d == 0 {
		return "none"
	}
	return days(d) + " days"
}

func showDuration(d time.Duration) string {
	if d == 0 {
		return "until unlocked"
	}
	return mins(d) + " minutes"
}

func boolAttr(b bool) string {
	if b {
		return "TRUE"
	}
	return "FALSE"
}

func domainFields(oldProps int64) []policyField {
	return []policyField{
		{"minPwdLength", "minimum length", func(p PasswordPolicy) string { return strconv.Itoa(p.MinLength) }, nil},
		{"pwdHistoryLength", "history", func(p PasswordPolicy) string { return strconv.Itoa(p.History) }, nil},
		{"pwdProperties", "complexity / reversible encryption", func(p PasswordPolicy) string {
			v := oldProps &^ pwdPropertiesKnown
			if p.Complexity {
				v |= pwdComplex
			}
			if p.ReversibleEncryption {
				v |= pwdStoreCleartext
			}
			return strconv.FormatInt(v, 10)
		}, func(p PasswordPolicy) string {
			return fmt.Sprintf("complexity %v, reversible encryption %v", p.Complexity, p.ReversibleEncryption)
		}},
		{"minPwdAge", "minimum age", func(p PasswordPolicy) string { return encodeInterval(p.MinAge, false) }, func(p PasswordPolicy) string { return showAge(p.MinAge) }},
		{"maxPwdAge", "maximum age", func(p PasswordPolicy) string { return encodeInterval(p.MaxAge, true) }, func(p PasswordPolicy) string {
			if p.MaxAge == 0 {
				return "never expires"
			}
			return showAge(p.MaxAge)
		}},
		{"lockoutThreshold", "lockout threshold", func(p PasswordPolicy) string { return strconv.Itoa(p.LockoutThreshold) }, nil},
		{"lockoutDuration", "lockout duration", func(p PasswordPolicy) string { return encodeInterval(p.LockoutDuration, true) }, func(p PasswordPolicy) string { return showDuration(p.LockoutDuration) }},
		{"lockOutObservationWindow", "observation window", func(p PasswordPolicy) string { return encodeInterval(p.ObservationWindow, false) }, func(p PasswordPolicy) string { return showDuration(p.ObservationWindow) }},
	}
}

// policyChanges compares two policies through fields and returns the
// replace modifications, the assertion on the old raw values and readable
// notes.
func policyChanges(fields []policyField, raw map[string]string, old, next PasswordPolicy) ([]AttrChange, escape.Filter, []string) {
	var attrs []AttrChange
	var asserts []escape.Filter
	var notes []string
	for _, f := range fields {
		nv := f.value(next)
		if nv == raw[f.attr] {
			continue
		}
		show := f.show
		if show == nil {
			show = f.value
		}
		if show(old) == show(next) && raw[f.attr] != "" {
			// Same meaning, different encoding (e.g. 0 vs "never"): leave it.
			continue
		}
		attrs = append(attrs, AttrChange{Op: ModReplace, Name: f.attr, Values: []string{nv}})
		if raw[f.attr] == "" {
			asserts = append(asserts, escape.Not(escape.Present(f.attr)))
		} else {
			asserts = append(asserts, escape.Eq(f.attr, raw[f.attr]))
		}
		notes = append(notes, fmt.Sprintf("%s: %s -> %s", f.label, show(old), show(next)))
	}
	var assert escape.Filter
	switch len(asserts) {
	case 0:
	case 1:
		assert = asserts[0]
	default:
		assert = escape.And(asserts...)
	}
	return attrs, assert, notes
}

// UpdateDomainPasswordPolicy replaces the changed attributes of the domain
// policy, asserting the values as read (a concurrent change gives
// ErrConflict).
func UpdateDomainPasswordPolicy(cur DomainPasswordPolicy, next PasswordPolicy) (*Operation, error) {
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := checkDN(cur.DN); err != nil {
		return nil, err
	}
	props, _ := strconv.ParseInt(cur.raw["pwdProperties"], 10, 64)
	attrs, assert, notes := policyChanges(domainFields(props), cur.raw, cur.Policy, next)
	if len(attrs) == 0 {
		return nil, ErrNoChange
	}
	if next.LockoutDisabled() {
		notes = append(notes, "warning: lockout threshold 0 means accounts never lock out")
	}
	return &Operation{preview: Preview{Summary: "change the domain password policy", Changes: []Change{
		{Type: ChangeModify, DN: cur.DN, Assert: assert, Notes: notes, Attrs: attrs}}}}, nil
}

// ---- fine-grained password policies ----

// PSO is a fine-grained password policy (msDS-PasswordSettings).
type PSO struct {
	DN         string
	GUID       string
	Name       string
	Precedence int
	Policy     PasswordPolicy
	AppliesTo  []string
	raw        map[string]string
}

var psoFieldsList = []policyField{
	{"msDS-MinimumPasswordLength", "minimum length", func(p PasswordPolicy) string { return strconv.Itoa(p.MinLength) }, nil},
	{"msDS-PasswordHistoryLength", "history", func(p PasswordPolicy) string { return strconv.Itoa(p.History) }, nil},
	{"msDS-PasswordComplexityEnabled", "complexity", func(p PasswordPolicy) string { return boolAttr(p.Complexity) }, nil},
	{"msDS-PasswordReversibleEncryptionEnabled", "reversible encryption", func(p PasswordPolicy) string { return boolAttr(p.ReversibleEncryption) }, nil},
	{"msDS-MinimumPasswordAge", "minimum age", func(p PasswordPolicy) string { return encodeInterval(p.MinAge, false) }, func(p PasswordPolicy) string { return showAge(p.MinAge) }},
	{"msDS-MaximumPasswordAge", "maximum age", func(p PasswordPolicy) string { return encodeInterval(p.MaxAge, true) }, func(p PasswordPolicy) string {
		if p.MaxAge == 0 {
			return "never expires"
		}
		return showAge(p.MaxAge)
	}},
	{"msDS-LockoutThreshold", "lockout threshold", func(p PasswordPolicy) string { return strconv.Itoa(p.LockoutThreshold) }, nil},
	{"msDS-LockoutDuration", "lockout duration", func(p PasswordPolicy) string { return encodeInterval(p.LockoutDuration, true) }, func(p PasswordPolicy) string { return showDuration(p.LockoutDuration) }},
	{"msDS-LockoutObservationWindow", "observation window", func(p PasswordPolicy) string { return encodeInterval(p.ObservationWindow, false) }, func(p PasswordPolicy) string { return showDuration(p.ObservationWindow) }},
}

var psoAttrs = append([]string{"cn", "objectGUID", "msDS-PasswordSettingsPrecedence", "msDS-PSOAppliesTo"}, func() []string {
	out := make([]string, len(psoFieldsList))
	for i, f := range psoFieldsList {
		out[i] = f.attr
	}
	return out
}()...)

// PSOContainerDN returns CN=Password Settings Container,CN=System,<domain>.
func (c *Conn) PSOContainerDN() string { return "CN=Password Settings Container,CN=System," + c.baseDN }

func psoFromEntry(e *ldap.Entry) PSO {
	raw := map[string]string{}
	for _, a := range psoAttrs {
		raw[a] = e.GetAttributeValue(a)
	}
	return PSO{DN: e.DN, GUID: attrGUID(e).String(), Name: e.GetAttributeValue("cn"), raw: raw,
		Precedence: int(attrInt64(e, "msDS-PasswordSettingsPrecedence")),
		AppliesTo:  e.GetAttributeValues("msDS-PSOAppliesTo"),
		Policy: PasswordPolicy{
			MinLength:            int(attrInt64(e, "msDS-MinimumPasswordLength")),
			History:              int(attrInt64(e, "msDS-PasswordHistoryLength")),
			Complexity:           strings.EqualFold(raw["msDS-PasswordComplexityEnabled"], "TRUE"),
			ReversibleEncryption: strings.EqualFold(raw["msDS-PasswordReversibleEncryptionEnabled"], "TRUE"),
			MinAge:               decodeInterval(raw["msDS-MinimumPasswordAge"]),
			MaxAge:               decodeInterval(raw["msDS-MaximumPasswordAge"]),
			LockoutThreshold:     int(attrInt64(e, "msDS-LockoutThreshold")),
			LockoutDuration:      decodeInterval(raw["msDS-LockoutDuration"]),
			ObservationWindow:    decodeInterval(raw["msDS-LockoutObservationWindow"]),
		}}
}

// PSOs lists the fine-grained policies by precedence (lowest first: it
// wins). Reading the container needs administrative rights by default.
func (c *Conn) PSOs(ctx context.Context) ([]PSO, error) {
	var out []PSO
	for e, err := range c.Search(ctx, SearchRequest{BaseDN: c.PSOContainerDN(), Scope: ScopeOneLevel,
		Filter: escape.Eq("objectClass", "msDS-PasswordSettings"), Attributes: psoAttrs, SortBy: "msDS-PasswordSettingsPrecedence"}) {
		if err != nil {
			return nil, err
		}
		out = append(out, psoFromEntry(e))
	}
	return out, nil
}

// PSOByDN reads one PSO.
func (c *Conn) PSOByDN(ctx context.Context, dn string) (PSO, error) {
	e, err := c.Get(ctx, dn, psoAttrs...)
	if err != nil {
		return PSO{}, err
	}
	return psoFromEntry(e), nil
}

func checkPrecedence(p int) error {
	if p < 1 || p > math.MaxInt32 {
		return fmt.Errorf("%w: precedence must be a positive number", ErrInvalid)
	}
	return nil
}

// CreatePSO builds the add of a fine-grained policy, optionally applied to
// users or groups (DNs) at once.
func CreatePSO(containerDN, name string, precedence int, p PasswordPolicy, appliesTo []string) (*Operation, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := checkPrecedence(precedence); err != nil {
		return nil, err
	}
	if name = strings.TrimSpace(name); name == "" || len(name) > 64 || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 }) {
		return nil, fmt.Errorf("%w: policy name", ErrInvalid)
	}
	dn, err := escape.ChildDN("CN", name, containerDN)
	if err != nil {
		return nil, err
	}
	attrs := []AttrChange{{Name: "objectClass", Values: []string{"top", "msDS-PasswordSettings"}},
		{Name: "msDS-PasswordSettingsPrecedence", Values: []string{strconv.Itoa(precedence)}}}
	notes := []string{fmt.Sprintf("precedence %d (lower wins)", precedence)}
	for _, f := range psoFieldsList {
		attrs = append(attrs, AttrChange{Name: f.attr, Values: []string{f.value(p)}})
		show := f.show
		if show == nil {
			show = f.value
		}
		notes = append(notes, f.label+": "+show(p))
	}
	for _, t := range appliesTo {
		if err := checkDN(t); err != nil {
			return nil, err
		}
	}
	if len(appliesTo) > 0 {
		attrs = append(attrs, AttrChange{Name: "msDS-PSOAppliesTo", Values: appliesTo})
	}
	return &Operation{preview: Preview{Summary: "create password policy " + name, Changes: []Change{
		{Type: ChangeAdd, DN: dn, Notes: notes, Attrs: attrs}}}}, nil
}

// UpdatePSO replaces the changed settings (and precedence) of a PSO,
// asserting the values as read.
func UpdatePSO(cur PSO, precedence int, next PasswordPolicy) (*Operation, error) {
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := checkPrecedence(precedence); err != nil {
		return nil, err
	}
	attrs, assert, notes := policyChanges(psoFieldsList, cur.raw, cur.Policy, next)
	if precedence != cur.Precedence {
		attrs = append(attrs, AttrChange{Op: ModReplace, Name: "msDS-PasswordSettingsPrecedence", Values: []string{strconv.Itoa(precedence)}})
		a := escape.Eq("msDS-PasswordSettingsPrecedence", strconv.Itoa(cur.Precedence))
		if assert == nil {
			assert = a
		} else {
			assert = escape.And(assert, a)
		}
		notes = append(notes, fmt.Sprintf("precedence: %d -> %d", cur.Precedence, precedence))
	}
	if len(attrs) == 0 {
		return nil, ErrNoChange
	}
	return &Operation{preview: Preview{Summary: "change password policy " + cur.Name, Changes: []Change{
		{Type: ChangeModify, DN: cur.DN, Assert: assert, Notes: notes, Attrs: attrs}}}}, nil
}

// ApplyPSO adds a user or group (DN) to the PSO's msDS-PSOAppliesTo.
func ApplyPSO(pso PSO, targetDN string) (*Operation, error) {
	return psoTarget(pso, targetDN, ModAdd)
}

// UnapplyPSO removes a user or group from msDS-PSOAppliesTo.
func UnapplyPSO(pso PSO, targetDN string) (*Operation, error) {
	return psoTarget(pso, targetDN, ModDelete)
}

func psoTarget(pso PSO, targetDN string, op ModOp) (*Operation, error) {
	if err := checkDN(pso.DN); err != nil {
		return nil, err
	}
	if err := checkDN(targetDN); err != nil {
		return nil, err
	}
	present := false
	for _, t := range pso.AppliesTo {
		if escape.EqualDN(t, targetDN) {
			present = true
		}
	}
	verb := "apply " + pso.Name + " to"
	if op == ModAdd && present {
		return nil, fmt.Errorf("%w: already applied", ErrAlreadyExists)
	}
	if op == ModDelete {
		if !present {
			return nil, fmt.Errorf("%w: not applied", ErrNotFound)
		}
		verb = "stop applying " + pso.Name + " to"
	}
	return &Operation{preview: Preview{Summary: verb + " " + targetDN, Changes: []Change{{Type: ChangeModify, DN: pso.DN,
		Notes: []string{verb + " " + targetDN}, Attrs: []AttrChange{{Op: op, Name: "msDS-PSOAppliesTo", Values: []string{targetDN}}}}}}}, nil
}

// EffectivePolicy is the policy that applies to one user.
type EffectivePolicy struct {
	// PSODN is the resultant PSO (msDS-ResultantPSO); empty = domain policy.
	PSODN  string
	PSO    *PSO // nil when the domain policy applies or the PSO is not readable
	Policy PasswordPolicy
	// PasswordExpires is msDS-UserPasswordExpiryTimeComputed (zero = never).
	PasswordExpires time.Time
	// NeverExpires is set by DONT_EXPIRE_PASSWORD on the account.
	NeverExpires bool
}

// EffectivePasswordPolicy computes the policy that applies to a user: the
// PSO named by the constructed msDS-ResultantPSO (precedence, user over
// group, as the DC resolves it), or the domain's policy.
func (c *Conn) EffectivePasswordPolicy(ctx context.Context, userDN string) (EffectivePolicy, error) {
	e, err := c.Get(ctx, userDN, "msDS-ResultantPSO", "msDS-UserPasswordExpiryTimeComputed", "userAccountControl")
	if err != nil {
		return EffectivePolicy{}, err
	}
	ep := EffectivePolicy{PSODN: e.GetAttributeValue("msDS-ResultantPSO"),
		NeverExpires: UAC(uint32(attrInt64(e, "userAccountControl"))).Has(UACDontExpirePassword)}
	if ft := FileTime(attrInt64(e, "msDS-UserPasswordExpiryTimeComputed")); ft > 0 && ft != Never {
		ep.PasswordExpires = ft.Time()
	}
	if ep.PSODN != "" {
		pso, perr := c.PSOByDN(ctx, ep.PSODN)
		if perr == nil {
			ep.PSO, ep.Policy = &pso, pso.Policy
			return ep, nil
		}
		if !errors.Is(perr, ErrNotFound) && !errors.Is(perr, ErrAccessDenied) {
			return ep, perr
		}
	}
	d, err := c.DomainPasswordPolicy(ctx)
	if err != nil {
		return ep, err
	}
	if ep.PSODN == "" {
		ep.Policy = d.Policy
	}
	return ep, nil
}
