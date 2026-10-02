package ad

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Reason classifies why a sign-in or bind was refused.
type Reason int

// Sign-in failure reasons. Only ReasonPasswordExpired and
// ReasonPasswordMustChange prove that the password was correct; every other
// reason, and in particular a generic LDAP result 49 without a recognized
// sub-code, must be treated as "wrong credentials".
const (
	ReasonUnknown Reason = iota
	// ReasonInvalidCredentials: wrong password or unknown user (AD 52e/525,
	// KDC_ERR_PREAUTH_FAILED, KDC_ERR_C_PRINCIPAL_UNKNOWN, generic 49).
	ReasonInvalidCredentials
	// ReasonPasswordExpired: AD 532 / KDC_ERR_KEY_EXPIRED (STATUS_PASSWORD_EXPIRED).
	ReasonPasswordExpired
	// ReasonPasswordMustChange: AD 773 / KDC_ERR_KEY_EXPIRED (STATUS_PASSWORD_MUST_CHANGE),
	// i.e. pwdLastSet=0.
	ReasonPasswordMustChange
	// ReasonAccountLocked: AD 775 / STATUS_ACCOUNT_LOCKED_OUT.
	ReasonAccountLocked
	// ReasonAccountDisabled: AD 533 / STATUS_ACCOUNT_DISABLED.
	ReasonAccountDisabled
	// ReasonAccountExpired: AD 701 / STATUS_ACCOUNT_EXPIRED.
	ReasonAccountExpired
	// ReasonLogonHours: AD 530 / STATUS_INVALID_LOGON_HOURS.
	ReasonLogonHours
	// ReasonWorkstationRestricted: AD 531 / STATUS_INVALID_WORKSTATION.
	ReasonWorkstationRestricted
	// ReasonAccountRestricted: the KDC revoked the client without saying why.
	ReasonAccountRestricted
	// ReasonClockSkew: KRB_AP_ERR_SKEW, the clocks differ too much.
	ReasonClockSkew
)

var reasonNames = map[Reason]string{
	ReasonUnknown:               "unknown",
	ReasonInvalidCredentials:    "invalid credentials",
	ReasonPasswordExpired:       "password expired",
	ReasonPasswordMustChange:    "password must be changed",
	ReasonAccountLocked:         "account locked",
	ReasonAccountDisabled:       "account disabled",
	ReasonAccountExpired:        "account expired",
	ReasonLogonHours:            "outside allowed logon hours",
	ReasonWorkstationRestricted: "workstation not allowed",
	ReasonAccountRestricted:     "account restricted",
	ReasonClockSkew:             "clock skew too great",
}

func (r Reason) String() string {
	if s, ok := reasonNames[r]; ok {
		return s
	}
	return fmt.Sprintf("reason(%d)", int(r))
}

// Sentinel errors, matched with errors.Is against an *AuthError.
var (
	ErrInvalidCredentials = errors.New("ad: invalid credentials")
	ErrPasswordExpired    = errors.New("ad: password expired")
	ErrPasswordMustChange = errors.New("ad: password must be changed")
	ErrAccountLocked      = errors.New("ad: account locked")
	ErrAccountDisabled    = errors.New("ad: account disabled")
	ErrAccountExpired     = errors.New("ad: account expired")
	ErrAccountRestricted  = errors.New("ad: account restricted")
	ErrClockSkew          = errors.New("ad: clock skew too great")
)

var reasonSentinel = map[Reason]error{
	ReasonInvalidCredentials:    ErrInvalidCredentials,
	ReasonPasswordExpired:       ErrPasswordExpired,
	ReasonPasswordMustChange:    ErrPasswordMustChange,
	ReasonAccountLocked:         ErrAccountLocked,
	ReasonAccountDisabled:       ErrAccountDisabled,
	ReasonAccountExpired:        ErrAccountExpired,
	ReasonLogonHours:            ErrAccountRestricted,
	ReasonWorkstationRestricted: ErrAccountRestricted,
	ReasonAccountRestricted:     ErrAccountRestricted,
	ReasonClockSkew:             ErrClockSkew,
}

// AuthError is a refused sign-in or bind, classified.
type AuthError struct {
	Reason Reason
	// Mechanism is "ldap" (an LDAP bind, simple or SASL) or "kerberos" (KDC).
	Mechanism string
	// Code is the raw diagnostic: the AD sub-code ("52e", "773"…) for LDAP,
	// or "KDC_ERR_…[/0xC0000…]" for Kerberos. Safe to log; never shown to the
	// end user verbatim (it reveals account state).
	Code string
	Err  error
	// verified is set when the refusal came after the directory checked the
	// password (LDAP 532/773; Kerberos KEY_EXPIRED after pre-authentication).
	verified bool
}

func (e *AuthError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("ad: %s sign-in refused: %s (%s)", e.Mechanism, e.Reason, e.Code)
	}
	return fmt.Sprintf("ad: %s sign-in refused: %s", e.Mechanism, e.Reason)
}

func (e *AuthError) Unwrap() error { return e.Err }

// Is matches the sentinel error of the reason.
func (e *AuthError) Is(target error) bool {
	return reasonSentinel[e.Reason] == target
}

// PasswordVerified reports whether the directory confirmed the password was
// correct before refusing (expired or must-change). Only then may a caller
// offer a password change with that old password.
func (e *AuthError) PasswordVerified() bool {
	return e.verified && (e.Reason == ReasonPasswordExpired || e.Reason == ReasonPasswordMustChange)
}

// adSubCodes maps the "data XXX" field of AD's AcceptSecurityContext
// diagnostic message to a reason.
var adSubCodes = map[string]Reason{
	"525": ReasonInvalidCredentials, // user not found: reported like a bad password
	"52e": ReasonInvalidCredentials,
	"530": ReasonLogonHours,
	"531": ReasonWorkstationRestricted,
	"532": ReasonPasswordExpired,
	"533": ReasonAccountDisabled,
	"701": ReasonAccountExpired,
	"773": ReasonPasswordMustChange,
	"775": ReasonAccountLocked,
}

var dataRE = regexp.MustCompile(`(?i)\bdata ([0-9a-f]{1,8})\b`)

// ClassifyBindError turns an LDAP bind error into an *AuthError when it is a
// credentials failure (result 49). A 49 whose diagnostic has no known
// sub-code is ReasonInvalidCredentials, never "maybe expired". Other errors
// are returned unchanged.
func ClassifyBindError(err error) error {
	if err == nil {
		return nil
	}
	var le *ldap.Error
	if !errors.As(err, &le) || le.ResultCode != ldap.LDAPResultInvalidCredentials {
		return err
	}
	msg := ""
	if le.Err != nil {
		msg = le.Err.Error()
	}
	ae := &AuthError{Reason: ReasonInvalidCredentials, Mechanism: "ldap", Err: err}
	if m := dataRE.FindStringSubmatch(msg); m != nil {
		code := strings.ToLower(strings.TrimLeft(m[1], "0"))
		ae.Code = code
		if r, ok := adSubCodes[code]; ok {
			ae.Reason = r
			// AD reports 532/773 only after validating the password.
			ae.verified = r == ReasonPasswordExpired || r == ReasonPasswordMustChange
		}
	}
	return ae
}

// Errors of write operations.
var (
	// ErrPasswordPolicy: the new password violates the domain or
	// fine-grained policy (length, complexity, history, minimum age).
	ErrPasswordPolicy = errors.New("ad: password does not satisfy the password policy")
	// ErrWrongPassword: the old password given for a self-service change is wrong.
	ErrWrongPassword = errors.New("ad: old password is wrong")
	// ErrAccessDenied: the directory refused the operation for this identity.
	ErrAccessDenied = errors.New("ad: access denied")
	// ErrNotFound: no such object.
	ErrNotFound = errors.New("ad: object not found")
	// ErrAlreadyExists: an object with that name already exists.
	ErrAlreadyExists = errors.New("ad: object already exists")
	// ErrConflict: the object changed since it was read (an RFC 4528
	// assertion or a delete of a specific value did not match).
	ErrConflict = errors.New("ad: object changed since it was read")
	// ErrNoChange: the operation would not change anything.
	ErrNoChange = errors.New("ad: nothing to change")
	// ErrProtectedObject: the library refuses to build the operation because
	// it would break the domain (e.g. disabling a domain controller).
	ErrProtectedObject = errors.New("ad: protected object")
)

// classifyWriteError maps LDAP result codes and AD's WERROR prefixes of write
// operations to the sentinel errors above, keeping the original as cause.
func classifyWriteError(err error) error {
	if err == nil {
		return nil
	}
	var le *ldap.Error
	if !errors.As(err, &le) {
		return err
	}
	msg := ""
	if le.Err != nil {
		msg = strings.ToUpper(le.Err.Error())
	}
	switch {
	case strings.HasPrefix(msg, "00000056"):
		return fmt.Errorf("%w: %w", ErrWrongPassword, err)
	case strings.HasPrefix(msg, "0000052D"):
		return fmt.Errorf("%w: %w", ErrPasswordPolicy, err)
	}
	switch le.ResultCode {
	case ldap.LDAPResultInsufficientAccessRights:
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	case ldap.LDAPResultNoSuchObject:
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case ldap.LDAPResultEntryAlreadyExists:
		return fmt.Errorf("%w: %w", ErrAlreadyExists, err)
	case ldap.LDAPResultNoSuchAttribute, ldap.LDAPResultAssertionFailed:
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case ldap.LDAPResultConstraintViolation:
		if strings.Contains(msg, "PASSWORD") {
			return fmt.Errorf("%w: %w", ErrPasswordPolicy, err)
		}
	}
	return err
}
