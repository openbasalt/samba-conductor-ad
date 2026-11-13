package ad

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-krb5/krb5/types"
)

// Errors of the verification that follows a Kerberos sign-in.
var (
	// ErrKDCNotVerified: the ticket from the AS exchange could not be used
	// against a domain controller, so the KDC answer (and with it the
	// password) is not proven. It is an infrastructure or attack signal,
	// never "wrong password": log it as such and show a generic error.
	ErrKDCNotVerified = errors.New("ad: the KDC answer could not be verified with a domain controller")
	// ErrIdentityMismatch: the domain controller bound the ticket as an
	// account other than the one that signed in. It also matches
	// ErrKDCNotVerified.
	ErrIdentityMismatch = errors.New("ad: the domain controller bound a different account")
)

// VerifyError is a failed sign-in verification. It matches
// ErrKDCNotVerified (and ErrIdentityMismatch when Mismatch is set) with
// errors.Is.
//
// It deliberately does not unwrap to Cause: the verifying bind may fail
// with an LDAP result 49, and a caller must never read that as a password
// refusal, much less as a "verified" expired password. Cause is for logs
// only.
type VerifyError struct {
	Mismatch bool
	Cause    error
}

func (e *VerifyError) Error() string {
	msg := ErrKDCNotVerified.Error()
	if e.Mismatch {
		msg = ErrIdentityMismatch.Error()
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Is matches ErrKDCNotVerified, and ErrIdentityMismatch for a mismatch.
func (e *VerifyError) Is(target error) bool {
	return target == ErrKDCNotVerified || (e.Mismatch && target == ErrIdentityMismatch)
}

// verifyFailure wraps err as a VerifyError, except a context error, which
// is returned as is (still a failure: the caller never treats it as a
// success).
func verifyFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return &VerifyError{Cause: err}
}

// SignInVerified signs in like SignIn and then proves the answer came from
// the real domain (see Session.Verify) before returning the Session. Use it
// wherever a sign-in decides access on its own, without binding LDAP with
// the ticket afterwards. Refusals of the AS exchange are *AuthError values,
// as with SignIn; a failed verification matches ErrKDCNotVerified and is
// never an *AuthError.
func SignInVerified(ctx context.Context, cfg Config, username, password string) (*Session, error) {
	s, err := SignIn(ctx, cfg, username, password)
	if err != nil {
		return nil, err
	}
	if err := s.Verify(ctx, cfg); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Verify proves that the session's ticket was issued by a KDC that holds
// the domain's keys: it obtains a service ticket for ldap/<dc> and binds
// LDAPS (CA-pinned, with channel bindings) with SASL GSSAPI. A KDC that
// forged the AS reply cannot issue a service ticket the domain controller
// accepts, because it does not know the DC's key. It then asks the DC who
// it bound (WhoAmI) and requires the sAMAccountName to be the name that
// signed in, so the caller never derives an identity from typed input
// alone. On success Account returns the confirmed name.
//
// Every failure matches ErrKDCNotVerified (a context error is returned as
// is) and must be treated as "not signed in".
func (s *Session) Verify(ctx context.Context, cfg Config) error {
	if s == nil {
		return &VerifyError{Cause: ErrSessionClosed}
	}
	conn, err := Connect(ctx, cfg, KerberosAuth(s))
	if err != nil {
		return verifyFailure(ctx, err)
	}
	defer func() { _ = conn.Close() }()
	account, err := conn.BoundAccount(ctx)
	if err != nil {
		return verifyFailure(ctx, err)
	}
	if !strings.EqualFold(account, s.name) {
		return &VerifyError{Mismatch: true, Cause: fmt.Errorf("signed in as %q, bound as %q", s.name, account)}
	}
	s.mu.Lock()
	s.account = account
	s.mu.Unlock()
	return nil
}

// BoundAccount returns the sAMAccountName this connection is bound as,
// from the DC's WhoAmI answer ("u:DOMAIN\\name"). It is the identity the
// directory authenticated, not what a user typed.
func (c *Conn) BoundAccount(ctx context.Context) (string, error) {
	who, err := c.WhoAmI(ctx)
	if err != nil {
		return "", err
	}
	return accountFromAuthzID(who)
}

// accountFromAuthzID parses an RFC 4532 authzId of the "u:" form, as AD and
// Samba return it ("u:DOMAIN\\name").
func accountFromAuthzID(who string) (string, error) {
	rest, ok := strings.CutPrefix(who, "u:")
	if !ok {
		return "", fmt.Errorf("ad: unexpected WhoAmI answer %q", who)
	}
	if _, name, ok := strings.Cut(rest, "\\"); ok {
		rest = name
	}
	if rest == "" || strings.ContainsAny(rest, "\\@") {
		return "", fmt.Errorf("ad: unexpected WhoAmI answer %q", who)
	}
	return rest, nil
}

// confirmPasswordChange signs in with the new password at the KDC that
// performed the change (it is the only one sure to know it before
// replication) and verifies that session against a DC.
func (k *kdcSet) confirmPasswordChange(ctx context.Context, cfg Config, cname types.PrincipalName, newPassword string) error {
	if k.answered != "" {
		k.hosts = pinFirst(k.answered, k.hosts)
	}
	rep, err := k.asExchange(ctx, cname, newPassword, false)
	if err != nil {
		return verifyFailure(ctx, fmt.Errorf("signing in with the new password: %w", err))
	}
	s, err := k.newSession(rep, cname)
	if err != nil {
		return verifyFailure(ctx, err)
	}
	defer s.Close()
	return s.Verify(ctx, cfg)
}

// pinFirst returns hosts with first moved to the front.
func pinFirst(first string, hosts []string) []string {
	out := make([]string, 0, len(hosts))
	out = append(out, first)
	for _, h := range hosts {
		if h != first {
			out = append(out, h)
		}
	}
	return out
}
