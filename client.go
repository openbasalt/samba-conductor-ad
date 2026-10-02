package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config describes how to reach the domain. It holds no credentials.
type Config struct {
	// Realm is the Kerberos realm / DNS domain, e.g. "LAB.CONDUCTOR.TEST".
	Realm string
	// DCs lists DC host names to use instead of DNS SRV discovery.
	DCs []string
	// Preferred host names are tried first (e.g. the local DC).
	Preferred []string
	// Resolver used for SRV discovery and for resolving DC names. Nil means
	// the system resolver. See NewDNSResolver.
	Resolver Resolver
	// RootCAs pins the CA(s) that may sign the DCs' LDAPS certificates
	// (normally only the domain CA). Required: there is no default trust in
	// the system pool. See CertPoolFromPEM.
	RootCAs *x509.CertPool
	// LDAPSPort defaults to 636.
	LDAPSPort int
	// DialTimeout per DC attempt; defaults to 5s.
	DialTimeout time.Duration
	// InsecureSkipTLSVerifyForTestsOnly disables certificate verification.
	// It exists for throwaway test setups only; never set it in production.
	InsecureSkipTLSVerifyForTestsOnly bool
}

// CertPoolFromPEM builds a pool holding only the given PEM certificates.
func CertPoolFromPEM(pemData []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("ad: no certificates found in PEM data")
	}
	return pool, nil
}

func (c *Config) validate() error {
	if !validRealm(c.Realm) {
		return fmt.Errorf("ad: invalid realm %q", c.Realm)
	}
	if c.RootCAs == nil && !c.InsecureSkipTLSVerifyForTestsOnly {
		return errors.New("ad: Config.RootCAs is required (pin the domain CA)")
	}
	for _, h := range append(append([]string(nil), c.DCs...), c.Preferred...) {
		if !validHost(h) {
			return fmt.Errorf("ad: invalid DC host %q", h)
		}
	}
	return nil
}

func (c *Config) port() int {
	if c.LDAPSPort > 0 {
		return c.LDAPSPort
	}
	return 636
}

func (c *Config) timeout() time.Duration {
	if c.DialTimeout > 0 {
		return c.DialTimeout
	}
	return 5 * time.Second
}

// domainControllers returns the candidate DCs in the order they are tried.
func (c *Config) domainControllers(ctx context.Context) ([]DC, error) {
	if len(c.DCs) > 0 {
		dcs := make([]DC, 0, len(c.DCs))
		for _, h := range c.DCs {
			dcs = append(dcs, DC{Host: strings.ToLower(strings.TrimSuffix(h, "."))})
		}
		return orderPreferred(dcs, c.Preferred), nil
	}
	return DiscoverDCs(ctx, c.Resolver, c.Realm, c.Preferred)
}

func (c *Config) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            c.RootCAs,
		ServerName:         serverName,
		InsecureSkipVerify: c.InsecureSkipTLSVerifyForTestsOnly, //nolint:gosec // explicit, loudly named test-only option
	}
}

// Authenticator binds an LDAP connection. See KerberosAuth and SimpleAuth.
type Authenticator interface {
	bind(ctx context.Context, l *ldap.Conn, dc DC) error
	mechanism() string
}

// Conn is an authenticated LDAPS connection to one DC. It is not safe for
// concurrent use by multiple goroutines.
type Conn struct {
	l           *ldap.Conn
	dc          DC
	baseDN      string
	configDN    string
	forestDN    string
	dnsHostName string
	functional  int
	realm       string
	dnsDomain   string
}

// DC returns the domain controller this connection is bound to.
func (c *Conn) DC() DC { return c.dc }

// BaseDN returns the domain's defaultNamingContext, e.g. "DC=lab,DC=conductor,DC=test".
func (c *Conn) BaseDN() string { return c.baseDN }

// ConfigurationDN returns the configurationNamingContext.
func (c *Conn) ConfigurationDN() string { return c.configDN }

// ForestDN returns the rootDomainNamingContext (the forest root domain's
// DN; the domain's own DN in a single-domain forest).
func (c *Conn) ForestDN() string { return c.forestDN }

// DCHostName returns the DNS host name of the DC this connection is bound
// to, as the DC reports it (RootDSE dnsHostName).
func (c *Conn) DCHostName() string { return c.dnsHostName }

// DNSDomain returns the domain's DNS name (lowercase realm).
func (c *Conn) DNSDomain() string { return c.dnsDomain }

// DomainFunctionality returns the domain functional level (7 = 2016).
func (c *Conn) DomainFunctionality() int { return c.functional }

// Close closes the connection.
func (c *Conn) Close() error { return c.l.Close() }

// WhoAmI returns the bound identity as reported by the DC ("u:LAB\\user").
func (c *Conn) WhoAmI(ctx context.Context) (string, error) {
	var out string
	err := c.guard(ctx, func() error {
		res, err := c.l.WhoAmI(nil)
		if err != nil {
			return err
		}
		out = res.AuthzID
		return nil
	})
	return out, err
}

// FailoverError reports that no DC could be reached; Attempts holds the
// per-DC errors in order.
type FailoverError struct {
	Attempts []DCAttempt
}

// DCAttempt is one failed attempt of a failover sequence.
type DCAttempt struct {
	DC  DC
	Err error
}

func (e *FailoverError) Error() string {
	parts := make([]string, 0, len(e.Attempts))
	for _, a := range e.Attempts {
		parts = append(parts, a.DC.Host+": "+a.Err.Error())
	}
	return "ad: no domain controller reachable (" + strings.Join(parts, "; ") + ")"
}

// Unwrap exposes the individual attempt errors.
func (e *FailoverError) Unwrap() []error {
	out := make([]error, 0, len(e.Attempts))
	for _, a := range e.Attempts {
		out = append(out, a.Err)
	}
	return out
}

// Connect opens an LDAPS connection to the first reachable DC and binds it
// with auth. It fails over to the next DC only on connectivity problems
// (dial, TLS handshake, connection reset): a credentials or authorization
// error is returned at once, so a wrong password is never sprayed across DCs
// (which would multiply bad-password counts towards a lockout).
func Connect(ctx context.Context, cfg Config, auth Authenticator) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, errors.New("ad: nil Authenticator")
	}
	dcs, err := cfg.domainControllers(ctx)
	if err != nil {
		return nil, err
	}
	fe := &FailoverError{}
	for _, dc := range dcs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l, err := dialLDAPS(ctx, &cfg, dc)
		if err != nil {
			fe.Attempts = append(fe.Attempts, DCAttempt{DC: dc, Err: err})
			continue
		}
		if err := bindWithContext(ctx, l, func() error { return auth.bind(ctx, l, dc) }); err != nil {
			_ = l.Close()
			if isConnectivityError(err) {
				fe.Attempts = append(fe.Attempts, DCAttempt{DC: dc, Err: err})
				continue
			}
			return nil, err
		}
		c := &Conn{l: l, dc: dc, realm: strings.ToUpper(cfg.Realm), dnsDomain: strings.ToLower(cfg.Realm)}
		if err := c.readRootDSE(ctx); err != nil {
			_ = l.Close()
			return nil, err
		}
		return c, nil
	}
	return nil, fe
}

func dialLDAPS(ctx context.Context, cfg *Config, dc DC) (*ldap.Conn, error) {
	d := dialer(cfg.Resolver, cfg.timeout())
	dctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	raw, err := d.DialContext(dctx, "tcp", net.JoinHostPort(dc.Host, strconv.Itoa(cfg.port())))
	if err != nil {
		return nil, &connectivityError{err}
	}
	tc := tls.Client(raw, cfg.tlsConfig(dc.Host))
	if err := tc.HandshakeContext(dctx); err != nil {
		_ = raw.Close()
		var verr *tls.CertificateVerificationError
		if errors.As(err, &verr) {
			// A certificate that does not chain to the pinned CA is a hard
			// failure on that DC, but other DCs may still be fine.
			return nil, &connectivityError{fmt.Errorf("ad: TLS certificate of %s rejected: %w", dc.Host, err)}
		}
		return nil, &connectivityError{err}
	}
	l := ldap.NewConn(tc, true)
	l.Start()
	l.SetTimeout(cfg.timeout() * 6)
	return l, nil
}

type connectivityError struct{ err error }

func (e *connectivityError) Error() string { return e.err.Error() }
func (e *connectivityError) Unwrap() error { return e.err }

func isConnectivityError(err error) bool {
	var ce *connectivityError
	if errors.As(err, &ce) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	return ldap.IsErrorWithCode(err, ldap.ErrorNetwork) || ldap.IsErrorWithCode(err, ldap.LDAPResultServerDown) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) || ldap.IsErrorWithCode(err, ldap.LDAPResultBusy)
}

// bindWithContext runs fn and closes the connection if ctx ends first.
func bindWithContext(ctx context.Context, l *ldap.Conn, fn func() error) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-done:
		}
	}()
	err := fn()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// guard runs fn; if ctx is cancelled first the connection is closed (the
// only way to interrupt go-ldap's synchronous calls) and ctx.Err() returned.
func (c *Conn) guard(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return bindWithContext(ctx, c.l, fn)
}

func (c *Conn) readRootDSE(ctx context.Context) error {
	return c.guard(ctx, func() error {
		res, err := c.l.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", []string{"defaultNamingContext", "configurationNamingContext", "rootDomainNamingContext",
				"dnsHostName", "domainFunctionality"}, nil))
		if err != nil {
			return fmt.Errorf("ad: reading RootDSE: %w", err)
		}
		if len(res.Entries) != 1 {
			return errors.New("ad: RootDSE not returned")
		}
		e := res.Entries[0]
		c.baseDN = e.GetAttributeValue("defaultNamingContext")
		c.configDN = e.GetAttributeValue("configurationNamingContext")
		c.dnsHostName = strings.ToLower(e.GetAttributeValue("dnsHostName"))
		c.forestDN = e.GetAttributeValue("rootDomainNamingContext")
		if c.forestDN == "" {
			c.forestDN = e.GetAttributeValue("defaultNamingContext")
		}
		c.functional, _ = strconv.Atoi(e.GetAttributeValue("domainFunctionality"))
		if c.baseDN == "" {
			return errors.New("ad: RootDSE has no defaultNamingContext")
		}
		return nil
	})
}

// simpleAuth binds with a password over the TLS connection.
type simpleAuth struct {
	username string
	password string
}

// SimpleAuth returns an Authenticator for an LDAP simple bind over TLS, the
// explicit fallback when Kerberos is unavailable. username may be a UPN
// ("user@domain"), "DOMAIN\\user", a bare sAMAccountName (sent as
// "user@realm"), or a DN. The password is used for the bind only.
func SimpleAuth(username, password string) Authenticator {
	return &simpleAuth{username: username, password: password}
}

func (a *simpleAuth) mechanism() string { return "simple" }

func (a *simpleAuth) bind(_ context.Context, l *ldap.Conn, dc DC) error {
	if a.password == "" {
		// An empty password would be an unauthenticated bind (RFC 4513 5.1.2):
		// it "succeeds" without proving anything.
		return &AuthError{Reason: ReasonInvalidCredentials, Mechanism: "ldap", Code: "empty password"}
	}
	name := a.username
	if !strings.Contains(name, "@") && !strings.Contains(name, "\\") && !strings.Contains(name, "=") {
		// Bare sAMAccountName: AD accepts the implicit UPN sam@dnsdomain.
		name = name + "@" + domainOfHost(dc.Host)
	}
	err := l.Bind(name, a.password)
	return ClassifyBindError(err)
}

// domainOfHost returns the DNS domain of a DC host name (everything after
// the first label).
func domainOfHost(host string) string {
	if _, rest, ok := strings.Cut(host, "."); ok {
		return rest
	}
	return host
}
