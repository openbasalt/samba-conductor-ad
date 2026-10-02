package ad

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"
)

// DC is a domain controller endpoint.
type DC struct {
	// Host is the DC's DNS name (also the TLS server name and the Kerberos
	// service host).
	Host string
	// Priority and Weight come from the SRV record (0 when configured).
	Priority uint16
	Weight   uint16
}

// Resolver is the subset of *net.Resolver used for discovery and dialing.
type Resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// NewDNSResolver returns a resolver that queries the given DNS servers
// ("ip" or "ip:port") instead of the system configuration. Queries go over
// TCP so that a server that is down is detected at connect time and the next
// one is tried (with UDP a dead server only shows up as a read timeout).
func NewDNSResolver(servers ...string) *net.Resolver {
	addrs := make([]string, 0, len(servers))
	for _, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		addrs = append(addrs, s)
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			var lastErr error
			for _, a := range addrs {
				c, err := d.DialContext(ctx, "tcp", a)
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = errors.New("ad: no DNS servers configured")
			}
			return nil, lastErr
		},
	}
}

var (
	realmRE    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))+$`)
	hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*\.?$`)
)

// validRealm reports whether realm is a DNS-style AD realm (no spaces, no
// krb5.conf syntax characters).
func validRealm(realm string) bool { return len(realm) <= 253 && realmRE.MatchString(realm) }

func validHost(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return true
	}
	return len(h) <= 253 && hostnameRE.MatchString(h)
}

// DiscoverDCs finds the domain's DCs through DNS SRV records
// (_ldap._tcp.dc._msdcs.<realm>), ordered: hosts listed in preferred first
// (in that order), then by SRV priority and weight as returned by the
// resolver.
func DiscoverDCs(ctx context.Context, r Resolver, realm string, preferred []string) ([]DC, error) {
	return discover(ctx, r, "ldap", "dc._msdcs."+strings.ToLower(realm), realm, preferred)
}

// DiscoverKDCs finds the realm's KDCs through _kerberos._tcp.<realm>.
func DiscoverKDCs(ctx context.Context, r Resolver, realm string, preferred []string) ([]DC, error) {
	return discover(ctx, r, "kerberos", strings.ToLower(realm), realm, preferred)
}

func discover(ctx context.Context, r Resolver, service, name, realm string, preferred []string) ([]DC, error) {
	if !validRealm(realm) {
		return nil, fmt.Errorf("ad: invalid realm %q", realm)
	}
	if r == nil {
		r = net.DefaultResolver
	}
	_, srvs, err := r.LookupSRV(ctx, service, "tcp", name)
	if err != nil {
		return nil, fmt.Errorf("ad: SRV lookup _%s._tcp.%s: %w", service, name, err)
	}
	dcs := make([]DC, 0, len(srvs))
	seen := map[string]bool{}
	for _, s := range srvs {
		host := strings.TrimSuffix(strings.ToLower(s.Target), ".")
		if !validHost(host) || seen[host] {
			continue
		}
		seen[host] = true
		dcs = append(dcs, DC{Host: host, Priority: s.Priority, Weight: s.Weight})
	}
	if len(dcs) == 0 {
		return nil, fmt.Errorf("ad: no DCs found for %s", realm)
	}
	return orderPreferred(dcs, preferred), nil
}

// orderPreferred moves the preferred hosts to the front, keeping the
// resolver's order (priority, then weighted random) for the rest.
func orderPreferred(dcs []DC, preferred []string) []DC {
	rank := func(h string) int {
		for i, p := range preferred {
			if strings.EqualFold(strings.TrimSuffix(p, "."), h) {
				return i
			}
		}
		return len(preferred)
	}
	out := slices.Clone(dcs)
	slices.SortStableFunc(out, func(a, b DC) int { return rank(a.Host) - rank(b.Host) })
	return out
}

// dialer builds a net.Dialer that resolves names with r (when given).
func dialer(r Resolver, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if nr, ok := r.(*net.Resolver); ok {
		d.Resolver = nr
	}
	return d
}
