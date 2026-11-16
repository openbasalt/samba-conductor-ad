package ad

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// labReverseZone is the reverse zone the lab seeds for its network: the
// /24 of the first DC address of AD_LAB_DNS ("10.0.0.10" gives
// "0.0.10.in-addr.arpa"). The lab tests read their network from that
// variable only, never from a hard-coded subnet.
func labReverseZone(dcs []string) (string, error) {
	if len(dcs) == 0 || strings.TrimSpace(dcs[0]) == "" {
		return "", fmt.Errorf("AD_LAB_DNS names no DC address")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(dcs[0]))
	if err != nil || !a.Is4() {
		return "", fmt.Errorf("AD_LAB_DNS: %q is not an IPv4 address", dcs[0])
	}
	b := a.As4()
	return fmt.Sprintf("%d.%d.%d.in-addr.arpa", b[2], b[1], b[0]), nil
}

func TestLabReverseZone(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.10": "2.0.192.in-addr.arpa", " 198.51.100.7": "100.51.198.in-addr.arpa"} {
		if got, err := labReverseZone([]string{in, "203.0.113.1"}); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range [][]string{nil, {""}, {"dc1.example.test"}, {"2001:db8::1"}} {
		if got, err := labReverseZone(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}
