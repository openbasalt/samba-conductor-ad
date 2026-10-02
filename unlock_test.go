package ad

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestUnlockUserOnDCsPreview(t *testing.T) {
	op, err := UnlockUserOnDCs("CN=u,DC=lab,DC=test", []string{"dc1.lab.test", "dc2.lab.test"})
	if err != nil {
		t.Fatal(err)
	}
	if got := op.DCs(); len(got) != 2 || got[1] != "dc2.lab.test" {
		t.Fatalf("DCs = %v", got)
	}
	p := op.Preview().String()
	for _, want := range []string{"every domain controller", "dc1.lab.test, dc2.lab.test", "lockoutTime: 0"} {
		if !strings.Contains(p, want) {
			t.Errorf("preview lacks %q:\n%s", want, p)
		}
	}
	if _, err := UnlockUserOnDCs("CN=u,DC=lab,DC=test", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("no DCs: %v", err)
	}
	single, _ := UnlockUser("CN=u,DC=lab,DC=test")
	if single.DCs() != nil {
		t.Error("a single-connection unlock names no DCs")
	}
}

// A DC that cannot be reached is reported with its error and does not stop
// the others from being tried.
func TestApplyOnDCsReportsEveryDC(t *testing.T) {
	op, _ := UnlockUserOnDCs("CN=u,DC=lab,DC=test", []string{"a", "b", "c"})
	var tried []string
	res := ApplyOnDCs(context.Background(), op, func(_ context.Context, host string) (*Conn, error) {
		tried = append(tried, host)
		return nil, errors.New("down " + host)
	})
	if len(res) != 3 || len(tried) != 3 {
		t.Fatalf("results %d, tried %v", len(res), tried)
	}
	for i, r := range res {
		if r.Err == nil || r.Host != tried[i] {
			t.Errorf("result %d: %+v", i, r)
		}
	}
}
