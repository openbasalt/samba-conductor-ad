package helper

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var caller = Caller{User: "LAB\\admin", SID: "S-1-5-21-1-2-3-1105", SessionID: "sess-1"}

func TestRoundTrip(t *testing.T) {
	req, err := NewRequest("req-00000001", OpDomainBackupOnline, caller, BackupOnlineParams{Label: "nightly"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, req); err != nil {
		t.Fatal(err)
	}
	got, err := NewReader(&buf).ReadRequest()
	if err != nil {
		t.Fatal(err)
	}
	p, err := got.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if bp, ok := p.(*BackupOnlineParams); !ok || bp.Label != "nightly" {
		t.Fatalf("params %#v", p)
	}
}

func TestRejects(t *testing.T) {
	base := func() Request {
		r, _ := NewRequest("req-00000001", OpPing, caller, nil)
		return r
	}
	cases := map[string]func(*Request){
		"unknown op":     func(r *Request) { r.Op = "exec" },
		"version":        func(r *Request) { r.Version = 99 },
		"bad id":         func(r *Request) { r.ID = "x" },
		"bad caller sid": func(r *Request) { r.Caller.SID = "admin" },
		"unknown field":  func(r *Request) { r.Op = OpDomainBackupOnline; r.Params = json.RawMessage(`{"label":"a","cmd":"rm"}`) },
		"invalid label":  func(r *Request) { r.Op = OpDomainBackupOnline; r.Params = json.RawMessage(`{"label":"../etc"}`) },
		"unit":           func(r *Request) { r.Op = OpServiceStatus; r.Params = json.RawMessage(`{"unit":"sshd.service"}`) },
		"trailing":       func(r *Request) { r.Params = json.RawMessage(`{} {}`) },
	}
	for name, mutate := range cases {
		r := base()
		mutate(&r)
		_, err := r.Decode()
		var he *Error
		if !errors.As(err, &he) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestReaderLimits(t *testing.T) {
	long := `{"version":1,"id":"` + strings.Repeat("a", MaxMessageSize) + `"}` + "\n"
	if _, err := NewReader(strings.NewReader(long)).ReadRequest(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	if _, err := NewReader(strings.NewReader(`{"version":1,"evil":true}` + "\n")).ReadRequest(); err == nil {
		t.Fatal("unknown envelope field accepted")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"version":1,"id":"req-00000001","op":"ping","caller":{"user":"a","sid":"S-1-5-21-1-2-3-4","session_id":"s"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := NewReader(bytes.NewReader(append(b, '\n'))).ReadRequest()
		if err != nil {
			return
		}
		p, err := req.Decode()
		if err != nil {
			return
		}
		if _, ok := Allowlist[req.Op]; !ok || p.Validate() != nil {
			t.Fatalf("decoded a request that is not allowlisted/valid: %+v", req)
		}
	})
}
