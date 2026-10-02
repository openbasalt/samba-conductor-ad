package helper

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// fakeHelper answers each connection with respond(req).
func fakeHelper(t *testing.T, respond func(Request) Response) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "h.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				req, err := NewReader(c).ReadRequest()
				if err != nil {
					return
				}
				_ = WriteMessage(c, respond(req))
			}()
		}
	}()
	return path
}

func TestCallRoundTrip(t *testing.T) {
	path := fakeHelper(t, func(r Request) Response {
		if r.Op == OpFSMORoles {
			resp, _ := OKResponse(r.ID, FSMORolesResult{Roles: []FSMORole{{Role: "PdcEmulationMasterRole", Owner: "CN=NTDS Settings,CN=DC1"}}})
			return resp
		}
		return ErrorResponse(r.ID, CodeNotAllowed, "nope")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := NewRequest("req-00000002", OpFSMORoles, caller, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Call(ctx, path, req)
	if err != nil {
		t.Fatal(err)
	}
	var res FSMORolesResult
	if err := DecodeResult(resp, &res); err != nil || len(res.Roles) != 1 {
		t.Fatalf("result %+v %v", res, err)
	}
	req2, _ := NewRequest("req-00000003", OpDCList, caller, nil)
	_, err = Call(ctx, path, req2)
	var he *Error
	if !errors.As(err, &he) || he.Code != CodeNotAllowed {
		t.Fatalf("error response: %v", err)
	}
	// Strict result decoding.
	bad := Response{OK: true, Result: []byte(`{"dcs":[],"extra":1}`)}
	if err := DecodeResult(bad, &DCListResult{}); err == nil {
		t.Error("unknown result field accepted")
	}
}

func TestCallUnavailable(t *testing.T) {
	req, _ := NewRequest("req-00000004", OpPing, caller, nil)
	_, err := Call(context.Background(), filepath.Join(t.TempDir(), "missing.sock"), req)
	var he *Error
	if !errors.As(err, &he) || he.Code != CodeUnavailable {
		t.Fatalf("missing socket: %v", err)
	}
	// An invalid request never leaves the process.
	req.Op = "exec"
	if _, err := Call(context.Background(), "/nonexistent", req); err == nil {
		t.Error("invalid request sent")
	}
}
