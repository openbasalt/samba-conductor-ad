package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Call sends one request to the helper over a new connection to socketPath
// and returns its response. The connection is closed when ctx ends. A
// response with OK=false is returned as its *Error.
func Call(ctx context.Context, socketPath string, req Request) (Response, error) {
	if _, err := req.Decode(); err != nil {
		return Response{}, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Response{}, &Error{Code: CodeUnavailable, Message: err.Error()}
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := WriteMessage(conn, req); err != nil {
		return Response{}, err
	}
	resp, err := NewReader(conn).ReadResponse()
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, fmt.Errorf("helper: reading response: %w", err)
	}
	if resp.ID != req.ID {
		return Response{}, errors.New("helper: response for another request")
	}
	if !resp.OK {
		if resp.Error == nil {
			return resp, &Error{Code: CodeFailed, Message: "no error detail"}
		}
		return resp, resp.Error
	}
	return resp, nil
}

// DecodeResult decodes a successful response's result into v, rejecting
// unknown fields.
func DecodeResult(resp Response, v any) error {
	dec := json.NewDecoder(bytes.NewReader(resp.Result))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// OKResponse builds a successful response carrying result.
func OKResponse(id string, result any) (Response, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return Response{}, err
	}
	return Response{Version: ProtocolVersion, ID: id, OK: true, Result: raw}, nil
}

// ErrorResponse builds a failed response.
func ErrorResponse(id string, code ErrorCode, msg string) Response {
	return Response{Version: ProtocolVersion, ID: id, Error: &Error{Code: code, Message: msg}}
}
