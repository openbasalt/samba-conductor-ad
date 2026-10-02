// Package helper defines the protocol between conductor (unprivileged) and
// conductor-helper (root, local only) for the few operations that need root
// on the DC. Only types, validation and framing live here; the helper binary
// is built in the conductor repository (P1/P3).
//
// Transport: a Unix stream socket (default DefaultSocketPath, mode 0660,
// group conductor), peer identity checked with SO_PEERCRED by the helper.
// Framing: one JSON object per line, at most MaxMessageSize bytes. Every
// request names an allowlisted operation and carries typed parameters that
// are decoded strictly (unknown fields rejected) and validated before the
// helper acts. Requests never carry passwords: the helper uses local
// root access or the machine account.
package helper

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/samba-conductor/ad/sid"
)

// ProtocolVersion is bumped on incompatible changes.
const ProtocolVersion = 1

// DefaultSocketPath is where conductor-helper listens.
const DefaultSocketPath = "/run/conductor-helper/helper.sock"

// MaxMessageSize bounds one framed message.
const MaxMessageSize = 64 << 10

// OpName names an allowlisted operation.
type OpName string

// The operations conductor-helper accepts.
const (
	OpPing                OpName = "ping"
	OpDomainBackupOnline  OpName = "domain.backup.online"
	OpReplicationStatus   OpName = "drs.showrepl"
	OpDomainLevel         OpName = "domain.level.show"
	OpServiceStatus       OpName = "service.status"
	OpBackupListArtifacts OpName = "backup.list"
	OpFSMORoles           OpName = "fsmo.show"
	OpDCList              OpName = "domain.dcs"
)

// Caller identifies who asked conductor for the operation; the helper
// records it in the audit log and may re-check the SID against policy.
type Caller struct {
	User      string `json:"user"`
	SID       string `json:"sid"`
	SessionID string `json:"session_id"`
	SourceIP  string `json:"source_ip,omitempty"`
}

// Request is one call to the helper.
type Request struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Op      OpName          `json:"op"`
	Caller  Caller          `json:"caller"`
	Params  json.RawMessage `json:"params,omitempty"`
	SentAt  time.Time       `json:"sent_at"`
}

// ErrorCode classifies a failed call.
type ErrorCode string

// Error codes.
const (
	CodeBadRequest   ErrorCode = "bad_request"
	CodeNotAllowed   ErrorCode = "not_allowed"
	CodeForbidden    ErrorCode = "forbidden"
	CodeFailed       ErrorCode = "failed"
	CodeUnavailable  ErrorCode = "unavailable"
	CodeVersionError ErrorCode = "version"
)

// Error is the error part of a Response.
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("helper: %s: %s", e.Code, e.Message) }

// Response answers a Request with the same ID.
type Response struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Params is implemented by every operation's parameter type.
type Params interface {
	Validate() error
}

// NoParams is used by operations without parameters.
type NoParams struct{}

// Validate implements Params.
func (NoParams) Validate() error { return nil }

// BackupOnlineParams asks for an online domain backup. The helper chooses
// the target directory from its own configuration; the caller may only pick
// a label that becomes part of the file name.
type BackupOnlineParams struct {
	Label string `json:"label"`
}

var labelRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Validate implements Params.
func (p BackupOnlineParams) Validate() error {
	if !labelRE.MatchString(p.Label) {
		return errors.New("label must be 1-32 of [a-z0-9-], starting alphanumeric")
	}
	return nil
}

// ServiceStatusParams asks for the state of an allowlisted systemd unit.
type ServiceStatusParams struct {
	Unit string `json:"unit"`
}

var allowedUnits = map[string]bool{"samba-ad-dc.service": true, "chrony.service": true}

// Validate implements Params.
func (p ServiceStatusParams) Validate() error {
	if !allowedUnits[p.Unit] {
		return fmt.Errorf("unit %q is not allowlisted", p.Unit)
	}
	return nil
}

// Allowlist maps each operation to a constructor of its parameter type.
// Anything not listed is refused with CodeNotAllowed.
var Allowlist = map[OpName]func() Params{
	OpPing:                func() Params { return &NoParams{} },
	OpDomainBackupOnline:  func() Params { return &BackupOnlineParams{} },
	OpReplicationStatus:   func() Params { return &NoParams{} },
	OpDomainLevel:         func() Params { return &NoParams{} },
	OpServiceStatus:       func() Params { return &ServiceStatusParams{} },
	OpBackupListArtifacts: func() Params { return &NoParams{} },
	OpFSMORoles:           func() Params { return &NoParams{} },
	OpDCList:              func() Params { return &NoParams{} },
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// NewRequest builds a validated request.
func NewRequest(id string, op OpName, caller Caller, params Params) (Request, error) {
	if params == nil {
		params = NoParams{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return Request{}, err
	}
	req := Request{Version: ProtocolVersion, ID: id, Op: op, Caller: caller, Params: raw, SentAt: time.Now().UTC()}
	if _, err := req.Decode(); err != nil {
		return Request{}, err
	}
	return req, nil
}

// Decode validates the envelope and decodes the typed parameters
// (unknown fields rejected). The helper calls it on every request.
func (r Request) Decode() (Params, error) {
	if r.Version != ProtocolVersion {
		return nil, &Error{Code: CodeVersionError, Message: fmt.Sprintf("protocol version %d, want %d", r.Version, ProtocolVersion)}
	}
	if !idRE.MatchString(r.ID) {
		return nil, &Error{Code: CodeBadRequest, Message: "invalid request id"}
	}
	if r.Caller.User == "" || r.Caller.SessionID == "" {
		return nil, &Error{Code: CodeBadRequest, Message: "caller user and session are required"}
	}
	if _, err := sid.Parse(r.Caller.SID); err != nil {
		return nil, &Error{Code: CodeBadRequest, Message: "caller SID is invalid"}
	}
	mk, ok := Allowlist[r.Op]
	if !ok {
		return nil, &Error{Code: CodeNotAllowed, Message: fmt.Sprintf("operation %q is not allowlisted", r.Op)}
	}
	p := mk()
	params := r.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, &Error{Code: CodeBadRequest, Message: "params: " + err.Error()}
	}
	if dec.More() {
		return nil, &Error{Code: CodeBadRequest, Message: "params: trailing data"}
	}
	if err := p.Validate(); err != nil {
		return nil, &Error{Code: CodeBadRequest, Message: err.Error()}
	}
	return p, nil
}

// WriteMessage frames v as one JSON line.
func WriteMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxMessageSize {
		return errors.New("helper: message too large")
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// Reader reads framed messages with the size limit enforced.
type Reader struct{ br *bufio.Reader }

// NewReader wraps r.
func NewReader(r io.Reader) *Reader { return &Reader{br: bufio.NewReaderSize(r, 4096)} }

// ErrTooLarge is returned for a line longer than MaxMessageSize.
var ErrTooLarge = errors.New("helper: message too large")

// ReadRequest reads one request line.
func (r *Reader) ReadRequest() (Request, error) {
	var req Request
	return req, r.read(&req)
}

// ReadResponse reads one response line.
func (r *Reader) ReadResponse() (Response, error) {
	var resp Response
	return resp, r.read(&resp)
}

func (r *Reader) read(v any) error {
	var line []byte
	for {
		chunk, isPrefix, err := r.br.ReadLine()
		if err != nil {
			return err
		}
		line = append(line, chunk...)
		if len(line) > MaxMessageSize {
			return ErrTooLarge
		}
		if !isPrefix {
			break
		}
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
