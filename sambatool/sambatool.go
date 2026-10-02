// Package sambatool runs typed samba-tool operations for the things LDAP
// cannot do (DNS through the DNS RPC server, replication status, domain
// level, online backups).
//
// Safety rules enforced here:
//   - an operation is a Go type whose fields are validated before any
//     command is built; there is no way to pass free-form arguments;
//   - user-supplied values are positional arguments placed after "--", and a
//     value starting with "-" is rejected anyway;
//   - secrets never go into argv: a password reaches samba-tool through an
//     inherited pipe (PASSWD_FD), a Kerberos identity through a credential
//     cache path (--use-krb5-ccache);
//   - output is parsed into structs;
//   - Preview returns the exact command line that Run executes.
package sambatool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Command is the argv of one samba-tool invocation, split by origin.
type Command struct {
	// Subcommand, e.g. ["dns", "add"]: constants only.
	Subcommand []string
	// Options built by the operation from validated values ("--json").
	Options []string
	// Args are user-supplied positional values; always placed after "--".
	Args []string
}

// Operation is a typed samba-tool command with a parser for its output.
type Operation[R any] interface {
	// Command validates the fields and builds the command.
	Command() (Command, error)
	// Parse turns stdout into the result.
	Parse(stdout []byte) (R, error)
}

// Credentials select how samba-tool authenticates to the DC.
type Credentials interface {
	apply(cmd *exec.Cmd, args *[]string) (cleanup func(), err error)
	describe() []string
}

// LocalSystem uses no network credentials: samba-tool runs as root on the
// DC against its local database (the privileged helper's case).
type LocalSystem struct{}

func (LocalSystem) apply(*exec.Cmd, *[]string) (func(), error) { return func() {}, nil }
func (LocalSystem) describe() []string                         { return nil }

// KerberosCCache authenticates with an existing Kerberos credential cache
// (FILE: path), e.g. one written for the signed-in user. The path is not a
// secret; the file must be readable only by the process user.
type KerberosCCache struct{ Path string }

func (k KerberosCCache) apply(_ *exec.Cmd, args *[]string) (func(), error) {
	if !strings.HasPrefix(k.Path, "/") || strings.ContainsAny(k.Path, "\x00\n") {
		return nil, errors.New("sambatool: ccache path must be absolute")
	}
	*args = append(*args, "--use-kerberos=required", "--use-krb5-ccache="+k.Path)
	return func() {}, nil
}

func (k KerberosCCache) describe() []string {
	return []string{"--use-kerberos=required", "--use-krb5-ccache=" + k.Path}
}

// Password authenticates with a username and password. The password is
// written to a pipe inherited as file descriptor 3 and announced to
// samba-tool with PASSWD_FD=3 in the child's environment only.
type Password struct {
	Username string // "user" or "DOMAIN\\user"
	Password string
}

var usernameRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9.-]{0,63}\\)?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (p Password) apply(cmd *exec.Cmd, args *[]string) (func(), error) {
	if !usernameRE.MatchString(p.Username) {
		return nil, fmt.Errorf("sambatool: invalid username %q", p.Username)
	}
	if p.Password == "" || strings.ContainsAny(p.Password, "\n\x00") {
		return nil, errors.New("sambatool: invalid password")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	// The pipe buffer (64 KiB on Linux) holds the password; write and close
	// before the child starts so it reads EOF after it.
	if _, err := w.WriteString(p.Password); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, err
	}
	_ = w.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, r)
	cmd.Env = append(cmd.Env, fmt.Sprintf("PASSWD_FD=%d", 2+len(cmd.ExtraFiles)))
	*args = append(*args, "--use-kerberos=off", "-U", p.Username)
	return func() { _ = r.Close() }, nil
}

func (p Password) describe() []string { return []string{"--use-kerberos=off", "-U", p.Username} }

// Runner executes operations.
type Runner struct {
	// Binary defaults to "samba-tool" found in PATH.
	Binary string
	// Credentials default to LocalSystem.
	Credentials Credentials
	// Timeout per command; defaults to 2 minutes.
	Timeout time.Duration
	// Env is the base environment of the child (default: PATH and LANG=C
	// only, so nothing of the parent leaks in).
	Env []string
}

func (r *Runner) binary() string {
	if r.Binary != "" {
		return r.Binary
	}
	return "samba-tool"
}

func (r *Runner) creds() Credentials {
	if r.Credentials != nil {
		return r.Credentials
	}
	return LocalSystem{}
}

// ValidateValue rejects values that could be taken as options or that carry
// control characters.
func ValidateValue(v string) error {
	if v == "" {
		return errors.New("sambatool: empty value")
	}
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("sambatool: value %q starts with '-'", v)
	}
	if len(v) > 4096 {
		return errors.New("sambatool: value too long")
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return fmt.Errorf("sambatool: control character in %q", v)
		}
	}
	return nil
}

var subcommandRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func argv(c Command, credArgs []string) ([]string, error) {
	if len(c.Subcommand) == 0 {
		return nil, errors.New("sambatool: empty subcommand")
	}
	for _, s := range c.Subcommand {
		if !subcommandRE.MatchString(s) {
			return nil, fmt.Errorf("sambatool: invalid subcommand %q", s)
		}
	}
	for _, o := range c.Options {
		// Long options, or -H with its value attached (some samba-tool
		// commands, e.g. "gpo", only know the short form of --URL).
		if !(strings.HasPrefix(o, "--") || (strings.HasPrefix(o, "-H") && len(o) > 2)) || strings.ContainsFunc(o, unicode.IsControl) {
			return nil, fmt.Errorf("sambatool: invalid option %q", o)
		}
	}
	for _, a := range c.Args {
		if err := ValidateValue(a); err != nil {
			return nil, err
		}
	}
	out := append([]string(nil), c.Subcommand...)
	out = append(out, c.Options...)
	out = append(out, credArgs...)
	if len(c.Args) > 0 {
		out = append(out, "--")
		out = append(out, c.Args...)
	}
	return out, nil
}

// Preview returns the exact command line Run would execute, shell-quoted.
// It contains no secret by construction.
func Preview[R any](r *Runner, op Operation[R]) (string, error) {
	c, err := op.Command()
	if err != nil {
		return "", err
	}
	args, err := argv(c, r.creds().describe())
	if err != nil {
		return "", err
	}
	parts := []string{shellQuote(r.binary())}
	for _, a := range args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " "), nil
}

func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_./=:@,+%", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ExitError is a failed samba-tool run, with its stderr (no secrets there:
// none were passed in argv).
type ExitError struct {
	Command string
	Code    int
	Stderr  string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("sambatool: %s exited %d: %s", e.Command, e.Code, strings.TrimSpace(e.Stderr))
}

// Run executes op and parses its output.
func Run[R any](ctx context.Context, r *Runner, op Operation[R]) (R, error) {
	var zero R
	c, err := op.Command()
	if err != nil {
		return zero, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.binary())
	cmd.Env = append([]string(nil), r.Env...)
	if len(cmd.Env) == 0 {
		cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	}
	var credArgs []string
	cleanup, err := r.creds().apply(cmd, &credArgs)
	if err != nil {
		return zero, err
	}
	defer cleanup()
	args, err := argv(c, credArgs)
	if err != nil {
		return zero, err
	}
	cmd.Args = append([]string{r.binary()}, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = nil
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return zero, &ExitError{Command: strings.Join(c.Subcommand, " "), Code: ee.ExitCode(), Stderr: stderr.String()}
		}
		return zero, fmt.Errorf("sambatool: %s: %w", strings.Join(c.Subcommand, " "), err)
	}
	return op.Parse(stdout.Bytes())
}

var dnsNameRE = regexp.MustCompile(`^(@|\*|[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,62}))*)\.?$`)

// validDNSName accepts a DNS name, "@" (zone apex) or a leading wildcard label.
func validDNSName(s string) bool {
	s = strings.TrimPrefix(s, "*.")
	return len(s) <= 253 && dnsNameRE.MatchString(s)
}

func validServer(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return s != "@" && s != "*" && validDNSName(s)
}
