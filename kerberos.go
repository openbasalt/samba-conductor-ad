package ad

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/kadmin"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// NTSTATUS values AD/Samba put in KRB-ERROR e-data.
const (
	statusAccountLocked      uint32 = 0xC0000234
	statusAccountDisabled    uint32 = 0xC0000072
	statusAccountExpired     uint32 = 0xC0000193
	statusPasswordExpired    uint32 = 0xC0000071
	statusPasswordMustChange uint32 = 0xC0000224
	statusInvalidLogonHours  uint32 = 0xC000006F
	statusInvalidWorkstation uint32 = 0xC0000070
	statusWrongPassword      uint32 = 0xC000006A
	statusLogonFailure       uint32 = 0xC000006D
)

// maxKDCReply bounds a KDC reply read from the network.
const maxKDCReply = 1 << 20

// Session is a signed-in Kerberos identity: a TGT and its session key. It
// holds no password; when the TGT expires the user must sign in again. A
// Session is safe for concurrent use.
type Session struct {
	mu        sync.Mutex
	cl        *client.Client
	dial      *ctxDialer
	principal string
	realm     string
	expires   time.Time
	closed    bool
	// ccache is the TGT in MIT ccache format, for WriteCCache.
	ccache []byte
}

// Principal returns "user@REALM".
func (s *Session) Principal() string { return s.principal }

// Realm returns the Kerberos realm.
func (s *Session) Realm() string { return s.realm }

// Expires returns the TGT end time.
func (s *Session) Expires() time.Time { return s.expires }

// Close forgets the tickets.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.cl.Destroy()
		clear(s.ccache)
		s.ccache = nil
		s.closed = true
	}
}

// WriteCCache writes the session's TGT as an MIT credential cache to path,
// a new file created with mode 0600 (it must not exist), for a tool that
// only takes a ccache (samba-tool --use-krb5-ccache, see
// sambatool.KerberosCCache). The file holds a usable ticket until the TGT
// expires: put it in a private directory and remove it right after use.
func (s *Session) WriteCCache(path string) error {
	s.mu.Lock()
	raw := slices.Clone(s.ccache)
	closed := s.closed || time.Now().After(s.expires)
	s.mu.Unlock()
	defer clear(raw)
	if closed || len(raw) == 0 {
		return ErrSessionClosed
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// ErrSessionClosed is returned when a closed or expired Session is used.
var ErrSessionClosed = errors.New("ad: Kerberos session closed or expired")

func (s *Session) serviceTicket(ctx context.Context, spn string) (messages.Ticket, types.EncryptionKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || time.Now().After(s.expires) {
		return messages.Ticket{}, types.EncryptionKey{}, ErrSessionClosed
	}
	s.dial.set(ctx)
	defer s.dial.set(context.Background())
	return s.cl.GetServiceTicket(spn)
}

// ctxDialer is the go-krb5 dialer for TGS requests: it resolves names with
// the configured resolver and honours the context of the current call.
//
// go-krb5 shuffles the configured KDCs before every request, so a TGS-REQ
// could reach a DC that has not replicated a change yet (a password just
// changed through kpasswd: KDC_ERR_KEY_EXPIRED). kdcOrder pins the order
// instead: the KDC that issued the TGT first, then the configured order.
type ctxDialer struct {
	mu       sync.Mutex
	ctx      context.Context
	d        *net.Dialer
	kdcOrder []string // "host:88", tried in order for any KDC address
}

func (c *ctxDialer) set(ctx context.Context) {
	c.mu.Lock()
	c.ctx = ctx
	c.mu.Unlock()
}

// Dial returns the *net.TCPConn go-krb5 expects.
func (c *ctxDialer) Dial(network, addr string) (net.Conn, error) {
	c.mu.Lock()
	ctx := c.ctx
	c.mu.Unlock()
	if network != "tcp" {
		return nil, fmt.Errorf("ad: Kerberos over %s is disabled", network)
	}
	if _, port, err := net.SplitHostPort(addr); err == nil && port == "88" && len(c.kdcOrder) > 0 {
		var firstErr error
		for _, a := range c.kdcOrder {
			conn, err := c.d.DialContext(ctx, network, a)
			if err == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = err
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, firstErr
	}
	return c.d.DialContext(ctx, network, addr)
}

// kdcOrderFrom puts first (the KDC that answered) in front of hosts.
func kdcOrderFrom(first string, hosts []string) []string {
	out := make([]string, 0, len(hosts))
	if first != "" {
		out = append(out, net.JoinHostPort(first, "88"))
	}
	for _, h := range hosts {
		if h != first {
			out = append(out, net.JoinHostPort(h, "88"))
		}
	}
	return out
}

// kdcSet is the realm's KDCs plus how to reach them.
type kdcSet struct {
	realm string
	hosts []string
	cfg   *config.Config
	dial  *net.Dialer
	// answered is the last host that replied (any reply, KRB-ERROR included).
	answered string
}

func newKDCSet(ctx context.Context, cfg Config) (*kdcSet, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	realm := strings.ToUpper(cfg.Realm)
	var hosts []string
	if len(cfg.DCs) > 0 {
		for _, dc := range orderPreferred(hostsToDCs(cfg.DCs), cfg.Preferred) {
			hosts = append(hosts, dc.Host)
		}
	} else {
		kdcs, err := DiscoverKDCs(ctx, cfg.Resolver, realm, cfg.Preferred)
		if err != nil {
			return nil, err
		}
		for _, k := range kdcs {
			hosts = append(hosts, k.Host)
		}
	}
	kc, err := krb5Config(realm, hosts)
	if err != nil {
		return nil, err
	}
	return &kdcSet{realm: realm, hosts: hosts, cfg: kc, dial: dialer(cfg.Resolver, cfg.timeout())}, nil
}

func hostsToDCs(hosts []string) []DC {
	out := make([]DC, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, DC{Host: strings.ToLower(strings.TrimSuffix(h, "."))})
	}
	return out
}

// krb5Config renders a minimal krb5.conf: TCP only, AES only (no RC4/DES),
// no DNS-based realm guessing, explicit KDC and kpasswd servers.
func krb5Config(realm string, hosts []string) (*config.Config, error) {
	if !validRealm(realm) || len(hosts) == 0 {
		return nil, fmt.Errorf("ad: invalid Kerberos realm %q or no KDCs", realm)
	}
	var sb strings.Builder
	enctypes := "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96"
	fmt.Fprintf(&sb, "[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n dns_lookup_realm = false\n", realm)
	fmt.Fprintf(&sb, " udp_preference_limit = 1\n rdns = false\n ticket_lifetime = 10h\n forwardable = false\n")
	fmt.Fprintf(&sb, " default_tkt_enctypes = %s\n default_tgs_enctypes = %s\n permitted_enctypes = %s\n", enctypes, enctypes, enctypes)
	fmt.Fprintf(&sb, "[realms]\n %s = {\n", realm)
	for _, h := range hosts {
		if !validHost(h) {
			return nil, fmt.Errorf("ad: invalid KDC host %q", h)
		}
		fmt.Fprintf(&sb, "  kdc = %s\n  kpasswd_server = %s\n", net.JoinHostPort(h, "88"), net.JoinHostPort(h, "464"))
	}
	domain := strings.ToLower(realm)
	fmt.Fprintf(&sb, " }\n[domain_realm]\n .%s = %s\n %s = %s\n", domain, realm, domain, realm)
	return config.NewFromString(sb.String())
}

// send writes one Kerberos message to the first reachable server (TCP,
// RFC 4120 7.2.2 framing) and returns the reply. A server that answers ends
// the loop even with a KRB-ERROR, so a bad password is never retried on
// another KDC.
func (k *kdcSet) send(ctx context.Context, port string, msg []byte) ([]byte, error) {
	var errs []string
	for _, h := range k.hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rb, err := k.sendOne(ctx, net.JoinHostPort(h, port), msg)
		if err == nil {
			k.answered = h
			return rb, nil
		}
		errs = append(errs, h+": "+err.Error())
	}
	return nil, &connectivityError{fmt.Errorf("ad: no KDC reachable: %s", strings.Join(errs, "; "))}
}

func (k *kdcSet) sendOne(ctx context.Context, addr string, msg []byte) ([]byte, error) {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := k.dial.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	frame := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(frame, uint32(len(msg)))
	copy(frame[4:], msg)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxKDCReply {
		return nil, fmt.Errorf("ad: KDC reply of %d bytes", n)
	}
	rb := make([]byte, n)
	if _, err := io.ReadFull(conn, rb); err != nil {
		return nil, err
	}
	return rb, nil
}

// clientPrincipal turns what the user typed into a principal name of realm:
// "user", "user@realm" (realm must match) or "DOMAIN\user".
func clientPrincipal(username, realm string) (types.PrincipalName, error) {
	u := strings.TrimSpace(username)
	if _, after, ok := strings.Cut(u, "\\"); ok {
		u = after
	}
	if before, after, ok := strings.Cut(u, "@"); ok {
		if !strings.EqualFold(after, realm) {
			return types.PrincipalName{}, fmt.Errorf("ad: UPN suffix %q is not the realm %s (alternative UPN suffixes are not supported yet)", after, realm)
		}
		u = before
	}
	if u == "" || len(u) > 256 || strings.ContainsAny(u, "/\\[]:;|=,+*?<>@\"\x00") || strings.ContainsFunc(u, func(r rune) bool { return r < 0x20 }) {
		return types.PrincipalName{}, &AuthError{Reason: ReasonInvalidCredentials, Mechanism: "kerberos", Code: "invalid username"}
	}
	return types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, u), nil
}

// asExchange performs a password AS exchange for sname (krbtgt or
// kadmin/changepw) and classifies refusals. The password is used only here.
func (k *kdcSet) asExchange(ctx context.Context, cname types.PrincipalName, password string, changePassword bool) (messages.ASRep, error) {
	var req messages.ASReq
	var err error
	if changePassword {
		req, err = messages.NewASReqForChgPasswd(k.realm, k.cfg, cname)
	} else {
		req, err = messages.NewASReqForTGT(k.realm, k.cfg, cname)
	}
	if err != nil {
		return messages.ASRep{}, fmt.Errorf("ad: building AS-REQ: %w", err)
	}
	rep, krbErr, err := k.roundTrip(ctx, &req)
	if err != nil {
		return messages.ASRep{}, err
	}
	if krbErr != nil {
		if krbErr.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
			return messages.ASRep{}, classifyKRBError(*krbErr, false)
		}
		if err := addEncTimestamp(&req, *krbErr, cname, k.realm, password); err != nil {
			return messages.ASRep{}, err
		}
		rep, krbErr, err = k.roundTrip(ctx, &req)
		if err != nil {
			return messages.ASRep{}, err
		}
		if krbErr != nil {
			return messages.ASRep{}, classifyKRBError(*krbErr, true)
		}
	}
	creds := credentials.NewFromPrincipalName(cname, k.realm).WithPassword(password)
	if ok, err := rep.Verify(k.cfg, creds, req); !ok {
		// Without pre-authentication a wrong password shows up here, as an
		// undecryptable reply.
		return messages.ASRep{}, &AuthError{Reason: ReasonInvalidCredentials, Mechanism: "kerberos", Code: "AS-REP not verifiable", Err: err}
	}
	return rep, nil
}

func (k *kdcSet) roundTrip(ctx context.Context, req *messages.ASReq) (messages.ASRep, *messages.KRBError, error) {
	b, err := req.Marshal()
	if err != nil {
		return messages.ASRep{}, nil, fmt.Errorf("ad: marshaling AS-REQ: %w", err)
	}
	rb, err := k.send(ctx, "88", b)
	if err != nil {
		return messages.ASRep{}, nil, err
	}
	var rep messages.ASRep
	if err := rep.Unmarshal(rb); err != nil {
		var ke messages.KRBError
		if errors.As(err, &ke) {
			return messages.ASRep{}, &ke, nil
		}
		return messages.ASRep{}, nil, fmt.Errorf("ad: decoding KDC reply: %w", err)
	}
	return rep, nil, nil
}

// addEncTimestamp adds PA-ENC-TIMESTAMP with a key derived from the password
// and the salt/etype the KDC announced in its PREAUTH_REQUIRED error.
func addEncTimestamp(req *messages.ASReq, krbErr messages.KRBError, cname types.PrincipalName, realm, password string) error {
	var pas types.PADataSequence
	if err := pas.Unmarshal(krbErr.EData); err != nil {
		return fmt.Errorf("ad: decoding pre-authentication hints: %w", err)
	}
	et := int32(0)
	for _, pa := range pas {
		if pa.PADataType != patype.PA_ETYPE_INFO2 {
			continue
		}
		info, err := pa.GetETypeInfo2()
		if err != nil {
			return fmt.Errorf("ad: decoding ETYPE-INFO2: %w", err)
		}
		for _, e := range info {
			if e.EType == etypeID.AES256_CTS_HMAC_SHA1_96 || e.EType == etypeID.AES128_CTS_HMAC_SHA1_96 {
				et = e.EType
				break
			}
		}
	}
	if et == 0 {
		return errors.New("ad: the KDC offers no AES pre-authentication (RC4/DES are refused)")
	}
	key, _, err := crypto.GetKeyFromPassword(password, cname, realm, et, pas)
	if err != nil {
		return fmt.Errorf("ad: deriving key: %w", err)
	}
	ts, err := types.GetPAEncTSEncAsnMarshalled()
	if err != nil {
		return err
	}
	enc, err := crypto.GetEncryptedData(ts, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 0)
	if err != nil {
		return err
	}
	pb, err := enc.Marshal()
	if err != nil {
		return err
	}
	req.PAData = append(req.PAData, types.PAData{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: pb})
	return nil
}

// paData mirrors PA-DATA / KERB-ERROR-DATA (both [1] type, [2] value).
type paData struct {
	Type  int32  `asn1:"explicit,tag:1"`
	Value []byte `asn1:"explicit,optional,tag:2"`
}

// ntStatusFromEData extracts the NTSTATUS that AD and Samba put in a
// KRB-ERROR's e-data (PA-PW-SALT / KERB-ERR-TYPE-EXTENDED, value starting
// with a little-endian NTSTATUS).
func ntStatusFromEData(edata []byte) (uint32, bool) {
	if len(edata) == 0 {
		return 0, false
	}
	var seq []paData
	if rest, err := asn1.Unmarshal(edata, &seq); err == nil && len(rest) == 0 {
		for _, p := range seq {
			if p.Type == 3 && len(p.Value) >= 4 {
				return binary.LittleEndian.Uint32(p.Value), true
			}
		}
	}
	var one paData
	if rest, err := asn1.Unmarshal(edata, &one); err == nil && len(rest) == 0 && one.Type == 3 && len(one.Value) >= 4 {
		return binary.LittleEndian.Uint32(one.Value), true
	}
	return 0, false
}

// classifyKRBError maps a KDC refusal to an AuthError. afterPreauth tells
// whether the request carried our encrypted timestamp: only then can an
// expired/must-change answer prove the password.
func classifyKRBError(e messages.KRBError, afterPreauth bool) *AuthError {
	// Lookup renders "(18) KDC_ERR_CLIENT_REVOKED Clients credentials…".
	code := "KRB_ERROR_" + strconv.Itoa(int(e.ErrorCode))
	if f := strings.Fields(errorcode.Lookup(e.ErrorCode)); len(f) >= 2 && strings.HasPrefix(f[1], "K") {
		code = f[1]
	}
	status, hasStatus := ntStatusFromEData(e.EData)
	if hasStatus {
		code += "/0x" + strings.ToUpper(strconv.FormatUint(uint64(status), 16))
	}
	ae := &AuthError{Mechanism: "kerberos", Code: code, Err: e}
	switch e.ErrorCode {
	case errorcode.KDC_ERR_PREAUTH_FAILED, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		ae.Reason = ReasonInvalidCredentials
	case errorcode.KRB_AP_ERR_SKEW:
		ae.Reason = ReasonClockSkew
	case errorcode.KDC_ERR_KEY_EXPIRED:
		ae.Reason = ReasonPasswordExpired
		if hasStatus && status == statusPasswordMustChange {
			ae.Reason = ReasonPasswordMustChange
		}
		ae.verified = afterPreauth
	case errorcode.KDC_ERR_CLIENT_REVOKED:
		ae.Reason = ReasonAccountRestricted
		switch status {
		case statusAccountLocked:
			ae.Reason = ReasonAccountLocked
		case statusAccountDisabled:
			ae.Reason = ReasonAccountDisabled
		case statusAccountExpired:
			ae.Reason = ReasonAccountExpired
		case statusInvalidLogonHours:
			ae.Reason = ReasonLogonHours
		case statusInvalidWorkstation:
			ae.Reason = ReasonWorkstationRestricted
		}
	default:
		if hasStatus && (status == statusWrongPassword || status == statusLogonFailure) {
			ae.Reason = ReasonInvalidCredentials
		} else {
			ae.Reason = ReasonUnknown
		}
	}
	return ae
}

// SignIn obtains a Kerberos TGT for username with password (one AS exchange
// against the realm's KDCs, discovered like DCs) and returns a Session that
// holds only the ticket. The password is not retained. Refusals are
// *AuthError values.
func SignIn(ctx context.Context, cfg Config, username, password string) (*Session, error) {
	if password == "" {
		return nil, &AuthError{Reason: ReasonInvalidCredentials, Mechanism: "kerberos", Code: "empty password"}
	}
	ks, err := newKDCSet(ctx, cfg)
	if err != nil {
		return nil, err
	}
	cname, err := clientPrincipal(username, ks.realm)
	if err != nil {
		return nil, err
	}
	rep, err := ks.asExchange(ctx, cname, password, false)
	if err != nil {
		var ae *AuthError
		if errors.As(err, &ae) && !ae.verified && (ae.Reason == ReasonPasswordExpired || ae.Reason == ReasonPasswordMustChange) {
			// Samba's KDC reports an expired password before it checks the
			// pre-authentication, so the answer alone proves nothing. The
			// kadmin/changepw service accepts expired passwords: an AS
			// exchange for it tells whether this password is the right one.
			if _, verr := ks.asExchange(ctx, cname, password, true); verr != nil {
				return nil, verr
			}
			ae.verified = true
		}
		return nil, err
	}
	cc, raw, err := ccacheFromASRep(rep, cname, ks.realm)
	if err != nil {
		return nil, err
	}
	cd := &ctxDialer{ctx: context.Background(), d: ks.dial, kdcOrder: kdcOrderFrom(ks.answered, ks.hosts)}
	cl, err := client.NewFromCCache(cc, ks.cfg, client.DisablePAFXFAST(true), client.UseDialer(cd))
	if err != nil {
		return nil, fmt.Errorf("ad: building Kerberos client: %w", err)
	}
	return &Session{
		cl:        cl,
		dial:      cd,
		principal: cname.PrincipalNameString() + "@" + ks.realm,
		realm:     ks.realm,
		expires:   rep.DecryptedEncPart.EndTime,
		ccache:    raw,
	}, nil
}

// ChangePasswordKerberos changes the user's own password with the kpasswd
// protocol (RFC 3244), authenticating with the old password. It works for
// accounts that must change their password (pwdLastSet=0) or whose password
// expired, which cannot bind to LDAP. The domain's password policy applies.
func ChangePasswordKerberos(ctx context.Context, cfg Config, username, oldPassword, newPassword string) error {
	if oldPassword == "" || newPassword == "" {
		return errors.New("ad: old and new passwords are required")
	}
	ks, err := newKDCSet(ctx, cfg)
	if err != nil {
		return err
	}
	cname, err := clientPrincipal(username, ks.realm)
	if err != nil {
		return err
	}
	rep, err := ks.asExchange(ctx, cname, oldPassword, true)
	if err != nil {
		return err
	}
	b, key, err := kpasswdChangeRequest(cname, ks.realm, newPassword, rep.Ticket, rep.DecryptedEncPart.Key)
	if err != nil {
		return err
	}
	rb, err := ks.send(ctx, "464", b)
	if err != nil {
		return err
	}
	reply, err := decodeKpasswdReply(rb)
	if err != nil {
		return err
	}
	if err := reply.Decrypt(key); err != nil {
		return fmt.Errorf("ad: decrypting kpasswd reply: %w", err)
	}
	switch reply.ResultCode {
	case client.KRB5_KPASSWD_SUCCESS:
		return nil
	case client.KRB5_KPASSWD_SOFTERROR:
		return fmt.Errorf("%w: %s", ErrPasswordPolicy, strings.TrimSpace(reply.Result))
	case client.KRB5_KPASSWD_ACCESSDENIED, client.KRB5_KPASSWD_AUTHERROR:
		return fmt.Errorf("%w: kpasswd: %s", ErrAccessDenied, strings.TrimSpace(reply.Result))
	default:
		return fmt.Errorf("ad: kpasswd result %d: %s", reply.ResultCode, strings.TrimSpace(reply.Result))
	}
}

// kpasswdChangeRequest builds an RFC 3244 request with protocol version 1:
// "change my own password", the new password as the KRB-PRIV user data.
// (go-krb5's kadmin uses version 0xff80 with the target set to the caller,
// which Samba treats as an administrative set-password and refuses for
// ordinary users: "Not permitted to change password".) The request is
// framed with its 2-byte total length, as the TCP transport expects inside
// the 4-byte record marker.
func kpasswdChangeRequest(cname types.PrincipalName, realm, newPassword string, tkt messages.Ticket, sessionKey types.EncryptionKey) ([]byte, types.EncryptionKey, error) {
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}
	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}
	if err := auth.GenerateSeqNumberAndSubKey(et.GetETypeID(), et.GetKeyByteSize()); err != nil {
		return nil, types.EncryptionKey{}, err
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}
	priv := messages.NewKRBPriv(messages.EncKrbPrivPart{
		UserData:       []byte(newPassword),
		Timestamp:      auth.CTime,
		Usec:           auth.Cusec,
		SequenceNumber: auth.SeqNumber,
	})
	if err := priv.EncryptEncPart(auth.SubKey); err != nil {
		return nil, types.EncryptionKey{}, err
	}
	ab, err := apReq.Marshal()
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}
	pb, err := priv.Marshal()
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}
	total := 6 + len(ab) + len(pb)
	if total > 0xffff {
		return nil, types.EncryptionKey{}, errors.New("ad: kpasswd request too large")
	}
	b := make([]byte, 6, total)
	binary.BigEndian.PutUint16(b[0:], uint16(total))
	binary.BigEndian.PutUint16(b[2:], 1) // protocol version 1: change password
	binary.BigEndian.PutUint16(b[4:], uint16(len(ab)))
	b = append(b, ab...)
	b = append(b, pb...)
	return b, auth.SubKey, nil
}

// decodeKpasswdReply validates the framing before handing the reply to
// go-krb5, whose decoder slices without bounds checks.
func decodeKpasswdReply(rb []byte) (reply kadmin.Reply, err error) {
	if len(rb) < 6 {
		return reply, errors.New("ad: short kpasswd reply")
	}
	n := int(binary.BigEndian.Uint16(rb[0:2]))
	apLen := int(binary.BigEndian.Uint16(rb[4:6]))
	if n > len(rb) || n < 6 || 6+apLen > n {
		return reply, errors.New("ad: malformed kpasswd reply")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ad: malformed kpasswd reply: %v", r)
		}
	}()
	if err := reply.Unmarshal(rb); err != nil {
		return reply, fmt.Errorf("ad: decoding kpasswd reply: %w", err)
	}
	return reply, nil
}
