package ad

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	krbasn1 "github.com/go-krb5/x/encoding/asn1"
)

const fakeRealm = "LAB.EXAMPLE.TEST"

// fakeDomain is a KDC (AS, TGS, kpasswd) and an LDAPS domain controller
// on loopback. The KDC encrypts service tickets with issueKey and the DC
// decrypts them with dcKey: equal keys model the real domain, different
// keys model a forged KDC that answers the AS exchange with a key derived
// from whatever password was typed but does not know the DC's key.
type fakeDomain struct {
	t         *testing.T
	mu        sync.Mutex
	passwords map[string]string // what the KDC encrypts the AS reply with
	krbtgtKey types.EncryptionKey
	issueKey  types.EncryptionKey
	dcKey     types.EncryptionKey
	refuseTGS bool
	// whoami overrides the DC's WhoAmI answer (default: the ticket's client).
	whoami string

	kdcConns   atomic.Int32
	tgsReqs    atomic.Int32
	binds      atomic.Int32
	bindsOK    atomic.Int32
	kpasswdReq atomic.Int32

	cfg Config
}

func randomKey(t *testing.T) types.EncryptionKey {
	t.Helper()
	et, err := crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatal(err)
	}
	k, err := types.GenerateEncryptionKey(et)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newFakeDomain starts the fake KDC, kpasswd server and LDAPS DC and
// points the package's Kerberos ports at them for the test.
func newFakeDomain(t *testing.T, genuine bool) *fakeDomain {
	t.Helper()
	f := &fakeDomain{t: t, passwords: map[string]string{}, krbtgtKey: randomKey(t), dcKey: randomKey(t)}
	f.issueKey = f.dcKey
	if !genuine {
		f.issueKey = randomKey(t)
	}
	kdcLn := listen(t)
	kpwLn := listen(t)
	oldKDC, oldKpw := kdcPort, kpasswdPort
	kdcPort, kpasswdPort = portOf(kdcLn), portOf(kpwLn)
	t.Cleanup(func() { kdcPort, kpasswdPort = oldKDC, oldKpw })
	go serveKerberos(kdcLn, func(b []byte) []byte { f.kdcConns.Add(1); return f.kdc(b) })
	go serveKerberos(kpwLn, f.kpasswd)

	caPEMPool, serverCert := testPKI(t)
	ldapLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ldapLn.Close() })
	go func() {
		for {
			c, err := ldapLn.Accept()
			if err != nil {
				return
			}
			go f.serveLDAP(c)
		}
	}()
	port, _ := strconv.Atoi(portOf(ldapLn))
	f.cfg = Config{Realm: fakeRealm, DCs: []string{"127.0.0.1"}, RootCAs: caPEMPool, LDAPSPort: port, DialTimeout: 2 * time.Second}
	return f
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func portOf(ln net.Listener) string {
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p
}

// testPKI returns a pool with a fresh CA and a server certificate for
// 127.0.0.1 signed by it.
func testPKI(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "dc"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// serveKerberos answers framed Kerberos TCP requests (RFC 4120 7.2.2).
func serveKerberos(ln net.Listener, handle func([]byte) []byte) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			var hdr [4]byte
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				return
			}
			msg := make([]byte, binary.BigEndian.Uint32(hdr[:]))
			if _, err := io.ReadFull(c, msg); err != nil {
				return
			}
			rep := handle(msg)
			if rep == nil {
				return // drop the connection
			}
			out := make([]byte, 4+len(rep))
			binary.BigEndian.PutUint32(out, uint32(len(rep)))
			copy(out[4:], rep)
			_, _ = c.Write(out)
		}()
	}
}

func marshalApp(v any, tag int) []byte {
	b, err := krbasn1.Marshal(v, krbasn1.WithMarshalSlicePreserveTypes(true), krbasn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		panic(err)
	}
	return asn1tools.AddASNAppTag(b, tag)
}

var ticketFlags = krbasn1.BitString{Bytes: []byte{0x40, 0xe1, 0, 0}, BitLength: 32}

// issueTicket returns a ticket for sname encrypted with key, and its session key.
func issueTicket(t *testing.T, cname, sname types.PrincipalName, key types.EncryptionKey, now time.Time) (messages.Ticket, types.EncryptionKey) {
	sess := randomKey(t)
	part := messages.EncTicketPart{Flags: ticketFlags, Key: sess, CRealm: fakeRealm, CName: cname,
		AuthTime: now, StartTime: now, EndTime: now.Add(10 * time.Hour)}
	enc, err := crypto.GetEncryptedData(marshalApp(part, asn1apptag.EncTicketPart), key, keyusage.KDC_REP_TICKET, 1)
	if err != nil {
		panic(err)
	}
	return messages.Ticket{TktVNO: 5, Realm: fakeRealm, SName: sname, EncPart: enc}, sess
}

func (f *fakeDomain) kdc(b []byte) []byte {
	now := time.Now().UTC().Truncate(time.Second)
	switch b[0] {
	case 0x6a: // AS-REQ
		var req messages.ASReq
		if err := req.Unmarshal(b); err != nil {
			return nil
		}
		f.mu.Lock()
		pw, ok := f.passwords[req.ReqBody.CName.PrincipalNameString()]
		f.mu.Unlock()
		if !ok {
			return nil
		}
		key, _, err := crypto.GetKeyFromPassword(pw, req.ReqBody.CName, fakeRealm, etypeID.AES256_CTS_HMAC_SHA1_96, types.PADataSequence{})
		if err != nil {
			return nil
		}
		tkt, sess := issueTicket(f.t, req.ReqBody.CName, req.ReqBody.SName, f.krbtgtKey, now)
		part := messages.EncKDCRepPart{Key: sess, LastReqs: []messages.LastReq{{LRType: 0, LRValue: now}}, Nonce: req.ReqBody.Nonce,
			Flags: ticketFlags, AuthTime: now, StartTime: now, EndTime: now.Add(10 * time.Hour), SRealm: fakeRealm, SName: req.ReqBody.SName}
		pb, _ := part.Marshal()
		enc, err := crypto.GetEncryptedData(pb, key, keyusage.AS_REP_ENCPART, 1)
		if err != nil {
			return nil
		}
		rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: msgtype.KRB_AS_REP, CRealm: fakeRealm,
			CName: req.ReqBody.CName, Ticket: tkt, EncPart: enc}}
		out, err := rep.Marshal()
		if err != nil {
			return nil
		}
		return out
	case 0x6c: // TGS-REQ
		f.tgsReqs.Add(1)
		if f.refuseTGS {
			return nil
		}
		var req messages.TGSReq
		if err := req.Unmarshal(b); err != nil {
			return nil
		}
		var ap messages.APReq
		for _, pa := range req.PAData {
			if pa.PADataType == patype.PA_TGS_REQ {
				if err := ap.Unmarshal(pa.PADataValue); err != nil {
					return nil
				}
			}
		}
		if err := ap.Ticket.Decrypt(f.krbtgtKey); err != nil {
			return nil
		}
		tgt := ap.Ticket.DecryptedEncPart
		tkt, sess := issueTicket(f.t, tgt.CName, req.ReqBody.SName, f.issueKey, now)
		part := messages.EncKDCRepPart{Key: sess, LastReqs: []messages.LastReq{{LRType: 0, LRValue: now}}, Nonce: req.ReqBody.Nonce,
			Flags: ticketFlags, AuthTime: now, StartTime: now, EndTime: now.Add(10 * time.Hour), SRealm: fakeRealm, SName: req.ReqBody.SName}
		pb, _ := part.Marshal()
		enc, err := crypto.GetEncryptedData(pb, tgt.Key, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
		if err != nil {
			return nil
		}
		rep := messages.TGSRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: msgtype.KRB_TGS_REP, CRealm: fakeRealm,
			CName: req.ReqBody.CName, Ticket: tkt, EncPart: enc}}
		out, err := rep.Marshal()
		if err != nil {
			return nil
		}
		return out
	}
	return nil
}

// kpasswd accepts any change (both a real KDC and a forged one would say
// "success" here) and from then on answers AS exchanges with the new password.
func (f *fakeDomain) kpasswd(b []byte) []byte {
	f.kpasswdReq.Add(1)
	if len(b) < 6 || binary.BigEndian.Uint16(b[2:]) != 1 {
		return nil
	}
	apLen := int(binary.BigEndian.Uint16(b[4:]))
	var ap messages.APReq
	if err := ap.Unmarshal(b[6 : 6+apLen]); err != nil {
		return nil
	}
	if err := ap.Ticket.Decrypt(f.krbtgtKey); err != nil {
		return nil
	}
	tktKey := ap.Ticket.DecryptedEncPart.Key
	if err := ap.DecryptAuthenticator(tktKey); err != nil {
		return nil
	}
	subkey := ap.Authenticator.SubKey
	var priv messages.KRBPriv
	if err := priv.Unmarshal(b[6+apLen:]); err != nil {
		return nil
	}
	if err := priv.DecryptEncPart(subkey); err != nil {
		return nil
	}
	f.mu.Lock()
	f.passwords[ap.Ticket.DecryptedEncPart.CName.PrincipalNameString()] = string(priv.DecryptedEncPart.UserData)
	f.mu.Unlock()

	repEnc, _ := crypto.GetEncryptedData(marshalApp(messages.EncAPRepPart{CTime: ap.Authenticator.CTime, Cusec: ap.Authenticator.Cusec},
		asn1apptag.EncAPRepPart), tktKey, keyusage.AP_REP_ENCPART, 0)
	apRep := marshalApp(messages.APRep{PVNO: 5, MsgType: msgtype.KRB_AP_REP, EncPart: repEnc}, asn1apptag.APREP)
	reply := messages.NewKRBPriv(messages.EncKrbPrivPart{UserData: []byte{0, 0, 'o', 'k'}, Timestamp: time.Now().UTC(), SequenceNumber: 1})
	if err := reply.EncryptEncPart(subkey); err != nil {
		return nil
	}
	pb, err := reply.Marshal()
	if err != nil {
		return nil
	}
	out := make([]byte, 6, 6+len(apRep)+len(pb))
	binary.BigEndian.PutUint16(out[0:], uint16(6+len(apRep)+len(pb)))
	binary.BigEndian.PutUint16(out[2:], 1)
	binary.BigEndian.PutUint16(out[4:], uint16(len(apRep)))
	return append(append(out, apRep...), pb...)
}

// ---- fake LDAPS domain controller ----

func ldapMessage(id int64, op *ber.Packet) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	env.AppendChild(op)
	return env.Bytes()
}

func ldapResult(app ber.Tag, code int64, msg string) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, app, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, msg, ""))
	return op
}

func saslInProgress(token []byte) *ber.Packet {
	op := ldapResult(1, 14, "")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, string(token), ""))
	return op
}

// acceptorOffer is the RFC 4752 security-layer offer, sealed by the acceptor
// with the context key (no acceptor subkey).
func acceptorOffer(key types.EncryptionKey) ([]byte, error) {
	wt := &gssapi.WrapToken{Flags: 0x01, EC: 12, SndSeqNum: 1, Payload: []byte{0x01, 0x00, 0x00, 0x00}}
	if err := wt.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, err
	}
	return wt.Marshal()
}

func (f *fakeDomain) serveLDAP(c net.Conn) {
	defer func() { _ = c.Close() }()
	var sessKey types.EncryptionKey
	var bound string
	step := 0
	write := func(id int64, op *ber.Packet) bool {
		_, err := c.Write(ldapMessage(id, op))
		return err == nil
	}
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case 0: // BindRequest (SASL GSSAPI)
			var creds []byte
			if len(op.Children) > 2 && len(op.Children[2].Children) > 1 {
				creds = op.Children[2].Children[1].Data.Bytes()
			}
			switch step {
			case 0:
				f.binds.Add(1)
				var ap messages.APReq
				oidLen := 0
				// GSS token: [APPLICATION 0] { OID, TOK_ID 01 00, AP-REQ }.
				var raw asn1.RawValue
				if _, err := asn1.Unmarshal(creds, &raw); err == nil {
					var oid asn1.ObjectIdentifier
					if rest, err := asn1.Unmarshal(raw.Bytes, &oid); err == nil && len(rest) > 2 {
						oidLen = len(raw.Bytes) - len(rest)
						err = ap.Unmarshal(rest[2:])
						if err != nil {
							oidLen = 0
						}
					}
				}
				if oidLen == 0 || ap.Ticket.Decrypt(f.dcKey) != nil || ap.DecryptAuthenticator(ap.Ticket.DecryptedEncPart.Key) != nil {
					// What a DC answers to a ticket it cannot decrypt.
					write(id, ldapResult(1, 49, "80090308: LdapErr: DSID-0C09056D, comment: AcceptSecurityContext error, data 0, v4563"))
					return
				}
				sessKey = ap.Ticket.DecryptedEncPart.Key
				bound = ap.Ticket.DecryptedEncPart.CName.PrincipalNameString()
				enc, err := crypto.GetEncryptedData(marshalApp(messages.EncAPRepPart{CTime: ap.Authenticator.CTime, Cusec: ap.Authenticator.Cusec},
					asn1apptag.EncAPRepPart), sessKey, keyusage.AP_REP_ENCPART, 0)
				if err != nil {
					return
				}
				apRep := marshalApp(messages.APRep{PVNO: 5, MsgType: msgtype.KRB_AP_REP, EncPart: enc}, asn1apptag.APREP)
				oid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2})
				tok := asn1tools.AddASNAppTag(append(append(oid, 0x02, 0x00), apRep...), 0)
				step = 1
				if !write(id, saslInProgress(tok)) {
					return
				}
			case 1:
				offer, err := acceptorOffer(sessKey)
				if err != nil {
					return
				}
				step = 2
				if !write(id, saslInProgress(offer)) {
					return
				}
			default:
				f.bindsOK.Add(1)
				if !write(id, ldapResult(1, 0, "")) {
					return
				}
			}
		case 3: // SearchRequest: the RootDSE
			e := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
			e.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
			attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			for k, v := range map[string]string{"defaultNamingContext": "DC=lab,DC=example,DC=test", "dnsHostName": "dc1.lab.example.test", "domainFunctionality": "7"} {
				a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, ""))
				set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
				set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
				a.AppendChild(set)
				attrs.AppendChild(a)
			}
			e.AppendChild(attrs)
			if !write(id, e) || !write(id, ldapResult(5, 0, "")) {
				return
			}
		case 23: // ExtendedRequest: WhoAmI
			who := "u:LAB\\" + bound
			if f.whoami != "" {
				who = f.whoami
			}
			r := ldapResult(24, 0, "")
			r.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, who, ""))
			if !write(id, r) {
				return
			}
		default: // UnbindRequest and anything else
			return
		}
	}
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestSignInVerifiedGenuineDomain(t *testing.T) {
	f := newFakeDomain(t, true)
	f.passwords["alice"] = "right password"
	// The DC reports the stored case of sAMAccountName; names compare
	// case-insensitively, and Account returns the DC's spelling.
	f.whoami = "u:LAB\\Alice"
	s, err := SignInVerified(testCtx(t), f.cfg, "LAB\\alice", "right password")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Account() != "Alice" || f.bindsOK.Load() != 1 || f.tgsReqs.Load() != 1 {
		t.Fatalf("account %q, binds %d, TGS %d", s.Account(), f.bindsOK.Load(), f.tgsReqs.Load())
	}
}

func TestSignInVerifiedWrongPassword(t *testing.T) {
	f := newFakeDomain(t, true)
	f.passwords["alice"] = "right password"
	_, err := SignInVerified(testCtx(t), f.cfg, "alice", "wrong password")
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Reason != ReasonInvalidCredentials || errors.Is(err, ErrKDCNotVerified) {
		t.Fatalf("wrong password: %v", err)
	}
	if f.tgsReqs.Load() != 0 || f.binds.Load() != 0 {
		t.Fatal("verification ran after a refused AS exchange")
	}
}

func TestSignInVerifiedEmptyPasswordNoNetwork(t *testing.T) {
	f := newFakeDomain(t, true)
	_, err := SignInVerified(testCtx(t), f.cfg, "alice", "")
	if !errors.Is(err, ErrInvalidCredentials) || f.kdcConns.Load() != 0 {
		t.Fatalf("empty password: %v (KDC contacted %d times)", err, f.kdcConns.Load())
	}
}

// TestForgedKDCIsNotEnough: a KDC that answers the AS exchange with a key
// derived from the password the attacker typed yields a Session, but not a
// verified sign-in: its service ticket is refused by the domain controller.
func TestForgedKDCIsNotEnough(t *testing.T) {
	f := newFakeDomain(t, false)
	f.passwords["alice"] = "anything" // the forger encrypts with the typed password
	s, err := SignIn(testCtx(t), f.cfg, "alice", "anything")
	if err != nil {
		t.Fatalf("the forged AS reply should decrypt: %v", err)
	}
	if s.Account() != "" {
		t.Fatal("unverified session reports an account")
	}
	s.Close()

	_, err = SignInVerified(testCtx(t), f.cfg, "alice", "anything")
	if !errors.Is(err, ErrKDCNotVerified) {
		t.Fatalf("forged KDC accepted: %v", err)
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		t.Fatalf("verification failure must not look like a password refusal: %v", err)
	}
	if f.binds.Load() != 1 || f.bindsOK.Load() != 0 {
		t.Fatalf("binds %d ok %d", f.binds.Load(), f.bindsOK.Load())
	}
}

func TestForgedKDCWithoutServiceTicket(t *testing.T) {
	f := newFakeDomain(t, false)
	f.refuseTGS = true
	f.passwords["alice"] = "anything"
	if _, err := SignInVerified(testCtx(t), f.cfg, "alice", "anything"); !errors.Is(err, ErrKDCNotVerified) {
		t.Fatalf("no service ticket: %v", err)
	}
}

func TestSignInVerifiedNoDomainController(t *testing.T) {
	f := newFakeDomain(t, true)
	f.passwords["alice"] = "pw"
	cfg := f.cfg
	cfg.LDAPSPort = 1 // nothing listens there
	if _, err := SignInVerified(testCtx(t), cfg, "alice", "pw"); !errors.Is(err, ErrKDCNotVerified) {
		t.Fatalf("DC unreachable: %v", err)
	}
}

func TestSignInVerifiedIdentityMismatch(t *testing.T) {
	f := newFakeDomain(t, true)
	f.passwords["alice"] = "pw"
	f.whoami = "u:LAB\\bob"
	_, err := SignInVerified(testCtx(t), f.cfg, "alice", "pw")
	if !errors.Is(err, ErrIdentityMismatch) || !errors.Is(err, ErrKDCNotVerified) {
		t.Fatalf("mismatch: %v", err)
	}
}

func TestChangePasswordKerberosConfirmed(t *testing.T) {
	f := newFakeDomain(t, true)
	f.passwords["alice"] = "old"
	if err := ChangePasswordKerberos(testCtx(t), f.cfg, "alice", "old", "new"); err != nil {
		t.Fatal(err)
	}
	if f.kpasswdReq.Load() != 1 || f.bindsOK.Load() != 1 {
		t.Fatalf("kpasswd %d, confirming binds %d", f.kpasswdReq.Load(), f.bindsOK.Load())
	}
}

func TestChangePasswordKerberosForged(t *testing.T) {
	f := newFakeDomain(t, false)
	f.passwords["alice"] = "anything"
	err := ChangePasswordKerberos(testCtx(t), f.cfg, "alice", "anything", "new")
	if !errors.Is(err, ErrKDCNotVerified) || f.kpasswdReq.Load() != 1 {
		t.Fatalf("forged kpasswd success accepted: %v", err)
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		t.Fatalf("must not unwrap to an AuthError: %v", err)
	}
}

func TestAccountFromAuthzID(t *testing.T) {
	for in, want := range map[string]string{"u:LAB\\alice": "alice", "u:alice": "alice"} {
		if got, err := accountFromAuthzID(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "dn:CN=alice,DC=lab", "u:LAB\\", "u:a\\b\\c", "u:alice@lab"} {
		if _, err := accountFromAuthzID(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
