package ad

// The SASL/GSSAPI client below is adapted from github.com/go-ldap/ldap/v3/gssapi
// (MIT License, Copyright (c) 2011-2015 Michael Mitton, Portions copyright
// (c) 2015-2024 go-ldap Authors), ported to github.com/go-krb5/krb5 and to
// Sessions that hold only a ticket.

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // required by RFC 4121 channel bindings
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/types"
	"github.com/go-ldap/ldap/v3"
)

// kerberosAuth binds with SASL/GSSAPI using a Session's ticket.
type kerberosAuth struct{ s *Session }

// KerberosAuth returns an Authenticator that binds with the Session's
// Kerberos ticket (SASL GSSAPI over the TLS connection). AD applies the
// signed-in user's own rights to everything done on the connection.
func KerberosAuth(s *Session) Authenticator { return &kerberosAuth{s: s} }

func (a *kerberosAuth) mechanism() string { return "kerberos" }

func (a *kerberosAuth) bind(ctx context.Context, l *ldap.Conn, dc DC) error {
	if a.s == nil {
		return ErrSessionClosed
	}
	state, ok := l.TLSConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		return errors.New("ad: GSSAPI bind requires the TLS connection state")
	}
	g := &gssClient{s: a.s, ctx: ctx, bindings: channelBindingsHash(state.PeerCertificates[0])}
	defer func() { _ = g.DeleteSecContext() }()
	return ClassifyBindError(l.GSSAPIBind(g, "ldap/"+dc.Host, ""))
}

// channelBindingsHash computes the RFC 4121 channel-binding checksum (MD5 of
// gss_channel_bindings_struct) for the TLS channel's "tls-server-end-point"
// binding (RFC 5929): the hash of the DC's certificate. It ties the Kerberos
// authenticator to this TLS connection, so it cannot be relayed through a
// TLS-terminating man in the middle. Samba 4.22 requires it for SASL over
// TLS (otherwise: 80090346, SEC_E_BAD_BINDINGS).
func channelBindingsHash(cert *x509.Certificate) []byte {
	var h hash.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h = sha512.New384()
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h = sha512.New()
	default: // SHA-256, and MD5/SHA-1 are upgraded to SHA-256 by RFC 5929
		h = sha256.New()
	}
	h.Write(cert.Raw)
	appData := append([]byte("tls-server-end-point:"), h.Sum(nil)...)
	// initiator addrtype+len, acceptor addrtype+len (all zero), then
	// application data length and bytes, integers little-endian.
	buf := make([]byte, 20, 20+len(appData))
	binary.LittleEndian.PutUint32(buf[16:], uint32(len(appData)))
	buf = append(buf, appData...)
	sum := md5.Sum(buf) //nolint:gosec // MD5 is what RFC 4121 section 4.1.1.2 specifies here
	return sum[:]
}

// gssClient implements ldap.GSSAPIClient (RFC 4752).
type gssClient struct {
	s        *Session
	ctx      context.Context
	bindings []byte
	ekey     types.EncryptionKey
	subkey   types.EncryptionKey
}

// apReq builds the initial GSS-API token: an AP-REQ whose authenticator
// carries the RFC 4121 checksum with our channel bindings and context flags.
func (g *gssClient) apReq(tkt messages.Ticket, key types.EncryptionKey, ctxFlags []int, apOptions []int) ([]byte, error) {
	g.s.mu.Lock()
	cname := g.s.cl.Credentials.CName()
	g.s.mu.Unlock()
	auth, err := types.NewAuthenticator(g.s.realm, cname)
	if err != nil {
		return nil, err
	}
	cksum := make([]byte, 24)
	binary.LittleEndian.PutUint32(cksum[0:4], 16)
	copy(cksum[4:20], g.bindings)
	var f uint32
	for _, fl := range ctxFlags {
		f |= uint32(fl)
	}
	binary.LittleEndian.PutUint32(cksum[20:24], f)
	auth.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: cksum}
	req, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return nil, err
	}
	types.SetFlag(&req.APOptions, flags.APOptionMutualRequired)
	for _, o := range apOptions {
		types.SetFlag(&req.APOptions, o)
	}
	b, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	oid, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2})
	if err != nil {
		return nil, err
	}
	tok := append(oid, 0x01, 0x00) // TOK_ID KRB_AP_REQ
	tok = append(tok, b...)
	return asn1tools.AddASNAppTag(tok, 0), nil
}

func (g *gssClient) DeleteSecContext() error {
	g.ekey = types.EncryptionKey{}
	g.subkey = types.EncryptionKey{}
	return nil
}

func (g *gssClient) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return g.InitSecContextWithOptions(target, input, nil)
}

func (g *gssClient) InitSecContextWithOptions(target string, input []byte, apOptions []int) ([]byte, bool, error) {
	ctxFlags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}
	if input == nil {
		tkt, ekey, err := g.s.serviceTicket(g.ctx, target)
		if err != nil {
			return nil, false, fmt.Errorf("ad: service ticket for %s: %w", target, err)
		}
		g.ekey = ekey
		out, err := g.apReq(tkt, ekey, ctxFlags, apOptions)
		if err != nil {
			return nil, false, err
		}
		return out, true, nil
	}
	var token spnego.KRB5Token
	if err := token.Unmarshal(input); err != nil {
		return nil, false, err
	}
	if token.IsKRBError() {
		return nil, true, token.KRBError
	}
	if !token.IsAPRep() {
		return []byte{}, true, nil
	}
	enc, err := crypto.DecryptEncPart(token.APRep.EncPart, g.ekey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, false, err
	}
	var part messages.EncAPRepPart
	if err := part.Unmarshal(enc); err != nil {
		return nil, false, err
	}
	g.subkey = part.Subkey
	return []byte{}, false, nil
}

// NegotiateSaslAuth answers the server's security-layer offer. We select no
// security layer: confidentiality and integrity come from TLS.
func (g *gssClient) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	token := &gssapi.WrapToken{}
	if err := unmarshalWrapToken(token, input); err != nil {
		return nil, err
	}
	if token.Flags&0b1 == 0 {
		return nil, errors.New("ad: SASL wrap token not from the acceptor")
	}
	key := g.ekey
	if token.Flags&0b100 != 0 {
		key = g.subkey
	}
	if ok, err := token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); !ok {
		return nil, fmt.Errorf("ad: SASL wrap token verification: %w", err)
	}
	if len(token.Payload) != 4 {
		return nil, errors.New("ad: bad final SASL GSSAPI token")
	}
	payload := append([]byte{0, 0, 0, 0}, []byte(authzid)...)
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	out := &gssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(et.GetHMACBitLength() / 8),
		SndSeqNum: 1,
		Payload:   payload,
	}
	if err := out.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}
	return out.Marshal()
}

// unmarshalWrapToken parses an acceptor's wrap token with bounds checks on
// the checksum length taken from the wire.
func unmarshalWrapToken(wt *gssapi.WrapToken, b []byte) error {
	if len(b) < gssapi.HdrLen {
		return errors.New("ad: wrap token shorter than its header")
	}
	if !bytes.Equal(b[0:2], []byte{0x05, 0x04}) {
		return errors.New("ad: wrong wrap token ID")
	}
	if b[2]&0x01 != 1 {
		return errors.New("ad: wrap token is not from the acceptor")
	}
	if b[3] != gssapi.FillerByte {
		return errors.New("ad: bad wrap token filler byte")
	}
	ec := int(binary.BigEndian.Uint16(b[4:6]))
	if ec > len(b)-gssapi.HdrLen {
		return errors.New("ad: inconsistent wrap token checksum length")
	}
	start := gssapi.HdrLen + ec
	wt.Flags = b[2]
	wt.EC = uint16(ec)
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	wt.CheckSum = b[16:start]
	wt.Payload = b[start:]
	return nil
}
