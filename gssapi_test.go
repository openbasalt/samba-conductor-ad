package ad

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

// acceptorWrapToken builds the token an acceptor sends with the SASL
// security-layer offer (RFC 4752): integrity only, checksum after the
// payload, then the data after the header rotated right by rrc bytes
// (RFC 4121 section 4.2.5).
func acceptorWrapToken(t *testing.T, key types.EncryptionKey, payload []byte, rrc int) []byte {
	t.Helper()
	wt := &gssapi.WrapToken{Flags: 0x01 | 0x04, EC: 12, SndSeqNum: 7, Payload: payload}
	if err := wt.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatal(err)
	}
	b, err := wt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	data := b[gssapi.HdrLen:]
	n := len(data)
	r := rrc % n
	rotated := append(append([]byte{}, data[n-r:]...), data[:n-r]...)
	binary.BigEndian.PutUint16(b[6:8], uint16(rrc))
	return append(b[:gssapi.HdrLen:gssapi.HdrLen], rotated...)
}

func TestUnmarshalWrapTokenRotation(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x5a}, 32)}
	offer := []byte{0x07, 0x01, 0x00, 0x00} // every layer, 65536 bytes
	for _, tc := range []struct {
		name string
		rrc  int
	}{
		{"MIT Kerberos, no rotation", 0},
		{"Heimdal, rotated by the checksum length", 12},
		{"rotation larger than the data", 12 + 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wt gssapi.WrapToken
			if err := unmarshalWrapToken(&wt, acceptorWrapToken(t, key, offer, tc.rrc)); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wt.Payload, offer) {
				t.Fatalf("payload %x, want %x", wt.Payload, offer)
			}
			if ok, err := wt.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); !ok {
				t.Fatalf("checksum: %v", err)
			}
		})
	}

	t.Run("tampered payload", func(t *testing.T) {
		b := acceptorWrapToken(t, key, offer, 0)
		b[gssapi.HdrLen] ^= 0x01
		var wt gssapi.WrapToken
		if err := unmarshalWrapToken(&wt, b); err != nil {
			t.Fatal(err)
		}
		if ok, _ := wt.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); ok {
			t.Fatal("a tampered token verified")
		}
	})

	t.Run("malformed", func(t *testing.T) {
		good := acceptorWrapToken(t, key, offer, 0)
		for name, b := range map[string][]byte{
			"short":          good[:gssapi.HdrLen-1],
			"checksum > len": func() []byte { c := bytes.Clone(good); binary.BigEndian.PutUint16(c[4:6], 200); return c }(),
			"not acceptor":   func() []byte { c := bytes.Clone(good); c[2] &^= 0x01; return c }(),
			"filler":         func() []byte { c := bytes.Clone(good); c[3] = 0; return c }(),
			"token ID":       func() []byte { c := bytes.Clone(good); c[0] = 0x04; return c }(),
		} {
			var wt gssapi.WrapToken
			if err := unmarshalWrapToken(&wt, b); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}
