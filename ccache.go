package ad

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// ccacheFromASRep serializes the TGT of an AS exchange as an in-memory MIT
// credential cache (format version 4) and loads it, so a go-krb5 client can
// be built from the ticket alone, with no password attached. Nothing is
// written to disk.
func ccacheFromASRep(rep messages.ASRep, cname types.PrincipalName, realm string) (*credentials.CCache, error) {
	tkt, err := rep.Ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("ad: marshaling TGT: %w", err)
	}
	part := rep.DecryptedEncPart
	if len(part.Key.KeyValue) == 0 {
		return nil, errors.New("ad: AS-REP has no session key")
	}
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.BigEndian, v) }
	data := func(d []byte) { w(uint32(len(d))); b.Write(d) }
	principal := func(p types.PrincipalName, r string) {
		w(uint32(p.NameType))
		w(uint32(len(p.NameString)))
		data([]byte(r))
		for _, c := range p.NameString {
			data([]byte(c))
		}
	}
	unix := func(t interface{ Unix() int64 }) { w(uint32(t.Unix())) }

	w(uint16(0x0504)) // file format 5, version 4
	w(uint16(0))      // no header tags
	principal(cname, realm)

	// The single credential: the TGT.
	principal(cname, realm)
	principal(rep.Ticket.SName, rep.Ticket.Realm)
	w(uint16(part.Key.KeyType))
	data(part.Key.KeyValue)
	unix(part.AuthTime)
	unix(part.StartTime)
	unix(part.EndTime)
	unix(part.RenewTill)
	w(uint8(0)) // not a user-to-user session key
	flags := make([]byte, 4)
	copy(flags, part.Flags.Bytes)
	b.Write(flags)
	w(uint32(0)) // addresses
	w(uint32(0)) // authdata
	data(tkt)
	data(nil) // second ticket

	cc := new(credentials.CCache)
	if err := cc.Unmarshal(b.Bytes()); err != nil {
		return nil, fmt.Errorf("ad: loading in-memory ccache: %w", err)
	}
	return cc, nil
}
