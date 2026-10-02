package ad

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// ccacheFromASRep serializes the TGT of an AS exchange as an in-memory MIT
// credential cache (format version 4) and loads it, so a go-krb5 client can
// be built from the ticket alone, with no password attached. Nothing is
// written to disk.
func ccacheFromASRep(rep messages.ASRep, cname types.PrincipalName, realm string) (*credentials.CCache, []byte, error) {
	raw, err := ccacheBytes(rep, cname, realm)
	if err != nil {
		return nil, nil, err
	}
	cc := new(credentials.CCache)
	if err := cc.Unmarshal(raw); err != nil {
		return nil, nil, fmt.Errorf("ad: loading in-memory ccache: %w", err)
	}
	return cc, raw, nil
}

// ccacheBytes serializes the TGT of an AS exchange in the MIT credential
// cache format (version 4).
func ccacheBytes(rep messages.ASRep, cname types.PrincipalName, realm string) ([]byte, error) {
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
	// Absent optional times (zero time.Time) are written as 0, never as a
	// wrapped negative Unix time (a start time in 2042 makes the TGT "not
	// yet valid" for MIT and Heimdal).
	unix := func(t time.Time) {
		if t.IsZero() || t.Unix() <= 0 {
			w(uint32(0))
			return
		}
		w(uint32(t.Unix()))
	}

	w(uint16(0x0504)) // file format 5, version 4
	w(uint16(0))      // no header tags
	principal(cname, realm)

	// The single credential: the TGT.
	principal(cname, realm)
	principal(rep.Ticket.SName, rep.Ticket.Realm)
	w(uint16(part.Key.KeyType))
	data(part.Key.KeyValue)
	start := part.StartTime
	if start.IsZero() {
		start = part.AuthTime // starttime is optional; it defaults to authtime
	}
	unix(part.AuthTime)
	unix(start)
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
	return b.Bytes(), nil
}
