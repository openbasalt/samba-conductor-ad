package ad

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// txtParts decodes the canonical data of a record back into its strings
// through the wire format, the way a DC stores them.
func txtParts(t *testing.T, r DNSRecord) []string {
	t.Helper()
	raw, err := EncodeDNSRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeDNSRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.Data != r.Data {
		t.Fatalf("wire round trip: %q != %q", back.Data, r.Data)
	}
	parts, err := txtStrings(back.Data)
	if err != nil {
		t.Fatal(err)
	}
	return parts
}

func TestTXTMultiLine(t *testing.T) {
	x255, x256 := strings.Repeat("x", 255), strings.Repeat("y", 256)
	cases := []struct {
		name, in string
		want     []string
	}{
		{"issue example", "v=DKIM1; h=sha256; k=rsa;\np=abcdef\nghijklmnop",
			[]string{"v=DKIM1; h=sha256; k=rsa;", "p=abcdef", "ghijklmnop"}},
		{"CRLF from a browser textarea", "v=DKIM1; k=rsa;\r\np=abc\r\ndef\r\n",
			[]string{"v=DKIM1; k=rsa;", "p=abc", "def"}},
		{"blank and trailing lines ignored", "\n\na\r\n\r\n   \n b \n\n\r\n", []string{"a", "b"}},
		{"embedded quotes and backslashes are literal on a raw line", `say "hi" \n C:\dir\`,
			[]string{`say "hi" \n C:\dir\`}},
		{"quoted line keeps escapes", `"a\"b" "c\\d"` + "\nraw", []string{`a"b`, `c\d`, "raw"}},
		{"quoted line keeps surrounding spaces", `" padded "` + "\n" + `""`, []string{" padded ", ""}},
		{"exactly 255 bytes", x255, []string{x255}},
		{"256 bytes split", x256, []string{x256[:255], "y"}},
		{"each long line split on its own", x256 + "\n" + x255 + "\nz", []string{x256[:255], "y", x255, "z"}},
		{"single line quoted strings unchanged", `"a b" "c"`, []string{"a b", "c"}},
		{"single line raw value unchanged", "v=spf1 mx -all", []string{"v=spf1 mx -all"}},
	}
	for _, c := range cases {
		r, err := NewDNSRecord(DNSTypeTXT, c.in, 0)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := txtParts(t, r); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	r, _ := NewDNSRecord(DNSTypeTXT, "v=DKIM1; h=sha256; k=rsa;\np=abcdef\nghijklmnop", 0)
	if want := `"v=DKIM1; h=sha256; k=rsa;" "p=abcdef" "ghijklmnop"`; r.Data != want {
		t.Errorf("canonical %q, want %q", r.Data, want)
	}
}

func TestTXTMultiLineRejects(t *testing.T) {
	for name, in := range map[string]string{
		"only blank lines":         "\r\n \n\t\n",
		"quoted string over 255":   `"` + strings.Repeat("x", 256) + `"`,
		"unbalanced quoted line":   "ok\n\"open",
		"control character inside": "a\tb\nc",
		"bare CR inside a line":    "a\rb",
		"total over the limit":     strings.Repeat(strings.Repeat("x", 254)+"\n", 16),
	} {
		if _, err := NewDNSRecord(DNSTypeTXT, in, 0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestTXTTotalLimit(t *testing.T) {
	// maxTXTData counts each string with its length byte: 15 strings of
	// 255 bytes (3840) plus one of 159 (160) is exactly the limit.
	in := strings.Repeat(strings.Repeat("x", 255)+"\n", 15) + strings.Repeat("y", 159)
	if _, err := NewDNSRecord(DNSTypeTXT, in, 0); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if _, err := NewDNSRecord(DNSTypeTXT, in+"y", 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("one byte over the limit accepted: %v", err)
	}
}

func TestTXTSplitKeepsUTF8(t *testing.T) {
	// 254 ASCII bytes then "é" (2 bytes): byte 255 would cut the character.
	in := strings.Repeat("a", 254) + "éé" + strings.Repeat("b", 10)
	r, err := NewDNSRecord(DNSTypeTXT, in, 0)
	if err != nil {
		t.Fatal(err)
	}
	parts := txtParts(t, r)
	if len(parts) != 2 || len(parts[0]) != 254 || strings.Join(parts, "") != in {
		t.Fatalf("split %q", parts)
	}
	for _, p := range parts {
		if !utf8.ValidString(p) {
			t.Errorf("invalid UTF-8 chunk %q", p)
		}
	}
	// A 4-byte character across the boundary.
	in = strings.Repeat("a", 253) + "😀" + "z"
	r, err = NewDNSRecord(DNSTypeTXT, in, 0)
	if err != nil {
		t.Fatal(err)
	}
	if parts := txtParts(t, r); len(parts) != 2 || parts[0] != strings.Repeat("a", 253) || parts[1] != "😀z" {
		t.Fatalf("split %q", parts)
	}
	// The editing form shows the strings as text, and saving them back
	// gives the same record.
	if back, err := NewDNSRecord(DNSTypeTXT, TXTLines(r.Data), 0); err != nil || back.Data != r.Data {
		t.Fatalf("round trip %q: %v", back.Data, err)
	}
}

func TestTXTLines(t *testing.T) {
	cases := []struct{ data, want string }{
		{`"v=DKIM1; h=sha256; k=rsa;" "p=abcdef" "ghijklmnop"`, "v=DKIM1; h=sha256; k=rsa;\np=abcdef\nghijklmnop"},
		{`"say \"hi\" C:\\dir"`, `say "hi" C:\dir`},
		{`"\"starts with a quote"`, `"\"starts with a quote"`},
		{`" padded " "" "ok"`, "\" padded \"\n\"\"\nok"},
		{`"a\tb"`, `"a\tb"`}, // control characters never parse: shown as stored
		{`"\xff\xfe"`, `"\xff\xfe"`},
		{`"unbalanced`, `"unbalanced`},
	}
	for _, c := range cases {
		if got := TXTLines(c.data); got != c.want {
			t.Errorf("TXTLines(%s) = %q, want %q", c.data, got, c.want)
		}
	}
}

// Every record, whatever its strings, survives the editing form: its lines
// parse back to the identical canonical data, plain and with CRLF.
func TestTXTLinesRoundTrip(t *testing.T) {
	samples := [][]string{
		{"v=DKIM1; h=sha256; k=rsa;", "p=abcdef", "ghijklmnop"},
		{strings.Repeat("x", 255), strings.Repeat("y", 255), "tail"},
		{" lead", "trail ", "", `"quoted"`, `back\slash`, `mid "quote"`},
		{"\xff\xfe raw bytes", "ünï ✓", "é"},
	}
	for _, s := range samples {
		data := quoteTXT(s)
		lines := TXTLines(data)
		for _, in := range []string{lines, strings.ReplaceAll(lines, "\n", "\r\n") + "\r\n"} {
			got, err := txtStrings(in)
			if err != nil || !reflect.DeepEqual(got, s) {
				t.Errorf("%q: %q %v, want %q", in, got, err, s)
			}
		}
	}
}

func FuzzTXTLines(f *testing.F) {
	f.Add("v=DKIM1; k=rsa;\r\np=abc\n\ndef")
	f.Add(`"a\"b" c`)
	f.Add(strings.Repeat("é", 200))
	f.Fuzz(func(t *testing.T, in string) {
		r, err := NewDNSRecord(DNSTypeTXT, in, 0)
		if err != nil {
			return
		}
		back, err := NewDNSRecord(DNSTypeTXT, TXTLines(r.Data), 0)
		if err != nil || back.Data != r.Data {
			t.Fatalf("%q: %q -> %q (%v)", in, r.Data, back.Data, err)
		}
	})
}
