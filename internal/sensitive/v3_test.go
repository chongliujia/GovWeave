package sensitive

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestV3FormattedEmailOffsetsAndLegacyIsolation(t *testing.T) {
	for _, delimiter := range []string{"**", "__", "`"} {
		text := "Contact: " + delimiter + "release@product.example" + delimiter + "."
		r := Scan([]byte(text), Version3)
		if r.State != "observed" || len(r.Findings) != 1 || r.DetectorVersion != Version3 {
			t.Fatalf("unexpected formatted result: %+v", r)
		}
		f := r.Findings[0]
		if f.RuleID != "formatted_email_address" || text[f.StartByte:f.EndByte] != "release@product.example" {
			t.Fatal("format bytes included in the address", f)
		}
	}
	if !Supports(Version3) || Scan([]byte("ordinary"), "future").State != "unknown" || SupportedVersion(Version3) {
		t.Fatal("version dispatch escaped frozen generation")
	}
	for _, text := range []string{"prefix**release@product.example**", "**release@product.example**.attacker.test", "**release@product.example**@attacker.test", "`release [at] product [dot] example`", "**release@product.example"} {
		for _, f := range Scan([]byte(text), Version3).Findings {
			if f.RuleID == "formatted_email_address" {
				t.Fatal("ambiguous or transformed markup admitted")
			}
		}
	}
}

func TestV3Base64MapsWholeTokenWithoutDisclosure(t *testing.T) {
	for _, codec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		for _, plain := range []string{"private.person@example.test", "\uffff private.person@example.test", "person [at] example [dot] test", "__person@example.test__", "phone: 13800000035", "sk-SyntheticUnitCredential00001234567"} {
			token := codec.EncodeToString([]byte(plain))
			text := "value: " + token + "."
			r := Scan([]byte(text), Version3)
			if r.State != "observed" || len(r.Findings) != 1 {
				t.Fatalf("encoded value missed: %+v", r)
			}
			f := r.Findings[0]
			if !strings.HasPrefix(f.RuleID, "base64_") || text[f.StartByte:f.EndByte] != token {
				t.Fatal("encoded span was not the original complete token")
			}
			data, _ := json.Marshal(r)
			if strings.Contains(string(data), plain) || strings.Contains(string(data), token) {
				t.Fatal("sensitive content retained in detection metadata")
			}
			if Scan([]byte(token), Version2).State != "not_observed" {
				t.Fatal("historical detector changed")
			}
		}
	}
}

func TestV3EncodingLimitsAndUnsupportedForms(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, text := range []string{strings.Repeat("A", MaxEncodedTokenBytes+1), strings.Repeat(encode("ordinary sample")+" ", MaxEncodedViews+1)} {
		r := Scan([]byte(text), Version3)
		if r.State != "unknown" || r.Reason != "encoding_limit" || !r.Truncated {
			t.Fatal("encoding bound released partial result", r)
		}
	}
	for _, input := range [][]byte{[]byte(strings.Repeat("x", MaxBytes+1)), {0xff}} {
		if Scan(input, Version3).State != "unknown" {
			t.Fatal("invalid input accepted")
		}
	}
	for _, text := range []string{encode(encode("hidden@example.test")), "SGVsbG8====", encode("ordinary safe message"), base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5})} {
		if r := Scan([]byte(text), Version3); r.State != "not_observed" {
			t.Fatal("unexpected recursive, invalid or negative decoding", r)
		}
	}
	text := strings.Repeat(encode("person@example.test")+" ", MaxFindings+1)
	if Scan([]byte(text), Version3).State != "unknown" {
		t.Fatal("too many findings must not produce a complete scan")
	}
}

func FuzzV3BoundedFindings(f *testing.F) {
	for _, text := range []string{"**person@example.test**", "cGVyc29uQGV4YW1wbGUudGVzdA==", "ordinary", "__mail@example.net__"} {
		f.Add([]byte(text))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		r := Scan(input, Version3)
		if len(r.Findings) > MaxFindings || r.InputBytes != len(input) || r.DetectorVersion != Version3 {
			t.Fatal("invalid result bounds")
		}
		for _, span := range r.Findings {
			if span.StartByte < 0 || span.EndByte <= span.StartByte || span.EndByte > len(input) {
				t.Fatal("invalid source offsets")
			}
		}
	})
}
