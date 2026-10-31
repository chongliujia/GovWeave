package sensitive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestV2NormalizationMapsOriginalSpansAndKeepsV1(t *testing.T) {
	for _, tc := range []struct{ text, rule string }{
		{"sk-\u200bRegressionSyntheticToken00000000000", "api_key"},
		{"－－－－－ＢＥＧＩＮ ＰＲＩＶＡＴＥ ＫＥＹ－－－－－", "private_key"},
		{"testing＠example．net", "email_address"},
		{"testing [AT] example [DOT] net", "email_address"},
		{"testing\u200d@example.net", "email_address"},
		{"＋８６ １３６ ００００ ００４９", "cn_mobile_phone"},
	} {
		prefix := "开头： "
		input := []byte(prefix + tc.text + " ; end")
		old := DetectVersion(input, Version)
		result := DetectVersion(input, Version2)
		if old.State != "not_observed" || result.State != "observed" || result.DetectorVersion != Version2 || len(result.Findings) != 1 {
			t.Fatalf("wrong observation for rule %s: %+v", tc.rule, result)
		}
		f := result.Findings[0]
		if f.RuleID != "normalized_"+tc.rule || f.StartByte != len(prefix) || f.EndByte != len(prefix)+len(tc.text) || string(input[f.StartByte:f.EndByte]) != tc.text {
			t.Fatal("normalized evidence did not map to original bytes", f)
		}
		data, _ := json.Marshal(result)
		if strings.Contains(string(data), tc.text) {
			t.Fatal("finding retained text")
		}
	}
}

func TestV2BoundsDuplicateViewsAndUnsupportedVersion(t *testing.T) {
	for _, input := range [][]byte{[]byte(strings.Repeat("x", MaxBytes+1)), {0xff}} {
		if r := DetectVersion(input, Version2); r.State != "unknown" || len(r.Findings) != 0 {
			t.Fatal("invalid input evaluated", r)
		}
	}
	if r := DetectVersion([]byte("clean"), "future"); r.State != "unknown" || r.Reason != "unsupported_version" {
		t.Fatal("version fallback")
	}
	for _, tc := range []struct {
		text  string
		state string
		count int
	}{
		{"\u200b" + strings.Repeat("one@example.net ", 32), "observed", 32},
		{strings.Repeat("one [at] example [dot] net ", 33), "unknown", 32},
		{strings.Repeat("one@example.net ", 32) + "two [at] example [dot] net", "unknown", 32},
		{"sk-RegressionSynthetic\u200bToken00000000000", "observed", 1},
	} {
		r := DetectVersion([]byte(tc.text), Version2)
		if r.State != tc.state || len(r.Findings) != tc.count || r.Truncated != (tc.state == "unknown") {
			t.Fatal("wrong merged finding budget", r)
		}
		for _, f := range r.Findings {
			if !utf8.ValidString(tc.text[f.StartByte:f.EndByte]) {
				t.Fatal("span split a rune")
			}
		}
	}
}

func TestV2DoesNotJoinOrdinaryWordsLinesOrInferIdentities(t *testing.T) {
	for _, text := range []string{"name at example dot net", "name [at]\nexample [dot] net", "reference: １３６００００００４９", "phone: ticket-１３６００００００４９", "short[dot]value", "hello\u200bworld", "phone: 136000000490"} {
		if r := DetectVersion([]byte(text), Version2); r.State != "not_observed" {
			t.Fatal("unsupported form overmatched", r)
		}
	}
}

func TestV1DetectorSourceRemainsFrozen(t *testing.T) {
	data, err := os.ReadFile("detector.go")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != "67533b31af969288af055e6aa7b46057e88f2d1e51ef688d6b01e4a36ca3134f" {
		t.Fatal("v1 implementation changed")
	}
}

func FuzzV2OriginalSpanBounds(f *testing.F) {
	for _, s := range []string{"x [at] example [dot] org", "phone: １３６００００００４９", "sk-\u200bRegressionSyntheticToken00000000000", "👨\u200d👩"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r := DetectVersion([]byte(s), Version2)
		if r.InputBytes != len(s) || len(r.Findings) > MaxFindings {
			t.Fatal("bounds violated")
		}
		for _, v := range r.Findings {
			if v.StartByte < 0 || v.EndByte > len(s) || v.StartByte >= v.EndByte || !utf8.ValidString(s[v.StartByte:v.EndByte]) {
				t.Fatal("bad original span")
			}
		}
	})
}
