package sensitive

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func categoryCount(result Result, category string) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Category == category {
			count++
		}
	}
	return count
}

func TestCredentialPatternCompatibility(t *testing.T) {
	for _, secret := range []string{
		"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----",
		"sk-" + strings.Repeat("a", 20), "gw_app_" + strings.Repeat("B", 43), "ghp_" + strings.Repeat("c", 30),
		"gho_" + strings.Repeat("c", 30), "ghu_" + strings.Repeat("c", 30), "ghs_" + strings.Repeat("c", 30),
		"ghr_" + strings.Repeat("c", 30), "github_pat_" + strings.Repeat("D", 40), "AKIA" + strings.Repeat("E", 16),
	} {
		result := Detect([]byte("prefix " + secret + " suffix"))
		if result.State != "observed" || categoryCount(result, "credential") != 1 {
			t.Fatalf("credential pattern not recognized: %+v", result)
		}
		finding := result.Findings[0]
		if finding.StartByte != len("prefix ") || finding.EndByte != len("prefix ")+len(secret) {
			t.Fatal("credential span did not match original bytes")
		}
	}
	for _, text := range []string{"sk-" + strings.Repeat("a", 19), "-----BEGIN PUBLIC KEY-----", "xsk-" + strings.Repeat("a", 24), "AKIA" + strings.Repeat("a", 16)} {
		if result := Detect([]byte(text)); result.State != "not_observed" {
			t.Fatal("credential boundary changed", result)
		}
	}
}

func TestPracticalEmailBoundaries(t *testing.T) {
	for _, address := range []string{"alice@example.com", "A.User+tag@sub.example.org", "a_b@example.museum", "o'brien@example.net", "a@b.co"} {
		for _, wrapper := range []struct{ prefix, suffix string }{{"", ""}, {"邮箱：", "。"}, {"(", ")."}, {"Contact ", ". Next sentence."}} {
			text := wrapper.prefix + address + wrapper.suffix
			result := Detect([]byte(text))
			if result.State != "observed" || categoryCount(result, "email") != 1 {
				t.Fatal("valid practical address not recognized", result)
			}
			finding := result.Findings[0]
			if text[finding.StartByte:finding.EndByte] != address {
				t.Fatal("email boundary included surrounding punctuation")
			}
		}
	}
	for _, text := range []string{
		"alice..bob@example.com", ".alice@example.com", "alice.@example.com", "alice@example..com",
		"alice@-example.com", "alice@example-.com", "alice@example.c", "alice@example.123",
		"alice@127.0.0.1", "alice@example.com_foo", "alice@example.com@other.net",
		strings.Repeat("a", 65) + "@example.com", "a@" + strings.Repeat("d", 64) + ".com",
		"a@" + strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + "." + strings.Repeat("f", 63) + "." + strings.Repeat("g", 63) + ".com",
		"not an address: alice [at] example [dot] com", "@example.com", "no email here", "x@y",
	} {
		if result := Detect([]byte(text)); categoryCount(result, "email") != 0 {
			t.Fatal("invalid or unsupported address partially recognized", result)
		}
	}
}

func TestMobileContextFormattingAndBoundaries(t *testing.T) {
	for _, text := range []string{
		"手机：13900000001", "手机号13900000001", "请拨打电话 139 0000 0001", "联系 139-0000-0001",
		"Phone: 13900000001", "MOBILE 139 0000 0001", "13900000001 (telephone)", "tel:139-0000-0001",
		"+8613900000001", "+86 139 0000 0001", "+86-139-0000-0001", "电话：\n13900000001",
	} {
		result := Detect([]byte(text))
		if result.State != "observed" || categoryCount(result, "phone") != 1 {
			t.Fatal("phone pattern/context not recognized", result)
		}
	}
	for _, text := range []string{
		"order 13900000001", "13900000001", "hotel 13900000001", "smartphone13900000001",
		"phone: serial13900000001", "phone: 113900000001", "phone: 139000000012", "phone: 13900000001v2",
		"phone: serial-13900000001", "phone: 13900000001-account", "phone: user@13900000001",
		"phone: v1.13900000001", "phone: +113900000001", "phone: 13900000001-12",
		"phone: 12900000001", "phone: 1390000000", "+86 139000000012", "mobile ١3900000001",
		"phone " + strings.Repeat("远", 25) + "13900000001", "13900000001" + strings.Repeat("远", 25) + " phone",
	} {
		if result := Detect([]byte(text)); categoryCount(result, "phone") != 0 {
			t.Fatal("ambiguous or partial mobile candidate recognized", result)
		}
	}
}

func TestOverlapSuppressionAndDeterministicUnicodeOffsets(t *testing.T) {
	text := "手机：13900000001@example.com；密钥 sk-" + strings.Repeat("Z", 24) + "；电话：13900000002"
	result := Detect([]byte(text))
	if len(result.Findings) != 3 || categoryCount(result, "phone") != 1 || categoryCount(result, "email") != 1 || categoryCount(result, "credential") != 1 {
		t.Fatal("overlapping phone candidate was double-classified", result)
	}
	previousEnd := -1
	for _, finding := range result.Findings {
		if finding.StartByte < previousEnd || !utf8.RuneStart(text[finding.StartByte]) || finding.EndByte < len(text) && !utf8.RuneStart(text[finding.EndByte]) {
			t.Fatal("invalid byte spans or ordering")
		}
		previousEnd = finding.EndByte
	}
	for i := 0; i < 10; i++ {
		got := Detect([]byte(text))
		for j := range result.Findings {
			if got.Findings[j] != result.Findings[j] {
				t.Fatal("finding order changed")
			}
		}
	}
}

func TestInputAndFindingLimitsStayUnknown(t *testing.T) {
	for _, tc := range []struct {
		input  []byte
		reason string
	}{{[]byte{0xff}, "invalid_utf8"}, {[]byte(strings.Repeat("a", MaxBytes+1)), "input_limit"}} {
		result := Detect(tc.input)
		if result.State != "unknown" || result.Reason != tc.reason || len(result.Findings) != 0 || result.InputBytes != len(tc.input) {
			t.Fatal("invalid input treated as clean", result)
		}
	}
	if result := Detect([]byte(strings.Repeat("a", MaxBytes))); result.State != "not_observed" {
		t.Fatal("maximum input is not supported")
	}
	if result := Detect(nil); result.State != "not_observed" || result.Findings == nil {
		t.Fatal("empty text contract changed")
	}
	for _, count := range []int{MaxFindings, MaxFindings + 1} {
		result := Detect([]byte(strings.Repeat("a@example.com ", count)))
		if len(result.Findings) != MaxFindings {
			t.Fatal("wrong finding bound")
		}
		if count == MaxFindings && (result.State != "observed" || result.Truncated) {
			t.Fatal("exact limit should be complete")
		}
		if count > MaxFindings && (result.State != "unknown" || !result.Truncated || result.Reason != "finding_limit") {
			t.Fatal("truncated findings must not report complete coverage")
		}
	}
}

func TestResultContainsNoRawInputOrHashAndIsConcurrentSafe(t *testing.T) {
	private := "sk-" + strings.Repeat("Q", 24)
	text := "mail privacy@example.com; 手机13900000001; " + private
	result := Detect([]byte(text))
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{private, "privacy@example.com", "13900000001", "sha256", "hash", text} {
		if strings.Contains(string(data), value) {
			t.Fatal("raw or derived content leaked into result")
		}
	}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 30; j++ {
				if got := Detect([]byte(text)); got.State != "observed" || len(got.Findings) != len(result.Findings) {
					t.Error("concurrent result changed")
				}
			}
		}()
	}
	group.Wait()
}
