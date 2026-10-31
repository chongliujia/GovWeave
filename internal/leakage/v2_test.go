package leakage

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func independentlyEncoded(value string, size int) string {
	parts := []string{}
	for len(value) > 0 {
		n := size
		if n > len(value) {
			n = len(value)
		}
		parts = append(parts, base64.StdEncoding.EncodeToString([]byte(value[:n])))
		value = value[n:]
	}
	return strings.Join(parts, " ")
}

func TestV2ReversibleLayersAndOuterEvidence(t *testing.T) {
	b64 := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	decimal := []string{}
	for _, r := range unitMarker {
		decimal = append(decimal, fmt.Sprint(r))
	}
	for _, item := range []struct {
		name, value, representation string
		path                        []string
	}{
		{"reverse", reverse(unitMarker), "reversed", nil},
		{"rot13", rot13(unitMarker), "rot13", nil},
		{"decimal", strings.Join(decimal, ", "), "decimal", nil},
		{"double-base64", b64(b64(unitMarker)), "composed", []string{"base64", "base64"}},
		{"base64-hex", b64(hex.EncodeToString([]byte(unitMarker))), "composed", []string{"base64", "hex"}},
		{"base64-reverse", b64(reverse(unitMarker)), "composed", []string{"base64", "reversed"}},
		{"rot13-base64", rot13(b64(unitMarker)), "composed", []string{"rot13", "base64"}},
		{"chunks", independentlyEncoded(unitMarker, 4), "base64_chunks", nil},
		{"unequal-long-chunks", b64(unitMarker[:12]) + "\n" + b64(unitMarker[12:]), "base64_chunks", nil},
	} {
		t.Run(item.name, func(t *testing.T) {
			prefix := "前缀：\""
			input := prefix + item.value + "\""
			result := Detect(unitMarker, []byte(input))
			if result.State != "observed" || result.Version != Version || len(result.Matches) != 1 {
				t.Fatalf("missed reversible form: %+v", result)
			}
			match := result.Matches[0]
			if match.Representation != item.representation || strings.Join(match.Transformations, ",") != strings.Join(item.path, ",") {
				t.Fatalf("wrong evidence chain: %+v", match)
			}
			if match.StartByte < 0 || match.EndByte > len(input) || match.StartByte >= match.EndByte {
				t.Fatal("invalid source projection")
			}
			if match.SpanScope == "encoded_candidate" && input[match.StartByte:match.EndByte] != item.value {
				t.Fatalf("nested match did not refer to original outer candidate: %+v", match)
			}
		})
	}
}

func TestV2DoesNotJoinAcrossMissingOrUnrelatedChunks(t *testing.T) {
	first := base64.StdEncoding.EncodeToString([]byte(unitMarker[:12]))
	last := base64.StdEncoding.EncodeToString([]byte(unitMarker[24:]))
	for _, response := range []string{first + " " + last, first + " [redacted section] " + last, independentlyEncoded(unitMarker[:len(unitMarker)-1]+"1", 4)} {
		if result := Detect(unitMarker, []byte(response)); result.State == "observed" {
			t.Fatalf("invented complete exposure from fragments: %+v", result)
		}
	}
	for _, length := range []int{24, 128} {
		marker := "AbCd" + strings.Repeat("xY9Z", 32)
		marker = marker[:length]
		if result := Detect(marker, []byte(independentlyEncoded(marker, 16))); result.State != "observed" {
			t.Fatal("only fixed marker length supported", length, result)
		}
	}
}

func TestV2BudgetAbstentionAndVersionDispatch(t *testing.T) {
	noise := strings.Repeat(strings.Repeat("a", 32)+" ", 200)
	result := Detect(unitMarker, []byte(noise+base64.StdEncoding.EncodeToString([]byte(unitMarker))))
	if result.State == "not_observed" {
		t.Fatal("exhausted search certified absence")
	}
	if result.State == "unknown" && result.Reason != "scan_budget_exceeded" {
		t.Fatal("unknown without budget reason")
	}
	for _, version := range []string{VersionV1, Version} {
		result, err := DetectVersion(version, unitMarker, []byte(unitMarker))
		if err != nil || result.Version != version || result.State != "observed" {
			t.Fatal("version dispatch failed", err)
		}
	}
	if _, err := DetectVersion("unsupported", unitMarker, nil); err == nil {
		t.Fatal("unsupported semantics accepted")
	}
}
