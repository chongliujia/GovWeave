package gateway

import (
	"encoding/base64"
	"strings"
	"testing"

	"govweave/internal/sensitive"
)

func TestFrozenV2FormattedPublicEmailFailure(t *testing.T) {
	p := redactPolicy(sensitive.Version2, "email")
	p.PublicEmails = []string{"release@product.example"}
	for _, text := range []string{"**release@product.example**", "`release@product.example`"} {
		r := sensitive.DetectVersion([]byte(text), p.DetectorVersion)
		a := assessOutputText(p, "app", text, r)
		if a.Result != "redact" || a.PublicEmailExceptions != 0 {
			t.Fatalf("historical formatted-address behavior changed: %+v", a)
		}
	}
}

func TestV3FormattedPermissionsAndEncodedRedaction(t *testing.T) {
	p := redactPolicy(sensitive.Version3, "credential", "email", "phone")
	p.PublicEmails = []string{"release@product.example"}
	for _, text := range []string{"**release@product.example**", "__release@product.example__", "`release@product.example`"} {
		r := sensitive.Scan([]byte(text), p.DetectorVersion)
		if a := assessOutputText(p, "app", text, r); a.Result != "allow" || a.PublicEmailExceptions != 1 {
			t.Fatalf("exact formatted public permission failed: %+v", a)
		}
	}
	for _, text := range []string{"**RELEASE@product.example**", "**release@product.example.attacker.test**", "**private@product.example**", "`release [at] product [dot] example`", base64.StdEncoding.EncodeToString([]byte(p.PublicEmails[0]))} {
		r := sensitive.Scan([]byte(text), p.DetectorVersion)
		a := assessOutputText(p, "app", text, r)
		if a.Result != "redact" || a.PublicEmailExceptions != 0 {
			t.Fatalf("non-exact/encoded permission escaped: %+v", a)
		}
		output, _, err := redactOutput(text, p, r)
		if err != nil || sensitive.Scan([]byte(output), p.DetectorVersion).State != "not_observed" {
			t.Fatal("redaction recheck failed", err)
		}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("hidden@secret.example"))
	text := "**release@product.example** " + encoded
	r := sensitive.Scan([]byte(text), p.DetectorVersion)
	output, evidence, err := redactOutput(text, p, r)
	if err != nil || output != "**release@product.example** [REDACTED]" || evidence.Replacements != 1 {
		t.Fatal("mixed public and encoded span release failed", output, err)
	}
	secret := base64.StdEncoding.EncodeToString([]byte("-----BEGIN PRIVATE KEY-----"))
	output, evidence, err = redactOutput("prefix "+secret+" suffix", p, sensitive.Scan([]byte("prefix "+secret+" suffix"), p.DetectorVersion))
	if err != nil || output != redactionMarker || evidence.Scope != "full_output" {
		t.Fatal("encoded credential must withhold entire output", err)
	}
	unknown := "**release@product.example** " + strings.Repeat("A", sensitive.MaxEncodedTokenBytes+1)
	a := assessOutputText(p, "app", unknown, sensitive.Scan([]byte(unknown), p.DetectorVersion))
	if a.Result != "error" || a.PublicEmailExceptions != 0 {
		t.Fatal("incomplete scan allowed a public permission")
	}
}
