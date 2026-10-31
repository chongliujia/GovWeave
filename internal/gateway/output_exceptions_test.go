package gateway

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"govweave/internal/sensitive"
)

func TestPublicEmailPermissionsAreExactAndRechecked(t *testing.T) {
	p := redactPolicy(sensitive.Version2, "credential", "email", "phone")
	p.PublicEmails = []string{"help@example.com"}
	for _, tc := range []struct {
		input, result, output string
		count                 int
	}{
		{"help@example.com", "allow", "", 1},
		{"help@example.com private@example.com", "redact", "help@example.com [REDACTED]", 1},
		{"HELP@example.com", "redact", "[REDACTED]", 0},
		{"help [at] example [dot] com", "redact", "[REDACTED]", 0},
		{"help@example.com.attacker.net", "redact", "[REDACTED]", 0},
		{"help@example.com sk-SyntheticCredentialNeverReal1234567890", "redact", "[REDACTED]", 1},
		{strings.Repeat("help@example.com ", 33), "error", "", 0},
	} {
		r := sensitive.DetectVersion([]byte(tc.input), p.DetectorVersion)
		a := assessOutputText(p, "app", tc.input, r)
		if a.Result != tc.result || a.PublicEmailExceptions != tc.count {
			t.Fatalf("unexpected decision: %+v", a)
		}
		if tc.output != "" {
			out, _, err := redactOutput(tc.input, p, r)
			if err != nil || out != tc.output {
				t.Fatal("incorrect exception/redaction", err, out)
			}
		}
	}
	p.ApplicationIDs = []string{"other-app"}
	if a := assessOutputText(p, "app", "help@example.com", sensitive.DetectVersion([]byte("help@example.com"), p.DetectorVersion)); a.Result != "not_applicable" || a.PublicEmailExceptions != 0 {
		t.Fatal("scope escaped")
	}
}

func TestPublicEmailHistoryValidationAndIsolation(t *testing.T) {
	g, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for _, emails := range [][]string{{"*@example.com"}, {"help@example.com", "help@example.com"}, {"help@example.com\n"}, {"sk-SyntheticCredentialNeverReal1234567890@example.com"}, make([]string, 17)} {
		in := defaultOutputPolicy().OutputPolicyInput
		in.PublicEmails = emails
		if _, err := g.OutputPolicies.Save(in, g.Store.Snapshot()); err == nil {
			t.Fatal("invalid public email accepted")
		}
	}
	in := defaultOutputPolicy().OutputPolicyInput
	in.Mode = "redact"
	in.PublicEmails = []string{"help@example.com"}
	p, err := g.OutputPolicies.Save(in, g.Store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	in.PublicEmails[0] = "tampered@example.com"
	p.PublicEmails[0] = "changed@example.com"
	p = g.OutputPolicies.Snapshot()
	if p.PublicEmails[0] != "help@example.com" {
		t.Fatal("snapshot aliased")
	}
	reopened, err := OpenOutputPolicies(filepath.Dir(g.OutputPolicies.path), g.Store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Snapshot().PublicEmails[0] != "help@example.com" {
		t.Fatal("permission lost on restart")
	}
	old, _ := reopened.Revision(0)
	if len(old.PublicEmails) != 0 {
		t.Fatal("historical snapshot changed")
	}
}

func TestPublicEmailToolReleaseAuditAndPrivateRedaction(t *testing.T) {
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) {
		return toolResponse(200, `{"text":"help@example.com private@example.com"}`), nil
	})
	in := defaultOutputPolicy().OutputPolicyInput
	in.Mode = "redact"
	in.PublicEmails = []string{"help@example.com"}
	if _, err := f.g.OutputPolicies.Save(in, f.g.Store.Snapshot()); err != nil {
		t.Fatal(err)
	}
	w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "help@example.com [REDACTED]") {
		t.Fatal(w.Code, w.Body.String())
	}
	r := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if r.OutputPolicy.PublicEmailExceptions != 1 || r.OutputPolicy.Redaction.Replacements != 1 {
		t.Fatal("missing exception evidence")
	}
	data, _ := json.Marshal(r)
	audit, _ := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
	for _, b := range [][]byte{data, audit} {
		if strings.Contains(string(b), "@example.com") {
			t.Fatal("email leaked to audit")
		}
	}
}
