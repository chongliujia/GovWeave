package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"govweave/internal/sensitive"
)

func redactPolicy(version string, categories ...string) OutputPolicySnapshot {
	p := defaultOutputPolicy()
	p.Mode, p.DetectorVersion, p.Categories = "redact", version, categories
	p.RedactionVersion = redactionVersion
	return p
}

func TestRedactionOriginalSpansAndWholeCredentialOutput(t *testing.T) {
	for _, tc := range []struct {
		input, want, scope, version string
		count                       int
	}{
		{"联系 unit@example.net，电话：13800000035。", "联系 [REDACTED]，电话：[REDACTED]。", "matched_spans", sensitive.Version, 2},
		{"邮箱：unit [at] example [dot] net；电话：１３８００００００３５。", "邮箱：[REDACTED]；电话：[REDACTED]。", "matched_spans", sensitive.Version2, 2},
		{"before unit@example.net after unit@example.net.", "before [REDACTED] after [REDACTED].", "matched_spans", sensitive.Version2, 2},
		{"-----BEGIN PRIVATE KEY-----\nsynthetic-unrecognized-body\n-----END PRIVATE KEY-----", redactionMarker, "full_output", sensitive.Version, 1},
		{"prefix sk-\u200bSyntheticRedactionCredential00000 suffix", redactionMarker, "full_output", sensitive.Version2, 1},
	} {
		p := redactPolicy(tc.version, "credential", "email", "phone")
		detection := sensitive.DetectVersion([]byte(tc.input), tc.version)
		text, e, err := redactOutput(tc.input, p, detection)
		if err != nil || text != tc.want || e.Scope != tc.scope || e.Replacements != tc.count || e.Version != redactionVersion {
			t.Fatal("incorrect redacted output", err, e)
		}
		if sensitive.DetectVersion([]byte(text), tc.version).State != "not_observed" {
			t.Fatal("selected pattern remained")
		}
	}
	// Only selected categories are transformed.
	input := "unit@example.net; phone: 13800000035"
	p := redactPolicy(sensitive.Version, "email")
	text, _, err := redactOutput(input, p, sensitive.Detect([]byte(input)))
	if err != nil || text != "[REDACTED]; phone: 13800000035" {
		t.Fatal("unselected content was changed", err)
	}
}

func TestRedactionRejectsUnknownExpansionInvalidSpansAndResidualFindings(t *testing.T) {
	p := redactPolicy(sensitive.Version2, "email")
	for _, text := range []string{strings.Repeat("a@example.net ", 33), strings.Repeat("x", 8193), strings.Repeat(" ", 8186) + "a@b.co"} {
		output, e, err := redactOutput(text, p, sensitive.DetectVersion([]byte(text), p.DetectorVersion))
		if err == nil || output != "" || e != nil {
			t.Fatal("unsafe redaction escaped bounds")
		}
	}
	text := "unit@example.net other@example.net"
	detection := sensitive.DetectVersion([]byte(text), p.DetectorVersion)
	detection.Findings = detection.Findings[:1]
	if output, _, err := redactOutput(text, p, detection); err == nil || output != "" {
		t.Fatal("post-check did not catch residual candidate")
	}
	text = "前 unit@example.net"
	for _, span := range []sensitive.Finding{{Category: "email", StartByte: -1, EndByte: 3}, {Category: "email", StartByte: 1, EndByte: 3}, {Category: "email", StartByte: 0, EndByte: 9999}} {
		detection = sensitive.DetectVersion([]byte(text), p.DetectorVersion)
		detection.Findings = []sensitive.Finding{span}
		if _, _, err := redactOutput(text, p, detection); err == nil {
			t.Fatal("invalid byte span accepted")
		}
	}
	// Duplicated/overlapping original ranges must be replaced once.
	text = "unit@example.net"
	detection = sensitive.DetectVersion([]byte(text), p.DetectorVersion)
	detection.Findings = append(detection.Findings, detection.Findings[0])
	if output, e, err := redactOutput(text, p, detection); err != nil || output != redactionMarker || e.Replacements != 1 {
		t.Fatal("duplicate span handling failed")
	}
}

func TestRedactionModelReleaseMetadataAndAuditPrivacy(t *testing.T) {
	for _, content := range []string{"Private: one [at] example [dot] net", "电话：１３８００００００３５", "-----BEGIN PRIVATE KEY-----\nprivate-body-sentinel\n-----END PRIVATE KEY-----"} {
		f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, completionText(content, "stop"))
		})
		selectOutputVersion(t, f.engine, sensitive.Version2, "redact")
		w := f.call(f.key, chatBody("internal-assistant", false))
		if w.Code != 200 || w.Header().Get("X-GovWeave-Output-Action") != "redacted" || !strings.Contains(w.Body.String(), redactionMarker) || strings.Contains(w.Body.String(), content) || strings.Contains(w.Body.String(), "private-body-sentinel") {
			t.Fatal("model did not withhold original content", w.Code)
		}
		record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
		if record.OutputPolicy.Result != "redacted" || record.OutputPolicy.Redaction == nil || record.OutputPolicy.State != "observed" || record.Outcome != "completed" {
			t.Fatal("completed redaction evidence missing")
		}
		audit, _ := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
		for _, private := range []string{content, "private-body-sentinel", "one [at] example", "start_byte", "end_byte"} {
			if strings.Contains(string(audit), private) {
				t.Fatal("audit retained source content or spans")
			}
		}
		copied := cloneOutputAssessment(record.OutputPolicy)
		copied.Redaction.Scope = "changed"
		if record.OutputPolicy.Redaction.Scope == "changed" {
			t.Fatal("redaction evidence aliases retained audit")
		}
	}
}

func TestRedactionModelUnknownAndAuditFailuresWithholdOutput(t *testing.T) {
	for _, content := range []string{strings.Repeat("a [at] example [dot] net ", 33), strings.Repeat(" ", 8186) + "a@b.co"} {
		f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, completionText(content, "stop"))
		})
		selectOutputVersion(t, f.engine, sensitive.Version2, "redact")
		w := f.call(f.key, chatBody("internal-assistant", false))
		if w.Code != 502 || w.Header().Get("X-GovWeave-Output-Action") != "" || strings.Contains(w.Body.String(), "a@b.co") {
			t.Fatal("unverified redaction released")
		}
		record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
		if record.OutputPolicy.Result != "error" || record.OutputPolicy.Redaction != nil {
			t.Fatal("failure reported completed redaction")
		}
	}
	var f fixture
	f = newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		f.engine.Audit.mu.Lock()
		f.engine.Audit.failed = true
		f.engine.Audit.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, completionText("secret@example.net", "stop"))
	})
	selectOutputVersion(t, f.engine, sensitive.Version2, "redact")
	w := f.call(f.key, chatBody("internal-assistant", false))
	if w.Code != 503 || strings.Contains(w.Body.String(), "secret@example.net") || strings.Contains(w.Body.String(), redactionMarker) || w.Header().Get("X-GovWeave-Output-Action") != "" {
		t.Fatal("audit failure released transformed content")
	}
}

func TestRedactionPolicySnapshotAndInspectionRecommendation(t *testing.T) {
	var f fixture
	f = newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		selectOutputVersion(t, f.engine, sensitive.Version2, "observe")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, completionText("unit@example.net", "stop"))
	})
	pinned := selectOutputVersion(t, f.engine, sensitive.Version2, "redact")
	w := evaluateText(f.engine, f.key, `{"text":"unit@example.net"}`)
	var evaluated struct {
		Policy OutputAssessment `json:"policy"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &evaluated) != nil || evaluated.Policy.Result != "redact" || evaluated.Policy.Redaction != nil || strings.Contains(w.Body.String(), redactionMarker) {
		t.Fatal("inspection claimed performed redaction")
	}
	w = f.call(f.key, chatBody("internal-assistant", false))
	record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
	if w.Code != 200 || record.OutputPolicy.Result != "redacted" || record.OutputPolicy.Revision != pinned.Revision {
		t.Fatal("mode changed during admitted call")
	}
	reopened, err := OpenOutputPolicies(f.dir, f.engine.Store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	historical, _ := reopened.Revision(pinned.Revision)
	if historical.Mode != "redact" || historical.RedactionVersion != redactionVersion {
		t.Fatal("redaction snapshot not retained")
	}
}

func TestRedactionToolLegacyBlockScopeAndFailures(t *testing.T) {
	content := "one [at] example [dot] net"
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) {
		data, _ := json.Marshal(map[string]string{"text": content})
		return toolResponse(200, string(data)), nil
	})
	selectOutputVersion(t, f.g, sensitive.Version2, "redact")
	w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), redactionMarker) || strings.Contains(w.Body.String(), content) {
		t.Fatal("tool did not redact")
	}
	record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.ToolGovernance.Decision != "redact" || record.ToolGovernance.OutputPolicy.Result != "redacted" {
		t.Fatal("tool redaction metadata missing")
	}
	content = "sk-SyntheticRedactionCredential00000"
	if w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`); w.Code != 403 || !strings.Contains(w.Body.String(), "tool_output_blocked") {
		t.Fatal("redaction bypassed independent credential block")
	}
	f.input.Revision, f.input.OutputMode = f.tool.Revision, "observe"
	if _, err := f.g.Tools.Save(f.tool.ID, f.input); err != nil {
		t.Fatal(err)
	}
	w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || strings.Contains(w.Body.String(), content) || waitRecord(t, f.g, w.Header().Get("X-Request-ID")).OutputPolicy.Redaction.Scope != "full_output" {
		t.Fatal("credential output not fully replaced")
	}
	// Selected email redaction must not claim unrelated credentials were removed.
	p := f.g.OutputPolicies.Snapshot().OutputPolicyInput
	p.Categories = []string{"email"}
	if _, err := f.g.OutputPolicies.Save(p, f.g.Store.Snapshot()); err != nil {
		t.Fatal(err)
	}
	content += " one@example.net"
	w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "sk-SyntheticRedactionCredential00000") || strings.Contains(w.Body.String(), "one@example.net") {
		t.Fatal("category scope changed")
	}
	content = strings.Repeat("a@example.net ", 33)
	if w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`); w.Code != 502 || strings.Contains(w.Body.String(), "a@example.net") {
		t.Fatal("tool unknown released")
	}
	content = "one@example.net"
	f.g.Audit.mu.Lock()
	f.g.Audit.failed = true
	f.g.Audit.mu.Unlock()
	if w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`); w.Code != 503 || strings.Contains(w.Body.String(), redactionMarker) {
		t.Fatal("tool audit failure released text")
	}
}

func TestRedactionToolFinalAuditFailureNeverReleasesText(t *testing.T) {
	var f toolFixture
	f = newToolFixture(t, func(*http.Request) (*http.Response, error) {
		f.g.Audit.mu.Lock()
		f.g.Audit.failed = true
		f.g.Audit.mu.Unlock()
		return toolResponse(200, `{"text":"unit@example.net"}`), nil
	})
	selectOutputVersion(t, f.g, sensitive.Version2, "redact")
	w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 503 || strings.Contains(w.Body.String(), redactionMarker) || strings.Contains(w.Body.String(), "unit@example.net") || w.Header().Get("X-GovWeave-Output-Action") != "" {
		t.Fatal("final tool audit failure released content")
	}
}
