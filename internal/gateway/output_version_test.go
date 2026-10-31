package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"govweave/internal/sensitive"
)

func selectOutputVersion(t *testing.T, g *Engine, version, mode string) OutputPolicySnapshot {
	t.Helper()
	in := g.OutputPolicies.Snapshot().OutputPolicyInput
	in.DetectorVersion, in.Mode = version, mode
	p, err := g.OutputPolicies.Save(in, g.Store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVersionedInspectionAndToolOutput(t *testing.T) {
	content := "versioned [at] example [dot] net"
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) {
		data, _ := json.Marshal(map[string]string{"text": content})
		return toolResponse(200, string(data)), nil
	})
	for _, version := range []string{sensitive.Version, sensitive.Version2} {
		p := selectOutputVersion(t, f.g, version, "block")
		body, _ := json.Marshal(map[string]string{"text": content})
		w := evaluateText(f.g, f.key, string(body))
		var result struct {
			Detection sensitive.Result `json:"detection"`
			Policy    OutputAssessment `json:"policy"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Detection.DetectorVersion != version || result.Policy.DetectorVersion != version {
			t.Fatal("inspection version mismatch")
		}
		want, status := "allow", 200
		if version == sensitive.Version2 {
			want, status = "block", 403
		}
		if result.Policy.Result != want {
			t.Fatal("wrong inspection verdict")
		}
		w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
		if w.Code != status || status == 403 && strings.Contains(w.Body.String(), content) {
			t.Fatal("versioned tool enforcement mismatch", w.Code)
		}
		audit := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
		if audit.OutputPolicy.DetectorVersion != version || audit.OutputPolicy.Revision != p.Revision || audit.ToolGovernance.OutputPolicy.DetectorVersion != version {
			t.Fatal("tool evidence version mismatch")
		}
	}
	selectOutputVersion(t, f.g, sensitive.Version2, "observe")
	w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), content) {
		t.Fatal("observe rewrote original text")
	}
}

func TestModelPinsDetectorGenerationAcrossPolicyChange(t *testing.T) {
	const content = "pinned [at] example [dot] net"
	var f fixture
	f = newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		selectOutputVersion(t, f.engine, sensitive.Version, "block")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, completionText(content, "stop"))
	})
	pinned := selectOutputVersion(t, f.engine, sensitive.Version2, "block")
	w := f.call(f.key, chatBody("internal-assistant", false))
	record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
	if w.Code != 403 || record.OutputPolicy.DetectorVersion != sensitive.Version2 || record.OutputPolicy.Revision != pinned.Revision {
		t.Fatal("in-flight generation changed")
	}
	if f.call(f.key, chatBody("internal-assistant", false)).Code != 200 {
		t.Fatal("new requests did not use selected v1 generation")
	}
}

func TestV3ToolAndInspectionPinVersionAndRedactEncodedEmail(t *testing.T) {
	const content = "cHJpdmF0ZS5wZXJzb25AZXhhbXBsZS50ZXN0"
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) {
		return toolResponse(200, `{"text":"`+content+`"}`), nil
	})
	old := selectOutputVersion(t, f.g, sensitive.Version2, "redact")
	if w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`); w.Code != 200 || !strings.Contains(w.Body.String(), content) {
		t.Fatal("v2 baseline changed", w.Code)
	}
	p := selectOutputVersion(t, f.g, sensitive.Version3, "redact")
	w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || strings.Contains(w.Body.String(), content) || !strings.Contains(w.Body.String(), redactionMarker) {
		t.Fatal("encoded tool result escaped", w.Code, w.Body.String())
	}
	record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.OutputPolicy.DetectorVersion != sensitive.Version3 || record.OutputPolicy.Revision != p.Revision || record.OutputPolicy.Result != "redacted" {
		t.Fatal("v3 tool audit missing")
	}
	w = evaluateText(f.g, f.key, `{"text":"`+content+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"base64_email_address"`) || strings.Contains(w.Body.String(), content) {
		t.Fatal("v3 inspection mismatch", w.Body.String())
	}
	history, err := f.g.OutputPolicies.Revision(old.Revision)
	if err != nil || history.DetectorVersion != sensitive.Version2 {
		t.Fatal("historical policy changed")
	}
	data, _ := json.Marshal(record)
	if strings.Contains(string(data), content) || strings.Contains(string(data), "private.person") {
		t.Fatal("encoded or decoded value retained in audit")
	}
}

func TestV3ModelRedactionAndFormatPermission(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"**release@product.example**", "**release@product.example**"},
		{"cHJpdmF0ZS5wZXJzb25AZXhhbXBsZS50ZXN0", redactionMarker},
	} {
		f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, completionText(tc.text, "stop"))
		})
		in := f.engine.OutputPolicies.Snapshot().OutputPolicyInput
		in.Mode, in.DetectorVersion, in.PublicEmails = "redact", sensitive.Version3, []string{"release@product.example"}
		if _, err := f.engine.OutputPolicies.Save(in, f.engine.Store.Snapshot()); err != nil {
			t.Fatal(err)
		}
		w := f.call(f.key, chatBody("internal-assistant", false))
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatal("v3 model enforcement mismatch", w.Code, w.Body.String())
		}
		record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
		if record.OutputPolicy.DetectorVersion != sensitive.Version3 || (tc.want == redactionMarker && record.OutputPolicy.Result != "redacted") || (tc.want != redactionMarker && record.OutputPolicy.PublicEmailExceptions != 1) {
			t.Fatal("v3 model evidence mismatch")
		}
	}
}
