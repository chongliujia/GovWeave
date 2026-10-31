package server

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/governance"
)

func TestEUReportArchiveAPIAndHistoricalReplay(t *testing.T) {
	evaluator, err := compliance.Open("../../examples/rule-packs")
	if err != nil {
		t.Fatal(err)
	}
	h := handlerWithCompliance(t, evaluator)
	base := "/api/v1/compliance"
	for _, route := range []struct{ method, path string }{{"GET", base + "/packs/eu-ai-act-chatbot-transparency/versions/0.1.0"}, {"POST", base + "/products/unknown/reports"}, {"GET", base + "/products/unknown/reports"}, {"GET", base + "/reports/unknown"}, {"POST", base + "/reports/unknown/replay"}} {
		if invoke(h, route.method, route.path, `{}`, "", nil).Code != 401 {
			t.Fatal("archive API missing administrator authentication")
		}
	}
	w := invoke(h, "GET", base+"/packs/eu-ai-act-chatbot-transparency/versions/0.1.0", "", testPassword, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"draft"`) || !strings.Contains(w.Body.String(), `"assessment_method":"manual"`) {
		t.Fatal("source-backed draft package unavailable")
	}
	w = invoke(h, "POST", "/api/v1/connections", `{"name":"EU local fixture","base_url":"http://127.0.0.1:1/v1","model":"synthetic","alias":"eu-support","enabled":true,"allow_insecure_http":true,"timeout_seconds":1}`, testPassword, nil)
	var connection struct{ ID string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &connection) != nil {
		t.Fatal("connection setup failed")
	}
	w = invoke(h, "POST", "/api/v1/applications", fmt.Sprintf(`{"name":"EU support fixture","allowed_connections":[%q]}`, connection.ID), testPassword, nil)
	var app applicationResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &app) != nil {
		t.Fatal("application setup failed")
	}
	data, err := os.ReadFile("../../examples/eu-customer-support-product.json")
	if err != nil {
		t.Fatal(err)
	}
	var input governance.ProductInput
	if json.Unmarshal(data, &input) != nil {
		t.Fatal("invalid product example")
	}
	input.ApplicationIDs = []string{app.Application.ID}
	for key, fact := range input.Facts {
		fact.ObservedAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
		input.Facts[key] = fact
	}
	marshal := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	w = invoke(h, "POST", base+"/products", marshal(input), testPassword, nil)
	var product governance.Product
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &product) != nil {
		t.Fatal("EU product setup failed")
	}
	path := base + "/products/" + product.ID + "/reports"
	for _, headers := range []map[string]string{{"Origin": "https://untrusted.example"}, {"X-GovWeave-Request": ""}} {
		if invoke(h, "POST", path, `{}`, testPassword, headers).Code != 403 {
			t.Fatal("cross-site archive capture allowed")
		}
	}
	if invoke(h, "POST", path, `{"facts":{}}`, testPassword, nil).Code != 400 {
		t.Fatal("archive input override accepted")
	}
	w = invoke(h, "POST", path, `{}`, testPassword, nil)
	var archive governance.ArchivedReport
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &archive) != nil {
		t.Fatalf("archive capture failed: %d %s", w.Code, w.Body.String())
	}
	if archive.Summary.Status != "insufficient_evidence" || len(archive.Summary.SHA256) != 64 || archive.Snapshot.RulePack.Review.Status != "draft" || archive.Snapshot.Report.Evaluation.LegalCompliance != "not_determined" {
		t.Fatal("draft report was presented as a legal conclusion")
	}
	categories := map[string]bool{}
	for _, finding := range archive.Snapshot.Report.Evaluation.Findings {
		categories[finding.Category] = true
	}
	if !categories["evidence_gap"] || !categories["manual_review"] {
		t.Fatal("missing evidence and manual review were not distinguished")
	}
	reportPath := base + "/reports/" + archive.Summary.ID
	if invoke(h, "GET", reportPath, "", app.APIKey, nil).Code != 401 {
		t.Fatal("inference key read archived profile evidence")
	}
	w = invoke(h, "POST", reportPath+"/replay", `{}`, testPassword, nil)
	var replay governance.ReplayResult
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &replay) != nil || !replay.Matches {
		t.Fatal("saved report replay failed")
	}
	input.Revision = product.Revision
	input.Version = "2.0.0"
	input.Facts["transparency.notice_present"] = compliance.Fact{Value: json.RawMessage("false"), EvidenceID: "synthetic-ui-test", Source: "assessment", ObservedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	if invoke(h, "PUT", base+"/products/"+product.ID, marshal(input), testPassword, nil).Code != 200 {
		t.Fatal("product update failed")
	}
	w = invoke(h, "GET", reportPath, "", testPassword, nil)
	var saved governance.ArchivedReport
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Snapshot.Product.Version != "1.0.0" || saved.Summary.SHA256 != archive.Summary.SHA256 {
		t.Fatal("report changed after live profile update")
	}
	w = invoke(h, "POST", path, `{}`, testPassword, nil)
	var second governance.ArchivedReport
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &second) != nil || second.Summary.ID == archive.Summary.ID || second.Summary.Status != "gaps_detected" {
		t.Fatal("new report did not retain new known gap")
	}
	w = invoke(h, "GET", path, "", testPassword, nil)
	var listing struct {
		Reports []governance.ReportSummary `json:"reports"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &listing) != nil || len(listing.Reports) != 2 {
		t.Fatal("report listing missing snapshots")
	}
	if invoke(h, "GET", base+"/reports/rpt_unknown", "", testPassword, nil).Code != 404 {
		t.Fatal("missing report did not return 404")
	}
	if invoke(h, "POST", reportPath+"/replay", fmt.Sprintf(`{"product_id":%q}`, product.ID), testPassword, nil).Code != 400 {
		t.Fatal("replay accepted replacement input")
	}
}
