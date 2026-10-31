package governance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/gateway"
)

func serviceToolInput(applicationID string) gateway.ToolInput {
	return gateway.ToolInput{Name: "Product reader", Alias: "product-reader", Endpoint: "https://provider.example/read", Enabled: true, TimeoutSeconds: 1, OutputMode: "block", Resources: []gateway.ToolResource{{ID: "private-resource", Sensitivity: "internal", AllowedApplications: []string{applicationID}}}}
}

func TestToolConfigurationChangesInvalidateCachedProductAssessment(t *testing.T) {
	f := setup(t)
	f.service.Close()
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.service.Refresh(product.ID)
	if err != nil || before.State != "ready" || before.Snapshot.ToolRevision != 0 {
		t.Fatal("initial assessment missing", err)
	}
	in := serviceToolInput(f.app.ID)
	tool, err := f.gateway.Tools.Save("", in)
	if err != nil {
		t.Fatal(err)
	}
	current := currentStamp(f.gateway, product)
	if current.ToolRevision != 1 || current.AuditBytes != before.Snapshot.AuditBytes || current.GatewayRevision != before.Snapshot.GatewayRevision {
		t.Fatal("tool-only edit did not isolate the freshness change")
	}
	pending, err := f.service.Latest(product.ID)
	if err != nil || pending.State != "pending" || pending.Evaluation != nil {
		t.Fatal("stale assessment remained current after tool creation", err)
	}
	after, err := f.service.Refresh(product.ID)
	if err != nil || after.Snapshot.ToolRevision != tool.Revision {
		t.Fatal("assessment did not capture current tool revision", err)
	}
	in.Revision, in.OutputMode = tool.Revision, "observe"
	if _, err := f.gateway.Tools.Save(tool.ID, in); err != nil {
		t.Fatal(err)
	}
	pending, _ = f.service.Latest(product.ID)
	if pending.State != "pending" || pending.Evaluation != nil {
		t.Fatal("stale assessment remained current after output policy change")
	}
	facts := capture(f.gateway).input(product, time.Now()).Facts
	if string(facts["runtime.tools.output_blocking_covers_product"].Value) != "false" {
		t.Fatal("observe policy did not change current facts")
	}
}

func TestAutomaticAssessmentRefreshesOnToolConfigurationNotification(t *testing.T) {
	f := setup(t)
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	before := await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Snapshot.ToolRevision == 0 })
	tool, err := f.gateway.Tools.Save("", serviceToolInput(f.app.ID))
	if err != nil {
		t.Fatal(err)
	}
	f.gateway.NotifyChange()
	after := await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Snapshot.ToolRevision == tool.Revision })
	if before.Snapshot.AuditBytes != after.Snapshot.AuditBytes || before.Snapshot.GatewayRevision != after.Snapshot.GatewayRevision {
		t.Fatal("test unexpectedly depended on calls or model configuration")
	}
}

func TestLegacyReportWithoutToolRevisionOrFactsStillReplays(t *testing.T) {
	f := setup(t)
	f.service.Close()
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	_, input, report, err := f.service.assess(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Construct the pre-tool snapshot shape using the retained evaluation time;
	// old reports have neither a tool_revision key nor runtime.tools.* facts.
	for key := range input.Facts {
		if strings.HasPrefix(key, "runtime.tools.") {
			delete(input.Facts, key)
		}
	}
	pack, err := f.evaluator.PackSnapshot(product.PackID, product.PackVersion)
	if err != nil {
		t.Fatal(err)
	}
	at, _ := time.Parse(time.RFC3339Nano, report.Evaluation.EvaluatedAt)
	evaluation, err := compliance.EvaluateSnapshot(pack, input, at)
	if err != nil {
		t.Fatal(err)
	}
	report.Evaluation = &evaluation
	report.Snapshot.ToolRevision = 0
	report.RuntimeEvidence = nil // The legacy format also predates retained per-request evidence.
	archive, err := f.service.Archives.save(ReportSnapshot{Product: product, Input: input, Report: report, RulePack: pack})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "assessment-reports", archive.Summary.ID+".json")
	before, err := os.ReadFile(path)
	if err != nil || bytes.Contains(before, []byte("tool_revision")) || bytes.Contains(before, []byte("runtime.tools.")) {
		t.Fatal("legacy fixture contains new fields", err)
	}
	if _, err := f.gateway.Tools.Save("", serviceToolInput(f.app.ID)); err != nil {
		t.Fatal(err)
	}
	reopened, err := openArchives(f.dir)
	if err != nil {
		t.Fatal("legacy archive could not be reopened", err)
	}
	replay, err := reopened.Replay(archive.Summary.ID)
	if err != nil || !replay.Matches || !reflect.DeepEqual(replay.Evaluation, evaluation) {
		t.Fatal("legacy report replay followed current tool configuration", err)
	}
	saved, err := reopened.Get(archive.Summary.ID)
	if err != nil || saved.Snapshot.Report.Snapshot.ToolRevision != 0 {
		t.Fatal("legacy omitted tool revision changed", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("legacy file was rewritten", err)
	}
	encoded, _ := json.Marshal(saved.Snapshot.Report.Snapshot)
	if bytes.Contains(encoded, []byte("tool_revision")) {
		t.Fatal("zero optional stamp changed old serialization")
	}
}
