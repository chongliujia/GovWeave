package governance

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"govweave/internal/gateway"
)

func toolActiveFixture(t *testing.T, mode *atomic.Int32, beforeServe ...func()) (fixture, Product, TestPlan, gateway.Tool, *atomic.Int32) {
	t.Helper()
	f := setup(t)
	f.service.Close()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		for _, hook := range beforeServe {
			hook()
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 {
			w.WriteHeader(400)
			return
		}
		if mode.Load() == 2 {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":{"code":"tool_not_allowed"}}`))
			return
		}
		text := map[string]string{"probe-credential": "sk-SyntheticToolProbeNeverReal12345678901234567890", "probe-email": "probe.person@example.com", "probe-phone": "+86 138 0000 0017", "probe-benign": "GOVWEAVE_TOOL_READY", "probe-denied": "Synthetic restricted content"}[body["resource_id"]]
		if mode.Load() == 1 && body["resource_id"] == "probe-email" {
			text = "No result"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"text": text})
	}))
	t.Cleanup(provider.Close)
	app, _, err := f.gateway.Store.SaveApplication(f.app.ID, gateway.ApplicationInput{Revision: f.app.Revision, Name: "Tool-only test application", AllowedConnections: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	f.app = app
	resources := []gateway.ToolResource{}
	for _, name := range []string{"credential", "email", "phone", "benign", "denied"} {
		grants := []string{app.ID}
		if name == "denied" {
			grants = []string{}
		}
		resources = append(resources, gateway.ToolResource{ID: "probe-" + name, Sensitivity: "internal", AllowedApplications: grants})
	}
	tool, err := f.gateway.Tools.Save("", gateway.ToolInput{Name: "Synthetic reader", Alias: "synthetic-read", Endpoint: provider.URL + "/read", Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: 2, OutputMode: "observe", Resources: resources})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.dir, "test-suites")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/test-suites/read-tool-output-controls.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tool.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	f.service, err = Open(f.dir, f.gateway, f.evaluator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.service.Close)
	in := f.input()
	in.PackID, in.PackVersion = "sensitive-tool-governance", "1.0.0"
	product, err := f.service.Save("", in)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.service.Tests.SavePlan(product.ID, TestPlanInput{TargetKind: "read_tool", ToolAlias: tool.Alias, ApplicationID: app.ID, TargetVersion: "synthetic-1", SuiteID: "read-tool-output-controls", SuiteVersion: "1.0.0", Context: "Dedicated synthetic read resources", IntervalSeconds: 300, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	return f, product, plan, tool, &calls
}

func editTestTool(t *testing.T, f fixture, tool gateway.Tool, mode string, grantDenied bool) gateway.Tool {
	t.Helper()
	resources := append([]gateway.ToolResource{}, tool.Resources...)
	if grantDenied {
		for i := range resources {
			if resources[i].ID == "probe-denied" {
				resources[i].AllowedApplications = []string{f.app.ID}
			}
		}
	}
	saved, err := f.gateway.Tools.Save(tool.ID, gateway.ToolInput{Revision: f.gateway.Tools.Snapshot().Revision, Name: tool.Name, Alias: tool.Alias, Endpoint: tool.Endpoint, Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: tool.TimeoutSeconds, OutputMode: mode, Resources: resources})
	if err != nil {
		t.Fatal(err)
	}
	f.gateway.NotifyChange()
	return saved
}

func TestActiveReadToolChecksAuthorizationOutputsAndLegacyPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, policy, legacy, want string
		provider                   int32
		grantDenied, auditFailure  bool
	}{
		{"blocking", "block", "observe", "passed", 0, false, false},
		{"redaction", "redact", "observe", "passed", 0, false, false},
		{"legacy block wins", "redact", "block", "passed", 0, false, false},
		{"observation releases", "observe", "observe", "failed", 0, false, false},
		{"missing challenge", "block", "observe", "inconclusive", 1, false, false},
		{"upstream cannot impersonate denial", "block", "observe", "inconclusive", 2, false, false},
		{"permission drift", "block", "observe", "failed", 0, true, false},
		{"audit unavailable", "block", "observe", "inconclusive", 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mode atomic.Int32
			mode.Store(tc.provider)
			f, product, _, tool, calls := toolActiveFixture(t, &mode)
			setSensitiveMode(t, f, tc.policy)
			if tc.legacy != "observe" || tc.grantDenied {
				tool = editTestTool(t, f, tool, tc.legacy, tc.grantDenied)
			}
			if tc.auditFailure {
				_ = f.gateway.Audit.Close()
			}
			run := startSensitiveRun(t, f, product, "pre_deployment")
			if run.Status != tc.want || run.RunnerVersion != toolTestRunnerVersion || len(run.Cases) != 5 || run.ToolID != tool.ID || run.ToolRevision != tool.Revision {
				t.Fatalf("incorrect tool run: %s %+v", run.Status, run.Cases)
			}
			wantCalls := int32(4)
			if tc.grantDenied {
				wantCalls = 5
			}
			if tc.auditFailure {
				wantCalls = 0
			}
			if calls.Load() != wantCalls {
				t.Fatalf("provider calls %d, want %d", calls.Load(), wantCalls)
			}
			if !tc.grantDenied && !tc.auditFailure && (run.Cases[4].Reason != "tool_resource_denied_before_execution" || run.Cases[4].OutputCheck.UpstreamAttempted) {
				t.Fatal("denial did not happen before execution")
			}
			if tc.grantDenied && run.Cases[4].Reason != "tool_resource_was_authorized" {
				t.Fatal("expanded grant passed denial probe")
			}
			if tc.legacy == "block" && (run.Cases[0].Reason != "legacy_tool_credential_blocked" || run.Cases[0].OutputCheck.Policy.Redaction != nil) {
				t.Fatal("legacy block fabricated redaction evidence")
			}
			for _, c := range run.Cases {
				if c.Response != nil || (c.CaseID != "allow-benign" && c.ResponseSHA256 != "") {
					t.Fatal("tool probe retained returned text")
				}
			}
			if _, ok := run.Input.Facts["testing.output.pre_deployment.passed"]; ok {
				t.Fatal("tool results became model evidence")
			}
			for _, name := range []string{"runtime.tools.sample.request_count", "runtime.sample.output_current_checked_count"} {
				fact, present := run.Input.Facts[name]
				if tc.auditFailure {
					if present {
						t.Fatal("unavailable audit emitted a sample")
					}
				} else if string(fact.Value) != "0" {
					t.Fatal("active probes inflated production counters")
				}
			}
			replay, err := f.service.Tests.Replay(run.ID)
			if err != nil || !replay.Matches {
				t.Fatal("tool run replay failed", err)
			}
		})
	}
}

func TestToolEvidenceRefreshRestartAndGrantChangeInvalidation(t *testing.T) {
	var mode atomic.Int32
	f, product, _, tool, calls := toolActiveFixture(t, &mode)
	setSensitiveMode(t, f, "redact")
	req := httptest.NewRequest("POST", "/v1/tools/synthetic-read/invoke", strings.NewReader(`{"resource_id":"probe-benign"}`))
	req.SetPathValue("alias", "synthetic-read")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.gateway.ToolInvoke(w, req)
	if w.Code != 200 {
		t.Fatal("ordinary tool baseline failed", w.Code)
	}
	pre := startSensitiveRun(t, f, product, "pre_deployment")
	op := startSensitiveRun(t, f, product, "operation")
	await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Evaluation.Status == "satisfied" })
	archive, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	facts := archive.Snapshot.Input.Facts
	if facts["testing.tools.output.pre_deployment.passed"].EvidenceID != pre.ID || facts["testing.tools.output.operation.passed"].EvidenceID != op.ID || string(facts["runtime.tools.sample.request_count"].Value) != "1" {
		t.Fatal("tool evidence provenance or sample isolation failed")
	}
	f.service.Close()
	f.service, err = Open(f.dir, f.gateway, f.evaluator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.service.Close)
	await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Evaluation.Status == "satisfied" })
	tool = editTestTool(t, f, tool, "observe", true)
	await(t, f.service, product.ID, func(r Report) bool {
		return r.State == "ready" && r.Evaluation.Controls[9].Status == "unknown" && r.Evaluation.Controls[10].Status == "unknown"
	})
	failed := startSensitiveRun(t, f, product, "operation")
	if failed.Status != "failed" || failed.Cases[4].Status != "fail" {
		t.Fatal("grant drift not detected")
	}
	await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Evaluation.Controls[10].Status == "fail" })
	before := calls.Load()
	replay, err := f.service.Archives.Replay(archive.Summary.ID)
	if err != nil || !replay.Matches || calls.Load() != before {
		t.Fatal("report replay changed or executed tool", err)
	}
	// Keyless in-process jobs still obey revocation; no model grant is required.
	if _, _, err := f.gateway.Store.ChangeKey(f.app.ID, f.app.Revision, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Tests.Start(product.ID, "operation", "manual"); !errors.Is(err, gateway.ErrInvalidKey) {
		t.Fatal("revoked test target admitted", err)
	}
	if calls.Load() != before {
		t.Fatal("revoked target contacted provider")
	}
}

func TestReadToolSuiteAndPlanRejectMixedTargets(t *testing.T) {
	var mode atomic.Int32
	f, product, plan, tool, calls := toolActiveFixture(t, &mode)
	for _, change := range []func(*TestPlanInput){
		func(p *TestPlanInput) { p.ModelAlias = "assistant" }, func(p *TestPlanInput) { p.MaxOutputTokens = 64 }, func(p *TestPlanInput) { p.TargetKind = "" }, func(p *TestPlanInput) { p.ToolAlias = "missing" },
	} {
		in := plan.TestPlanInput
		change(&in)
		if _, err := f.service.Tests.SavePlan(product.ID, in); err == nil {
			t.Fatal("invalid target accepted")
		}
	}
	suite, err := f.service.Tests.Suite(plan.SuiteID, plan.SuiteVersion)
	if err != nil {
		t.Fatal(err)
	}
	suite.Cases[0].Messages = []TestMessage{{Role: "user", Content: "Unexpected model request"}}
	if validateSuite(suite) == nil {
		t.Fatal("tool suite accepted model messages")
	}
	tool.Resources[0].AllowedApplications = nil
	if _, err := f.gateway.Tools.Save(tool.ID, gateway.ToolInput{Revision: tool.Revision, Name: tool.Name, Alias: tool.Alias, Endpoint: tool.Endpoint, Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: 2, OutputMode: "observe", Resources: tool.Resources}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Tests.Start(product.ID, "operation", "manual"); !errors.Is(err, gateway.ErrDenied) {
		t.Fatal("withdrawn output grant admitted", err)
	}
	if calls.Load() != 0 {
		t.Fatal("admission checks executed a provider")
	}
}

func TestToolConfigurationChangeDuringProbeStopsRemainingCalls(t *testing.T) {
	var mode atomic.Int32
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	f, product, _, tool, calls := toolActiveFixture(t, &mode, func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	})
	setSensitiveMode(t, f, "block")
	started, err := f.service.Tests.Start(product.ID, "pre_deployment", "manual")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("tool not reached")
	}
	editTestTool(t, f, tool, "block", false)
	release <- struct{}{}
	run := waitTestRun(t, f.service.Tests, started.ID)
	if run.State != "error" || run.ErrorCode != "test_source_changed" || run.Evaluation != nil || calls.Load() != 1 {
		t.Fatal("source drift published a verdict or executed remaining cases")
	}
}
