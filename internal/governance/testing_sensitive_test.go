package governance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"govweave/internal/compliance"
)

func sensitiveActiveFixture(t *testing.T, mode *atomic.Int32, beforeServe ...func()) (fixture, Product, TestPlan) {
	t.Helper()
	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, hook := range beforeServe {
			hook()
		}
		var body struct {
			Messages []TestMessage `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Messages) != 1 {
			w.WriteHeader(400)
			return
		}
		if mode.Load() == 2 {
			w.WriteHeader(500)
			return
		}
		if mode.Load() == 3 {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":{"code":"content_output_blocked"}}`))
			return
		}
		text := "GOVWEAVE_OUTPUT_READY"
		for category, candidate := range map[string]string{"credential": "sk-SyntheticOutputProbeNeverReal12345678901234567890", "email": "probe.person@example.com", "phone": "+86 138 0000 0017"} {
			if strings.Contains(body.Messages[0].Content, "("+category+")") {
				text = candidate
			}
		}
		if mode.Load() == 1 && strings.Contains(body.Messages[0].Content, "(email)") {
			text = "I cannot provide that."
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}}})
	})
	f, product, plan := activeFixture(t, provider, func(suite *TestSuite) {
		*suite = TestSuite{}
		data, err := os.ReadFile("../../examples/test-suites/sensitive-output-controls.json")
		if err != nil || json.Unmarshal(data, suite) != nil {
			t.Fatal("invalid output suite", err)
		}
	})
	in := product.ProductInput
	in.PackID, in.PackVersion = "sensitive-output-governance", "1.1.0"
	var err error
	product, err = f.service.Save(product.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	return f, product, plan
}

func setSensitiveMode(t *testing.T, f fixture, mode string) {
	t.Helper()
	in := f.gateway.OutputPolicies.Snapshot().OutputPolicyInput
	in.Mode, in.DetectorVersion = mode, "sensitive-text-v2"
	if _, err := f.gateway.OutputPolicies.Save(in, f.gateway.Store.Snapshot()); err != nil {
		t.Fatal(err)
	}
	f.gateway.NotifyChange()
}

func startSensitiveRun(t *testing.T, f fixture, product Product, phase string) TestRun {
	t.Helper()
	started, err := f.service.Tests.Start(product.ID, phase, "manual")
	if err != nil {
		t.Fatal(err)
	}
	return waitTestRun(t, f.service.Tests, started.ID)
}

func TestActiveOutputChecksRequireExecutionAndActualCategory(t *testing.T) {
	for _, tc := range []struct {
		name, policy, status, reason string
		provider                     int32
		auditFailure                 bool
	}{
		{"block", "block", "passed", "sensitive_output_blocked", 0, false},
		{"redact", "redact", "passed", "sensitive_output_redacted", 0, false},
		{"observe releases", "observe", "failed", "sensitive_output_released", 0, false},
		{"disabled", "disabled", "failed", "output_protection_inactive", 0, false},
		{"refusal is not protection proof", "block", "inconclusive", "output_challenge_not_observed", 1, false},
		{"provider failure", "block", "inconclusive", "output_execution_unavailable", 2, false},
		{"provider cannot forge gateway block", "block", "inconclusive", "output_execution_unavailable", 3, false},
		{"audit failure", "block", "inconclusive", "output_audit_unavailable", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mode atomic.Int32
			mode.Store(tc.provider)
			f, product, plan := sensitiveActiveFixture(t, &mode)
			setSensitiveMode(t, f, tc.policy)
			// Even opt-in response retention cannot store probe output text.
			plan.RetainResponses = true
			if _, err := f.service.Tests.SavePlan(product.ID, plan.TestPlanInput); err != nil {
				t.Fatal(err)
			}
			if tc.auditFailure {
				_ = f.gateway.Audit.Close()
			}
			run := startSensitiveRun(t, f, product, "pre_deployment")
			if run.Status != tc.status || len(run.Cases) != 4 || run.Cases[1].Reason != tc.reason {
				t.Fatalf("unexpected run: %s %+v", run.Status, run.Cases)
			}
			for i, result := range run.Cases {
				if result.OutputCheck == nil || result.Response != nil || (i < 3 && (result.ResponseSHA256 != "" || result.ResponseBytes != 0)) {
					t.Fatal("missing receipt or retained probe text")
				}
			}
			if err := validateRun(run); err != nil {
				t.Fatal("new evidence cannot be read", err)
			}
			replay, err := f.service.Tests.Replay(run.ID)
			if err != nil || !replay.Matches {
				t.Fatal("retained test evaluation did not replay", err)
			}
			if run.Status == "inconclusive" {
				if _, ok := run.Input.Facts["testing.output.pre_deployment.passed"]; ok {
					t.Fatal("inconclusive probes became usable evidence")
				}
			} else {
				want := "false"
				if tc.status == "passed" {
					want = "true"
				}
				if string(run.Input.Facts["testing.output.pre_deployment.passed"].Value) != want {
					t.Fatal("missing phase evidence")
				}
			}
		})
	}
}

func TestOutputProbeEvidenceRefreshesProductAndExpiresWithoutBorrowingOldSuccess(t *testing.T) {
	var mode atomic.Int32
	f, product, plan := sensitiveActiveFixture(t, &mode)
	setSensitiveMode(t, f, "block")
	// One normal production request establishes the separate runtime baseline.
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"assistant","messages":[{"role":"user","content":"(benign)"}],"stream":false}`))
	req.Header.Set("Authorization", "Bearer "+f.key)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.gateway.Chat(w, req)
	if w.Code != 200 {
		t.Fatal("benign production request failed", w.Code)
	}
	waitStates := func(pre, op string) Report {
		return await(t, f.service, product.ID, func(r Report) bool {
			if r.State != "ready" || len(r.Evaluation.Controls) != 10 {
				return false
			}
			return r.Evaluation.Controls[8].Status == pre && r.Evaluation.Controls[9].Status == op
		})
	}
	waitStates("unknown", "unknown")
	pre := startSensitiveRun(t, f, product, "pre_deployment")
	waitStates("pass", "unknown")
	op := startSensitiveRun(t, f, product, "operation")
	ready := waitStates("pass", "pass")
	if ready.Evaluation.Status != "satisfied" || ready.Snapshot.TestEvidenceRevision == 0 {
		t.Fatal("runtime and active evidence did not combine")
	}
	archive, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	facts := archive.Snapshot.Input.Facts
	if facts["testing.output.pre_deployment.passed"].EvidenceID != pre.ID || facts["testing.output.operation.passed"].EvidenceID != op.ID {
		t.Fatal("wrong run provenance")
	}
	if string(facts["runtime.sample.output_current_checked_count"].Value) != "1" {
		t.Fatal("active tests inflated production sample")
	}
	expires, _ := time.Parse(time.RFC3339Nano, facts["testing.output.operation.passed"].ExpiresAt)
	deadline, _ := time.Parse(time.RFC3339Nano, ready.Evaluation.ReevaluateAt)
	if !deadline.Equal(expires) {
		t.Fatal("expiry cannot invalidate a cached success")
	}
	later, err := compliance.EvaluateSnapshot(archive.Snapshot.RulePack, archive.Snapshot.Input, expires)
	if err != nil || later.Controls[9].Status != "unknown" || later.Controls[8].Status != "pass" {
		t.Fatal("phase expiry was not honored", err)
	}
	// A newer inconclusive run must remove the old operation success.
	mode.Store(1)
	latest := startSensitiveRun(t, f, product, "operation")
	if latest.Status != "inconclusive" {
		t.Fatal("refusal passed")
	}
	waitStates("pass", "unknown")
	mode.Store(0)
	startSensitiveRun(t, f, product, "operation")
	waitStates("pass", "pass")
	// Plan edits invalidate both phases even without gateway/audit changes.
	plan.Context = "Changed validation context"
	if _, err := f.service.Tests.SavePlan(product.ID, plan.TestPlanInput); err != nil {
		t.Fatal(err)
	}
	pending, err := f.service.Latest(product.ID)
	if err != nil || pending.State != "pending" || pending.Evaluation != nil {
		t.Fatal("plan edit left cached success current", err)
	}
	waitStates("unknown", "unknown")
	startSensitiveRun(t, f, product, "pre_deployment")
	startSensitiveRun(t, f, product, "operation")
	waitStates("pass", "pass")
	f.service.Close()
	f.service, err = Open(f.dir, f.gateway, f.evaluator)
	if err != nil {
		t.Fatal("retained output evidence prevented service restart", err)
	}
	t.Cleanup(f.service.Close)
	waitStates("pass", "pass")
	setSensitiveMode(t, f, "redact")
	waitStates("unknown", "unknown")
	replay, err := f.service.Archives.Replay(archive.Summary.ID)
	if err != nil || !replay.Matches || replay.Evaluation.Status != "satisfied" {
		t.Fatal("later edits rewrote archived evidence", err)
	}
}

func TestRunningOutputProbeWithdrawsOldEvidenceAndSourceChangeAborts(t *testing.T) {
	var mode atomic.Int32
	var hold atomic.Bool
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	f, product, _ := sensitiveActiveFixture(t, &mode, func() {
		if hold.Load() {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
	})
	setSensitiveMode(t, f, "block")
	startSensitiveRun(t, f, product, "operation")
	await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Evaluation.Controls[9].Status == "pass" })
	hold.Store(true)
	started, err := f.service.Tests.Start(product.ID, "operation", "manual")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not reach model")
	}
	await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Evaluation.Controls[9].Status == "unknown" })
	setSensitiveMode(t, f, "redact")
	// Let the current call complete, then require the runner to stop before
	// making any more calls under a different policy revision.
	hold.Store(false)
	release <- struct{}{}
	run := waitTestRun(t, f.service.Tests, started.ID)
	if run.State != "error" || run.ErrorCode != "test_source_changed" || run.Evaluation != nil || len(run.Cases) != 1 {
		t.Fatal("source change published active evidence")
	}
}

func TestOutputSuiteCoverageAndStoredEvidenceValidation(t *testing.T) {
	var mode atomic.Int32
	f, product, _ := sensitiveActiveFixture(t, &mode)
	setSensitiveMode(t, f, "redact")
	run := startSensitiveRun(t, f, product, "pre_deployment")
	data, _ := json.Marshal(run)
	for _, mutate := range []func(*TestRun){
		func(r *TestRun) { r.RunnerVersion = canaryV2TestRunnerVersion },
		func(r *TestRun) { r.Cases[0].OutputCheck.Policy.Revision++ },
		func(r *TestRun) { r.Cases[0].OutputCheck.Policy.Redaction = nil },
		func(r *TestRun) { r.Cases[0].OutputCheck.AuditCommitted = false },
		func(r *TestRun) { r.Cases[0].Status = "fail" },
	} {
		var changed TestRun
		_ = json.Unmarshal(data, &changed)
		mutate(&changed)
		if validateRun(changed) == nil {
			t.Fatal("tampered output-control evidence was accepted")
		}
	}
	partial := run
	partial.Suite.Cases = append([]TestCase{}, run.Suite.Cases[:3]...)
	partial.Cases = append([]TestCaseResult{}, run.Cases[:3]...)
	if _, valid := outputSuiteVerdict(partial); valid {
		t.Fatal("missing benign control accepted as full coverage")
	}
	partial.Suite.Cases[2].Category = "email"
	if _, valid := outputSuiteVerdict(partial); valid {
		t.Fatal("duplicate category accepted as coverage")
	}
}
