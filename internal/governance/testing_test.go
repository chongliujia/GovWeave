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

	"govweave/internal/compliance"
	"govweave/internal/gateway"
)

func activeFixture(t *testing.T, provider http.Handler, edit func(*TestSuite)) (fixture, Product, TestPlan) {
	t.Helper()
	f := setup(t)
	f.service.Close()
	mock := httptest.NewServer(provider)
	t.Cleanup(mock.Close)
	suitesDir := filepath.Join(f.dir, "test-suites")
	if err := os.Mkdir(suitesDir, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/test-suites/chat-contract-smoke.json")
	if err != nil {
		t.Fatal(err)
	}
	var suite TestSuite
	if json.Unmarshal(data, &suite) != nil {
		t.Fatal("invalid example")
	}
	if edit != nil {
		edit(&suite)
	}
	data, _ = json.Marshal(suite)
	if err := os.WriteFile(filepath.Join(suitesDir, "contract.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	f.connection, err = f.gateway.Store.SaveConnection(f.connection.ID, gateway.ConnectionInput{Revision: f.connection.Revision, Name: "Synthetic model", BaseURL: mock.URL + "/v1", Model: "fixture-model", Alias: "assistant", Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = Open(f.dir, f.gateway, f.evaluator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.service.Close)
	input := f.input()
	input.PackID, input.PackVersion = "nist-ai-rmf-lifecycle", "0.1.0"
	product, err := f.service.Save("", input)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.service.Tests.SavePlan(product.ID, TestPlanInput{ApplicationID: f.app.ID, ModelAlias: "assistant", TargetVersion: "release-1", SuiteID: suite.ID, SuiteVersion: suite.Version, Context: "Synthetic API contract in staging; no representative risk coverage claimed", IntervalSeconds: 300, TimeoutSeconds: 1, MaxOutputTokens: 64})
	if err != nil {
		t.Fatal(err)
	}
	return f, product, plan
}

func contractProvider(mode *atomic.Int32, calls *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct {
			Model     string        `json:"model"`
			Stream    bool          `json:"stream"`
			MaxTokens int           `json:"max_tokens"`
			Messages  []TestMessage `json:"messages"`
		}
		if r.URL.Path != "/v1/chat/completions" || json.NewDecoder(r.Body).Decode(&body) != nil || body.Model != "fixture-model" || body.Stream || body.MaxTokens != 64 {
			w.WriteHeader(400)
			return
		}
		if mode.Load() == 2 {
			w.WriteHeader(500)
			_, _ = w.Write([]byte("provider-private-detail"))
			return
		}
		content := "GOVWEAVE_TEST_OK"
		if strings.Contains(body.Messages[0].Content, "JSON") {
			content = `{"status":"ok"}`
		}
		if mode.Load() == 1 {
			content = "unexpected"
		}
		finish := "stop"
		if mode.Load() == 3 {
			finish = "length"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": content}, "finish_reason": finish}}})
	})
}

func waitTestRun(t *testing.T, a *ActiveTests, id string) TestRun {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		run, err := a.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if run.State != "running" {
			return run
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("test run did not finish")
	return TestRun{}
}

func startTestRun(t *testing.T, a *ActiveTests, product, phase string) TestRun {
	t.Helper()
	summary, err := a.Start(product, phase, "manual")
	if err != nil {
		t.Fatal(err)
	}
	return waitTestRun(t, a, summary.ID)
}

func controlStatus(t *testing.T, run TestRun, id string) string {
	t.Helper()
	if run.Evaluation == nil {
		t.Fatalf("missing evaluation: %s", run.ErrorCode)
	}
	for _, control := range run.Evaluation.Controls {
		if control.ID == id {
			return control.Status
		}
	}
	t.Fatal("missing control", id)
	return ""
}

func TestActiveLifecycleEvidenceRegressionAndReplay(t *testing.T) {
	var mode, calls atomic.Int32
	f, product, _ := activeFixture(t, contractProvider(&mode, &calls), nil)
	a := f.service.Tests
	pre := startTestRun(t, a, product.ID, "pre_deployment")
	if pre.Status != "passed" || controlStatus(t, pre, "NIST-PREDEPLOYMENT-TEST") != "pass" || controlStatus(t, pre, "NIST-OPERATION-TEST") != "unknown" {
		t.Fatal("incorrect pre-deployment evidence")
	}
	op := startTestRun(t, a, product.ID, "operation")
	if op.Status != "passed" || controlStatus(t, op, "NIST-PREDEPLOYMENT-TEST") != "pass" || controlStatus(t, op, "NIST-OPERATION-TEST") != "pass" {
		t.Fatal("lifecycle evidence was not linked")
	}
	if controlStatus(t, op, "NIST-INDEPENDENT-REVIEW") != "unknown" || op.Evaluation.LegalCompliance != "not_determined" {
		t.Fatal("technical tests approved human or legal judgements")
	}
	mode.Store(1)
	regression := startTestRun(t, a, product.ID, "operation")
	if regression.Status != "failed" || regression.Comparison == nil || regression.Comparison.Regressions != 2 || regression.Comparison.PreviousRunID != op.ID || controlStatus(t, regression, "NIST-OPERATION-TEST") != "fail" {
		t.Fatal("regression not retained")
	}
	mode.Store(2)
	failedRequest := startTestRun(t, a, product.ID, "operation")
	if failedRequest.Status != "inconclusive" || controlStatus(t, failedRequest, "NIST-OPERATION-TEST") != "unknown" {
		t.Fatal("provider error became a compliance verdict")
	}
	if _, exists := failedRequest.Input.Facts["testing.operation.passed"]; exists {
		t.Fatal("old pass survived incomplete testing")
	}
	mode.Store(3)
	truncated := startTestRun(t, a, product.ID, "operation")
	if truncated.Status != "inconclusive" {
		t.Fatal("truncated output passed")
	}
	count := calls.Load()
	f.service.Close()
	// Changing the installed suite does not alter retained decisions.
	data, _ := os.ReadFile(filepath.Join(f.dir, "test-suites", "contract.json"))
	var suite TestSuite
	_ = json.Unmarshal(data, &suite)
	suite.Description += " changed after capture"
	data, _ = json.Marshal(suite)
	if os.WriteFile(filepath.Join(f.dir, "test-suites", "contract.json"), data, 0600) != nil {
		t.Fatal("write suite")
	}
	reopened, err := Open(f.dir, f.gateway, f.evaluator)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	replay, err := reopened.Tests.Replay(op.ID)
	if err != nil || !replay.Matches || calls.Load() != count {
		t.Fatal("replay requested a model or lost its decision", err)
	}
	if reopened.Tests.Catalog()[0].SHA256 == op.SuiteSHA256 {
		t.Fatal("test did not change the active suite")
	}
	for _, name := range []string{"test-plans.json", "test-runs/" + op.ID + ".json"} {
		info, err := os.Stat(filepath.Join(f.dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("evidence must be private", err)
		}
	}
	for _, run := range []TestRun{pre, op, failedRequest} {
		data, _ := json.Marshal(run)
		if strings.Contains(string(data), f.key) || strings.Contains(string(data), "provider-private-detail") {
			t.Fatal("private provider data leaked")
		}
		for _, result := range run.Cases {
			if result.Response != nil {
				t.Fatal("response retained without opt-in")
			}
		}
	}
}

func TestActiveScheduleOptInAndVersionBoundaries(t *testing.T) {
	var mode, calls atomic.Int32
	f, product, plan := activeFixture(t, contractProvider(&mode, &calls), nil)
	a := f.service.Tests
	a.dispatchDue(time.Now().Add(24 * time.Hour))
	if calls.Load() != 0 {
		t.Fatal("disabled scheduler called target")
	}
	_ = startTestRun(t, a, product.ID, "pre_deployment")
	plan.ScheduleEnabled = true
	plan.RetainResponses = true
	plan, err := a.SavePlan(product.ID, plan.TestPlanInput)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise exactly the scheduler dispatch used by the live one-second tick,
	// without waiting five minutes in a unit test.
	a.mu.Lock()
	plan.NextRunAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	a.plans[product.ID] = plan
	if a.persistPlansLocked() != nil {
		t.Fatal("persist due plan")
	}
	a.mu.Unlock()
	a.dispatchDue(time.Now())
	current, _ := a.Plan(product.ID)
	run := waitTestRun(t, a, current.LastRunID)
	if run.Trigger != "scheduled" || run.Phase != "operation" || run.Status != "passed" || run.Cases[0].Response == nil {
		t.Fatal("scheduled run did not retain selected evidence")
	}
	if controlStatus(t, run, "NIST-PREDEPLOYMENT-TEST") != "unknown" {
		t.Fatal("old plan evidence crossed revision boundary")
	}
	count := calls.Load()
	a.dispatchDue(time.Now())
	if calls.Load() != count {
		t.Fatal("scheduler repeated before next interval")
	}
	input := product.ProductInput
	input.Version = "release-2"
	input.Revision = product.Revision
	if _, err := f.service.Save(product.ID, input); err != nil {
		t.Fatal(err)
	}
	updated := startTestRun(t, a, product.ID, "operation")
	if updated.Comparison != nil || controlStatus(t, updated, "NIST-PREDEPLOYMENT-TEST") != "unknown" {
		t.Fatal("old product evidence reused")
	}
	input.Facts["testing.operation.passed"] = compliance.Fact{Value: json.RawMessage("true"), EvidenceID: "forged", Source: "assessment", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if _, err := f.service.Save("", input); err == nil {
		t.Fatal("forged test facts accepted")
	}
}

func TestActiveGatewayBlockingIsNotEndpointOutput(t *testing.T) {
	var mode, calls atomic.Int32
	f, product, _ := activeFixture(t, contractProvider(&mode, &calls), func(s *TestSuite) {
		s.Cases = []TestCase{{ID: "block", Title: "Synthetic credential check", Scope: "gateway_control", Check: "credential_block", Messages: []TestMessage{{Role: "user", Content: "sk-synthetic-test-secret-012345678901234567890"}}}}
	})
	setMode(t, f, "block")
	run := startTestRun(t, f.service.Tests, product.ID, "pre_deployment")
	if run.Status != "passed" || run.Cases[0].HTTPStatus != 403 || calls.Load() != 0 {
		t.Fatal("blocked test reached provider")
	}
	input := capture(f.gateway).input(product, time.Now())
	if string(input.Facts["runtime.sample.request_count"].Value) != "0" {
		t.Fatal("test traffic counted as business traffic")
	}
	view := f.gateway.Audit.View(100, "")
	if len(view.Records) != 1 || view.Records[0].Operation != "assessment.chat.completions" || view.Records[0].UpstreamAttempted {
		t.Fatal("test request not labelled correctly")
	}
	request := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"assistant","messages":[{"role":"user","content":"hello"}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Application-ID", f.app.ID)
	w := httptest.NewRecorder()
	f.gateway.Chat(w, request)
	if w.Code != 401 {
		t.Fatal("public handler accepted assessment identity")
	}
}

func TestActiveAdmissionConcurrencyCancellationAndCapacity(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	defer close(release)
	f, product, plan := activeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), nil)
	a := f.service.Tests
	started, err := a.Start(product.ID, "pre_deployment", "manual")
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	if _, err := a.Start(product.ID, "operation", "manual"); !errors.Is(err, ErrTestBusy) {
		t.Fatal("overlapping product run admitted")
	}
	plan.Context = "updated while test runs"
	if _, err := a.SavePlan(product.ID, plan.TestPlanInput); err != nil {
		t.Fatal(err)
	}
	run := waitTestRun(t, a, started.ID)
	if run.State != "error" || run.ErrorCode != "test_source_changed" || run.Evaluation != nil {
		t.Fatal("source change published a verdict")
	}
	if _, _, err := f.gateway.Store.ChangeKey(f.app.ID, f.app.Revision, true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Start(product.ID, "operation", "manual"); !errors.Is(err, gateway.ErrInvalidKey) {
		t.Fatal("revoked app admitted")
	}
	a.mu.Lock()
	for i := len(a.runs); i < MaxTestRuns; i++ {
		a.runs[time.Unix(int64(i), 0).String()] = TestRunSummary{}
	}
	a.mu.Unlock()
	if _, err := a.Start(product.ID, "operation", "manual"); !errors.Is(err, ErrTestCapacity) {
		t.Fatal("capacity did not stop execution")
	}
}

func TestTestSuiteValidationAndEvidenceCorruption(t *testing.T) {
	var mode, calls atomic.Int32
	f, product, _ := activeFixture(t, contractProvider(&mode, &calls), nil)
	run := startTestRun(t, f.service.Tests, product.ID, "pre_deployment")
	path := filepath.Join(f.dir, "test-runs", run.ID+".json")
	data, _ := os.ReadFile(path)
	if os.WriteFile(path, append(data, 'x'), 0600) != nil {
		t.Fatal("corrupt evidence")
	}
	if _, err := f.service.Tests.Get(run.ID); !errors.Is(err, ErrTestUnavailable) {
		t.Fatal("corruption hidden")
	}
	f.service.Close()
	if _, err := Open(f.dir, f.gateway, f.evaluator); err == nil {
		t.Fatal("corrupt evidence accepted after restart")
	}
	for _, edit := range []func(*TestSuite){
		func(s *TestSuite) { s.Cases[0].Check = "script" },
		func(s *TestSuite) { s.Cases[0].Scope = "gateway_control" },
		func(s *TestSuite) { s.Cases[0].Expected = "" },
		func(s *TestSuite) { s.Cases = append(s.Cases, s.Cases[0]) },
	} {
		suite, _ := f.service.Tests.Suite("chat-contract-smoke", "1.0.0")
		edit(&suite)
		if validateSuite(suite) == nil {
			t.Fatal("invalid suite accepted")
		}
	}
}
