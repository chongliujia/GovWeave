package governance

import (
	"encoding/json"
	"errors"
	"fmt"
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

func dualPlanFixture(t *testing.T, modelMode *atomic.Int32, hook func()) (fixture, Product, TestPlan, *atomic.Int32) {
	t.Helper()
	var toolMode atomic.Int32
	f, product, _, _, toolCalls := toolActiveFixture(t, &toolMode)
	f.service.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hook != nil {
			hook()
		}
		var body struct {
			Messages []TestMessage `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Messages) != 1 {
			w.WriteHeader(400)
			return
		}
		text := "GOVWEAVE_OUTPUT_READY"
		for category, candidate := range map[string]string{"credential": "sk-SyntheticOutputProbeNeverReal12345678901234567890", "email": "probe.person@example.com", "phone": "+86 138 0000 0017"} {
			if strings.Contains(body.Messages[0].Content, "("+category+")") {
				text = candidate
			}
		}
		if modelMode.Load() == 1 && strings.Contains(body.Messages[0].Content, "(email)") {
			text = "No challenge"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}}})
	}))
	t.Cleanup(provider.Close)
	var err error
	f.connection, err = f.gateway.Store.SaveConnection(f.connection.ID, gateway.ConnectionInput{Revision: f.connection.Revision, Name: "Dual-plan synthetic model", BaseURL: provider.URL + "/v1", Model: "local", Alias: "assistant", Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	f.app, _, err = f.gateway.Store.SaveApplication(f.app.ID, gateway.ApplicationInput{Revision: f.app.Revision, Name: "Dual-target application", AllowedConnections: []string{f.connection.ID}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/test-suites/sensitive-output-controls.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.dir, "test-suites", "model.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	f.service, err = Open(f.dir, f.gateway, f.evaluator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.service.Close)
	in := product.ProductInput
	in.PackID, in.PackVersion = "application-output-governance", "1.0.0"
	// Exercise the full profile allowance with both evidence namespaces.
	for i := len(in.Facts); i < 112; i++ {
		in.Facts[fmt.Sprintf("profile.field_%03d", i)] = compliance.Fact{Value: json.RawMessage("true"), Source: "declared", EvidenceID: "synthetic-profile", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	product, err = f.service.Save(product.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	model, err := f.service.Tests.SaveNamedPlan(product.ID, "model", TestPlanInput{ApplicationID: f.app.ID, ModelAlias: "assistant", TargetVersion: "model-1", SuiteID: "sensitive-output-controls", SuiteVersion: "1.0.0", Context: "Synthetic dual-target verification", IntervalSeconds: 300, TimeoutSeconds: 2, MaxOutputTokens: 128})
	if err != nil {
		t.Fatal(err)
	}
	setSensitiveMode(t, f, "redact")
	return f, product, model, toolCalls
}

func runNamed(t *testing.T, f fixture, product Product, plan, phase string) TestRun {
	t.Helper()
	start, err := f.service.Tests.StartPlan(product.ID, plan, phase, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if start.PlanID != plan {
		t.Fatal("incorrect summary plan identity")
	}
	return waitTestRun(t, f.service.Tests, start.ID)
}

func currentDualFacts(t *testing.T, f fixture, product Product) map[string]compliance.Fact {
	t.Helper()
	input := capture(f.gateway).input(product, time.Now())
	f.service.Tests.addOutputEvidence(product, capture(f.gateway), &input)
	if err := compliance.ValidateInput(input); err != nil {
		t.Fatal(err)
	}
	if len(input.Facts) > 160 {
		t.Fatal("combined evidence exceeded the fact limit")
	}
	return input.Facts
}

func TestDualPlansKeepIndependentEvidenceAndLegacyHistory(t *testing.T) {
	var mode atomic.Int32
	f, product, model, calls := dualPlanFixture(t, &mode, nil)
	pre := runNamed(t, f, product, "model", "pre_deployment")
	op := runNamed(t, f, product, "model", "operation")
	facts := currentDualFacts(t, f, product)
	if facts["testing.output.operation.passed"].EvidenceID != op.ID || facts["testing.tools.output.operation.passed"].EvidenceID != "" {
		t.Fatal("model result satisfied tool requirement")
	}
	toolPre := runNamed(t, f, product, "", "pre_deployment")
	toolOp := runNamed(t, f, product, "", "operation")
	if toolPre.Plan.ID != "" || pre.Plan.ID != "model" || comparableTestRuns(pre, toolPre) {
		t.Fatal("plan identity crossed run boundaries")
	}
	facts = currentDualFacts(t, f, product)
	for name, id := range map[string]string{"testing.output.pre_deployment.passed": pre.ID, "testing.output.operation.passed": op.ID, "testing.tools.output.pre_deployment.passed": toolPre.ID, "testing.tools.output.operation.passed": toolOp.ID} {
		if facts[name].EvidenceID != id || string(facts[name].Value) != "true" {
			t.Fatal("lost independent evidence", name)
		}
	}
	if len(facts) != 157 {
		t.Fatalf("unexpected complete product fact budget: %d", len(facts))
	}
	// A test-run evaluation remains about its own plan; product reports combine.
	if _, ok := toolOp.Input.Facts["testing.output.operation.passed"]; ok {
		t.Fatal("run imported another plan's evidence")
	}
	archive, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	oldHash := digestJSON(toolOp)
	f.service.Close()
	f.service, err = Open(f.dir, f.gateway, f.evaluator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.service.Close)
	if len(f.service.Tests.Plans(product.ID)) != 2 {
		t.Fatal("restart lost a plan")
	}
	retained, err := f.service.Tests.Get(toolOp.ID)
	if err != nil || digestJSON(retained) != oldHash {
		t.Fatal("legacy serialization changed", err)
	}
	model.Context = "Updated model measurement context"
	if _, err = f.service.Tests.SaveNamedPlan(product.ID, "model", model.TestPlanInput); err != nil {
		t.Fatal(err)
	}
	facts = currentDualFacts(t, f, product)
	if facts["testing.output.operation.passed"].EvidenceID != "" || facts["testing.tools.output.operation.passed"].EvidenceID != toolOp.ID {
		t.Fatal("plan edit invalidated the wrong target")
	}
	runNamed(t, f, product, "model", "pre_deployment")
	runNamed(t, f, product, "model", "operation")
	mode.Store(1)
	unknown := runNamed(t, f, product, "model", "operation")
	if unknown.Status != "inconclusive" {
		t.Fatal("missing challenge passed")
	}
	facts = currentDualFacts(t, f, product)
	if facts["testing.output.operation.passed"].EvidenceID != "" || facts["testing.tools.output.operation.passed"].EvidenceID != toolOp.ID {
		t.Fatal("unknown evidence crossed plans or reused old success")
	}
	before := calls.Load()
	replay, err := f.service.Archives.Replay(archive.Summary.ID)
	if err != nil || !replay.Matches || calls.Load() != before {
		t.Fatal("combined report replay changed or executed provider", err)
	}
}

func TestDualPlansRejectDuplicateTargetsAndWrongIdentity(t *testing.T) {
	var mode atomic.Int32
	f, product, model, calls := dualPlanFixture(t, &mode, nil)
	legacy, _ := f.service.Tests.Plan(product.ID)
	duplicate := legacy.TestPlanInput
	duplicate.Revision = 0
	if _, err := f.service.Tests.SaveNamedPlan(product.ID, "read_tool", duplicate); !errors.Is(err, ErrTestTargetConflict) {
		t.Fatal("duplicate tool target accepted", err)
	}
	if _, err := f.service.Tests.SaveNamedPlan(product.ID, "read_tool", model.TestPlanInput); err == nil {
		t.Fatal("named plan accepted wrong target")
	}
	if _, err := f.service.Tests.StartPlan(product.ID, "missing", "operation", "manual"); err == nil {
		t.Fatal("unknown plan selected a fallback")
	}
	change := model.TestPlanInput
	change.Revision = legacy.Revision
	if _, err := f.service.Tests.SavePlan(product.ID, change); !errors.Is(err, ErrTestTargetConflict) {
		t.Fatal("legacy plan became a duplicate model target", err)
	}
	if calls.Load() != 0 || len(f.service.Tests.Plans(product.ID)) != 2 {
		t.Fatal("invalid configuration mutated or executed")
	}
	// Persisted duplicate target kinds fail startup, rather than overwrite facts.
	f.service.Close()
	dup := legacy
	dup.ID = "read_tool"
	data, _ := json.Marshal(testPlanState{SchemaVersion: 1, Plans: []TestPlan{legacy, dup, model}})
	if err := os.WriteFile(filepath.Join(f.dir, "test-plans.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(f.dir, f.gateway, f.evaluator); err == nil {
		s.Close()
		t.Fatal("duplicate persisted targets accepted")
	}
}

func TestOtherPlanEditDoesNotCancelRunAndProductConcurrencyHolds(t *testing.T) {
	var mode atomic.Int32
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	f, product, _, _ := dualPlanFixture(t, &mode, func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	})
	started, err := f.service.Tests.StartPlan(product.ID, "model", "operation", "manual")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("model not reached")
	}
	if _, err = f.service.Tests.Start(product.ID, "operation", "manual"); !errors.Is(err, ErrTestBusy) {
		t.Fatal("two plans ran concurrently in one product", err)
	}
	legacy, _ := f.service.Tests.Plan(product.ID)
	legacy.Context = "Updated tool context"
	if _, err = f.service.Tests.SavePlan(product.ID, legacy.TestPlanInput); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		select {
		case release <- struct{}{}:
		case <-time.After(3 * time.Second):
			t.Fatal("model stopped after unrelated plan edit")
		}
	}
	run := waitTestRun(t, f.service.Tests, started.ID)
	if run.State != "completed" || run.Status != "passed" {
		t.Fatal("unrelated plan edit cancelled model run", run.ErrorCode)
	}
}

func TestDualPlanSchedulingDispatchesBothTargets(t *testing.T) {
	var mode atomic.Int32
	f, product, _, _ := dualPlanFixture(t, &mode, nil)
	a := f.service.Tests
	a.mu.Lock()
	for key, plan := range a.plans {
		plan.ScheduleEnabled = true
		plan.NextRunAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
		a.plans[key] = plan
	}
	if err := a.persistPlansLocked(); err != nil {
		a.mu.Unlock()
		t.Fatal(err)
	}
	a.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.dispatchDue(time.Now())
		plans := a.Plans(product.ID)
		complete := true
		for _, plan := range plans {
			if plan.LastRunID == "" {
				complete = false
				continue
			}
			run, err := a.Get(plan.LastRunID)
			if err != nil || run.State != "completed" {
				complete = false
				continue
			}
			if run.Trigger != "scheduled" || run.Plan.ID != plan.ID || run.Status != "passed" {
				t.Fatal("scheduler mixed plans")
			}
		}
		if complete {
			if len(a.List(product.ID)) != 2 {
				t.Fatal("scheduler repeated a due plan")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scheduler did not execute both due targets")
}
