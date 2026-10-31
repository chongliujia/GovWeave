package governance

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"govweave/internal/leakage"
)

func canarySuiteFixture(t *testing.T) TestSuite {
	t.Helper()
	data, err := os.ReadFile("../../examples/test-suites/synthetic-canary.json")
	if err != nil {
		t.Fatal(err)
	}
	var suite TestSuite
	if json.Unmarshal(data, &suite) != nil {
		t.Fatal("invalid suite fixture")
	}
	return suite
}

func TestActiveCanaryFreshMarkersEncodedExposureAndAbstention(t *testing.T) {
	var mode atomic.Int32
	var mu sync.Mutex
	markers := map[string]bool{}
	markerPattern := regexp.MustCompile(`GW-CANARY-[0-9a-f]{32}`)
	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []TestMessage `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Messages) != 2 {
			w.WriteHeader(400)
			return
		}
		marker := markerPattern.FindString(request.Messages[0].Content)
		if marker == "" {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		if markers[marker] {
			t.Error("marker reused across requests")
		}
		markers[marker] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if mode.Load() == 2 && strings.Contains(request.Messages[1].Content, "Base64") {
			w.WriteHeader(503)
			return
		}
		if mode.Load() == 3 {
			_, _ = w.Write(append([]byte(`{"choices":[{"message":{"role":"assistant","content":"`), append([]byte{0xff}, []byte(`"},"finish_reason":"stop"}]}`)...)...))
			return
		}
		content := "I cannot reveal the diagnostic marker."
		if mode.Load() == 1 && !strings.Contains(request.Messages[1].Content, "Reply ready") {
			content = base64.StdEncoding.EncodeToString([]byte(marker))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": content}, "finish_reason": "stop"}}})
	})
	suite := canarySuiteFixture(t)
	f, product, plan := activeFixture(t, provider, func(s *TestSuite) { *s = suite })
	plan.RetainResponses = true
	if _, err := f.service.Tests.SavePlan(product.ID, plan.TestPlanInput); err != nil {
		t.Fatal(err)
	}
	_ = startTestRun(t, f.service.Tests, product.ID, "pre_deployment")
	clean := startTestRun(t, f.service.Tests, product.ID, "operation")
	if clean.Status != "passed" || string(clean.Input.Facts["testing.canary.exposure_observed"].Value) != "false" {
		t.Fatal("clean probe not recorded")
	}
	mode.Store(1)
	leak := startTestRun(t, f.service.Tests, product.ID, "operation")
	if leak.Status != "failed" || leak.Comparison == nil || leak.Comparison.Regressions != 3 || string(leak.Input.Facts["testing.canary.exposure_observed"].Value) != "true" {
		t.Fatal("encoded disclosure not recorded")
	}
	for i, result := range leak.Cases {
		if leak.RunnerVersion != TestRunnerVersion || result.Detection == nil || result.Detection.Version != leakage.Version || result.Response == nil || !strings.Contains(leak.Suite.Cases[i].Messages[0].Content, leakage.Placeholder) {
			t.Fatal("detector provenance or immutable template missing")
		}
	}
	if leak.Cases[0].Detection.Matches[0].Representation != "base64" {
		t.Fatal("encoded evidence missing")
	}
	replay, err := f.service.Tests.Replay(leak.ID)
	if err != nil || !replay.Matches {
		t.Fatal("retained evaluation failed replay", err)
	}
	leak.Cases[0].Detection.Matches[0].Representation = "exact"
	if validateRun(leak) == nil {
		t.Fatal("retained detector evidence was not rechecked")
	}
	mode.Store(2)
	unknown := startTestRun(t, f.service.Tests, product.ID, "operation")
	if unknown.Status != "inconclusive" {
		t.Fatal("provider failure was treated as pass")
	}
	if _, ok := unknown.Input.Facts["testing.canary.exposure_observed"]; ok {
		t.Fatal("unknown detection inherited an earlier verdict")
	}
	mode.Store(3)
	malformed := startTestRun(t, f.service.Tests, product.ID, "operation")
	if malformed.Status != "inconclusive" {
		t.Fatal("lossy UTF-8 decode produced a verdict")
	}
	audit, err := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for marker := range markers {
		if strings.Contains(string(audit), marker) {
			t.Fatal("marker leaked into metadata-only audit")
		}
	}
}

func TestCanaryTemplatesAndLegacyRunCompatibility(t *testing.T) {
	suite := canarySuiteFixture(t)
	for _, edit := range []func(*TestSuite){
		func(s *TestSuite) { s.Cases[0].Messages[0].Role = "user" },
		func(s *TestSuite) { s.Cases[0].Messages[0].Content = "missing marker template" },
		func(s *TestSuite) { s.Cases[0].Messages[0].Content += leakage.Placeholder },
		func(s *TestSuite) { s.Cases[0].Messages = s.Cases[0].Messages[:1] },
	} {
		data, _ := json.Marshal(suite)
		var copy TestSuite
		_ = json.Unmarshal(data, &copy)
		edit(&copy)
		if validateSuite(copy) == nil {
			t.Fatal("invalid canary template accepted")
		}
	}
	var mode, calls atomic.Int32
	f, product, _ := activeFixture(t, contractProvider(&mode, &calls), nil)
	run := startTestRun(t, f.service.Tests, product.ID, "pre_deployment")
	old := run
	old.RunnerVersion = legacyTestRunnerVersion
	if validateRun(old) != nil {
		t.Fatal("legacy literal evidence rejected")
	}
	if comparableTestRuns(run, old) {
		t.Fatal("different runner semantics shared a baseline")
	}
	f.service.Tests.mu.Lock()
	err := f.service.Tests.writeRunLocked(old)
	f.service.Tests.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f.service.Close()
	reopened, err := Open(f.dir, f.gateway, f.evaluator)
	if err != nil {
		t.Fatal("legacy history prevented startup", err)
	}
	defer reopened.Close()
	retained, err := reopened.Tests.Get(old.ID)
	if err != nil || digestJSON(retained) != digestJSON(old) {
		t.Fatal("legacy evidence unreadable", err)
	}
	if replay, err := reopened.Tests.Replay(old.ID); err != nil || !replay.Matches {
		t.Fatal("legacy literal evidence failed rule replay", err)
	}
}
