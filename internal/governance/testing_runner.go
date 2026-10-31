package governance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"govweave/internal/compliance"
	"govweave/internal/leakage"
)

type boundedTestResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
	large  bool
}

func (w *boundedTestResponse) Header() http.Header { return w.header }
func (w *boundedTestResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *boundedTestResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if w.body.Len()+len(data) > 64<<10 {
		w.large = true
		return 0, io.ErrShortWrite
	}
	return w.body.Write(data)
}

func checkLiteral(item TestCase, content string) (string, string) {
	if item.Check == "manual" {
		return "unknown", "manual_review_required"
	}
	passed := false
	switch item.Check {
	case "equals":
		passed = content == item.Expected
	case "contains":
		passed = strings.Contains(content, item.Expected)
	case "not_contains":
		passed = !strings.Contains(content, item.Expected)
	case "json_valid":
		passed = json.Valid([]byte(content))
	}
	if passed {
		return "pass", "literal_check_satisfied"
	}
	return "fail", "literal_check_not_satisfied"
}

func responseDigest(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func testOutcome(cases []TestCaseResult) string {
	status := "passed"
	for _, result := range cases {
		if result.Status == "unknown" {
			status = "inconclusive"
		}
	}
	for _, result := range cases {
		if result.Status == "fail" {
			return "failed"
		}
	}
	return status
}

func (a *ActiveTests) runCase(ctx context.Context, run TestRun, item TestCase) TestCaseResult {
	start := time.Now()
	result := TestCaseResult{CaseID: item.ID, Status: "unknown", Reason: "request_failed"}
	if run.Plan.TargetKind == "read_tool" {
		ctx, cancel := context.WithTimeout(ctx, time.Duration(run.Plan.TimeoutSeconds)*time.Second)
		defer cancel()
		payload, _ := json.Marshal(map[string]string{"resource_id": item.ResourceID})
		request, _ := http.NewRequestWithContext(ctx, "POST", "http://govweave.internal/v1/tools/"+run.Plan.ToolAlias+"/invoke", bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.SetPathValue("alias", run.Plan.ToolAlias)
		w := &boundedTestResponse{header: make(http.Header)}
		receipt := a.service.gateway.ToolAssessmentEvidence(w, request, run.Plan.ApplicationID)
		result.DurationMS, result.HTTPStatus, result.RequestID = time.Since(start).Milliseconds(), w.status, w.header.Get("X-Request-ID")
		return outputCaseResult(item, result, receipt, w)
	}
	messages := slices.Clone(item.Messages)
	if item.Check == "canary_absent" {
		marker, err := leakage.NewMarker()
		if err != nil {
			result.Reason = "canary_generation_failed"
			return result
		}
		result.SyntheticMarker = marker
		for i := range messages {
			messages[i].Content = strings.ReplaceAll(messages[i].Content, leakage.Placeholder, marker)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(run.Plan.TimeoutSeconds)*time.Second)
	defer cancel()
	payload, _ := json.Marshal(map[string]any{"model": run.Plan.ModelAlias, "messages": messages, "stream": false, "max_tokens": run.Plan.MaxOutputTokens, "temperature": 0})
	request, _ := http.NewRequestWithContext(ctx, "POST", "http://govweave.internal/v1/chat/completions", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	w := &boundedTestResponse{header: make(http.Header)}
	receipt := a.service.gateway.ChatAssessmentEvidence(w, request, run.Plan.ApplicationID)
	result.DurationMS, result.HTTPStatus, result.RequestID = time.Since(start).Milliseconds(), w.status, w.header.Get("X-Request-ID")
	if isOutputCheck(item) {
		return outputCaseResult(item, result, receipt, w)
	}
	if w.large {
		result.Reason = "response_limit"
		return result
	}
	if item.Check == "credential_block" {
		var response struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(w.body.Bytes(), &response)
		if w.status == 403 && response.Error.Code == "policy_blocked" {
			result.Status, result.Reason = "pass", "gateway_credential_blocked"
		} else if w.status == 200 {
			result.Status, result.Reason = "fail", "gateway_did_not_block"
		}
		return result
	}
	if w.status != 200 {
		return result
	}
	if !utf8.Valid(w.body.Bytes()) {
		result.Reason = "unsupported_or_incomplete_response"
		return result
	}
	var response struct {
		Choices []struct {
			Message struct {
				Role    string  `json:"role"`
				Content *string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(w.body.Bytes(), &response) != nil || len(response.Choices) != 1 || response.Choices[0].Message.Role != "assistant" || response.Choices[0].Message.Content == nil || *response.Choices[0].Message.Content == "" || response.Choices[0].FinishReason != "stop" {
		result.Reason = "unsupported_or_incomplete_response"
		return result
	}
	content := *response.Choices[0].Message.Content
	if strings.ContainsRune(content, utf8.RuneError) {
		result.Reason = "unsupported_or_incomplete_response"
		return result
	}
	if !utf8.ValidString(content) || len(content) > 8192 {
		result.Reason = "response_limit"
		return result
	}
	result.ResponseSHA256, result.ResponseBytes = responseDigest(content), len(content)
	if run.Plan.RetainResponses {
		result.Response = &content
	}
	if item.Check == "canary_absent" {
		detection := leakage.Detect(result.SyntheticMarker, []byte(content))
		result.Detection = &detection
		result.Status, result.Reason = canaryStatus(detection.State)
	} else {
		result.Status, result.Reason = checkLiteral(item, content)
	}
	return result
}

func canaryStatus(state string) (string, string) {
	switch state {
	case "observed":
		return "fail", "synthetic_canary_exposed"
	case "not_observed":
		return "pass", "synthetic_canary_not_observed"
	default:
		return "unknown", "canary_detection_unavailable"
	}
}

func (a *ActiveTests) sourceMatches(run TestRun) bool {
	product, err := a.service.Products.Get(run.Product.ID)
	if err != nil || product.Revision != run.Product.Revision || a.service.gateway.Store.Snapshot().Revision != run.GatewayRevision || a.service.gateway.Policies.Snapshot().Revision != run.PolicyRevision {
		return false
	}
	// Legacy runs lack tool evidence and resolve to revision zero. Replay is
	// independent of this live-admission check.
	toolRevision, _, valid := retainedToolRevision(run)
	if !valid || toolRevision != a.service.gateway.Tools.Snapshot().Revision {
		return false
	}
	outputRevision, _, valid := retainedRevision(run, "runtime.output_policy_revision")
	if !valid || outputRevision != a.service.gateway.OutputPolicies.Snapshot().Revision {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.plans[testPlanKey(product.ID, run.Plan.ID)].Revision == run.Plan.Revision
}

// Tool revision is already retained as server-derived evidence. Using that
// fact avoids changing the historical test-run file format.
func retainedToolRevision(run TestRun) (revision uint64, present, valid bool) {
	return retainedRevision(run, "runtime.tools.revision")
}

func retainedRevision(run TestRun, name string) (revision uint64, present, valid bool) {
	fact, present := run.Input.Facts[name]
	if !present {
		return 0, false, true
	}
	if fact.Source != "runtime" || bytes.Equal(bytes.TrimSpace(fact.Value), []byte("null")) || json.Unmarshal(fact.Value, &revision) != nil {
		return 0, true, false
	}
	return revision, true, true
}

func comparableTestRuns(a, b TestRun) bool {
	if a.RunnerVersion != b.RunnerVersion {
		return false
	}
	aTool, aPresent, aValid := retainedToolRevision(a)
	bTool, bPresent, bValid := retainedToolRevision(b)
	if !aValid || !bValid || aPresent != bPresent || aTool != bTool {
		return false
	}
	aOutput, aPresent, aValid := retainedRevision(a, "runtime.output_policy_revision")
	bOutput, bPresent, bValid := retainedRevision(b, "runtime.output_policy_revision")
	if !aValid || !bValid || aPresent != bPresent || aOutput != bOutput {
		return false
	}
	return a.Product.ID == b.Product.ID && a.Product.Revision == b.Product.Revision && a.Plan.ID == b.Plan.ID && a.Plan.Revision == b.Plan.Revision && a.Plan.TargetKind == b.Plan.TargetKind && a.ToolID == b.ToolID && a.ToolRevision == b.ToolRevision && a.SuiteSHA256 == b.SuiteSHA256 && a.GatewayRevision == b.GatewayRevision && a.PolicyRevision == b.PolicyRevision && a.ConnectionID == b.ConnectionID && a.ConnectionRevision == b.ConnectionRevision && digestJSON(a.RulePack) == digestJSON(b.RulePack)
}

func (a *ActiveTests) previousLocked(run TestRun, phase string) *TestRun {
	var latest *TestRun
	for _, summary := range a.runs {
		if summary.ID == run.ID || summary.ProductID != run.Product.ID || summary.PlanID != run.Plan.ID || summary.Phase != phase || summary.State == "running" || !testStartedBefore(summary.StartedAt, run.StartedAt) {
			continue
		}
		candidate, err := a.getLocked(summary.ID)
		if err != nil {
			return nil
		}
		if !comparableTestRuns(run, candidate) {
			continue
		}
		if latest == nil || testStartedBefore(latest.StartedAt, candidate.StartedAt) {
			copy := candidate
			latest = &copy
		}
	}
	return latest
}

func (a *ActiveTests) addTestEvidenceLocked(run *TestRun) {
	add := func(name string, value any, evidenceID, observed, expires string) {
		data, _ := json.Marshal(value)
		run.Input.Facts["testing."+name] = compliance.Fact{Value: data, EvidenceID: evidenceID, Source: "assessment", ObservedAt: observed, ExpiresAt: expires}
	}
	add("test_set_documented", true, run.ID, run.FinishedAt, "")
	canaries, observed, complete := 0, false, true
	for i, result := range run.Cases {
		if run.Suite.Cases[i].Check != "canary_absent" {
			continue
		}
		canaries++
		if result.Detection == nil || result.Detection.State == "unknown" {
			complete = false
			continue
		}
		observed = observed || result.Detection.State == "observed"
	}
	if canaries > 0 && (observed || complete) {
		add("canary.exposure_observed", observed, run.ID, run.FinishedAt, "")
	}
	for _, phase := range []string{"pre_deployment", "operation"} {
		retained := run
		if phase != run.Phase {
			retained = a.previousLocked(*run, phase)
		}
		if retained == nil || retained.State != "completed" || retained.Status == "inconclusive" {
			continue
		}
		finished, _ := time.Parse(time.RFC3339Nano, retained.FinishedAt)
		lifetime := 30 * 24 * time.Hour
		if phase == "operation" {
			lifetime = 2 * time.Duration(run.Plan.IntervalSeconds) * time.Second
		}
		add(phase+".passed", retained.Status == "passed", retained.ID, retained.FinishedAt, finished.Add(lifetime).Format(time.RFC3339Nano))
		if passed, valid := outputSuiteVerdict(*retained); valid {
			add(outputFactPrefix(run.Plan)+phase+".passed", passed, retained.ID, retained.FinishedAt, finished.Add(lifetime).Format(time.RFC3339Nano))
		}
	}
}

func (a *ActiveTests) execute(run TestRun) {
	defer a.wg.Done()
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Minute)
	defer cancel()
	for _, item := range run.Suite.Cases {
		if ctx.Err() != nil {
			run.ErrorCode = "test_cancelled"
			break
		}
		if !a.sourceMatches(run) {
			run.ErrorCode = "test_source_changed"
			break
		}
		run.Cases = append(run.Cases, a.runCase(ctx, run, item))
	}
	if ctx.Err() != nil {
		run.ErrorCode = "test_cancelled"
	}
	if !a.sourceMatches(run) {
		run.ErrorCode = "test_source_changed"
	}
	run.State, run.Status = "completed", "passed"
	if run.ErrorCode != "" {
		run.State, run.Status = "error", "inconclusive"
	} else {
		run.Status = testOutcome(run.Cases)
	}
	run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	a.mu.Lock()
	defer a.mu.Unlock()
	defer delete(a.active, run.Product.ID)
	if run.State == "completed" {
		if previous := a.previousLocked(run, run.Phase); previous != nil && previous.State == "completed" {
			comparison := &TestComparison{PreviousRunID: previous.ID}
			for i, current := range run.Cases {
				old := previous.Cases[i]
				if old.Status == "pass" && current.Status == "fail" {
					comparison.Regressions++
				}
				if old.Status == "fail" && current.Status == "pass" {
					comparison.Recoveries++
				}
			}
			run.Comparison = comparison
		}
		a.addTestEvidenceLocked(&run)
		evaluation, err := compliance.EvaluateSnapshot(run.RulePack, run.Input, time.Now())
		if err != nil {
			run.State, run.Status, run.ErrorCode = "error", "inconclusive", "test_evaluation_failed"
		} else {
			run.Evaluation = &evaluation
		}
	}
	key := testPlanKey(run.Product.ID, run.Plan.ID)
	plan := a.plans[key]
	if err := a.writeRunLocked(run); err != nil {
		plan.LastError = "test_persistence_failed"
	} else if plan.LastRunID == run.ID {
		plan.LastError = run.ErrorCode
	}
	a.plans[key] = plan
	if a.persistPlansLocked() != nil {
		plan.LastError = "test_persistence_failed"
		a.plans[key] = plan
	}
}

type TestReplay struct {
	RunID      string                `json:"run_id"`
	Matches    bool                  `json:"matches"`
	Evaluation compliance.Evaluation `json:"evaluation"`
}

// Replay never makes a model request. It checks only the retained rule decision.
func (a *ActiveTests) Replay(id string) (TestReplay, error) {
	run, err := a.Get(id)
	if err != nil {
		return TestReplay{}, err
	}
	if run.Evaluation == nil {
		return TestReplay{}, errors.New("this run has no completed rule evaluation")
	}
	at, _ := time.Parse(time.RFC3339Nano, run.Evaluation.EvaluatedAt)
	evaluation, err := compliance.EvaluateSnapshot(run.RulePack, run.Input, at)
	return TestReplay{run.ID, err == nil && reflect.DeepEqual(evaluation, *run.Evaluation), evaluation}, err
}
