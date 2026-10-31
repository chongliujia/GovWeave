package governance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/gateway"
	"govweave/internal/storage"
)

var testRunID = regexp.MustCompile(`^test_[A-Za-z0-9_-]{22}$`)

type testPlanState struct {
	SchemaVersion int        `json:"schema_version"`
	Plans         []TestPlan `json:"plans"`
}

type ActiveTests struct {
	mu               sync.Mutex
	dir              string
	service          *Service
	suites           map[string]TestSuite
	plans            map[string]TestPlan
	runs             map[string]TestRunSummary
	active           map[string]bool
	evidenceRevision uint64
	ctx              context.Context
	cancel           context.CancelFunc
	done             chan struct{}
	wg               sync.WaitGroup
}

func openActiveTests(dir string, service *Service) (*ActiveTests, error) {
	suites, err := loadSuites(filepath.Join(dir, "test-suites"))
	if err != nil {
		return nil, err
	}
	a := &ActiveTests{dir: dir, service: service, suites: suites, plans: map[string]TestPlan{}, runs: map[string]TestRunSummary{}, active: map[string]bool{}, done: make(chan struct{})}
	var state testPlanState
	err = readPrivateJSON(filepath.Join(dir, "test-plans.json"), 256<<10, true, &state)
	if err == nil {
		if state.SchemaVersion != 1 || state.Plans == nil || len(state.Plans) > 2*MaxProducts {
			return nil, ErrTestUnavailable
		}
		for _, plan := range state.Plans {
			if validatePlanIdentity(plan.ID, plan.TestPlanInput) != nil || validateTestPlan(plan.TestPlanInput) != nil || !identifier.MatchString(plan.ProductID) || plan.Revision == 0 {
				return nil, ErrTestUnavailable
			}
			if _, exists := a.plans[testPlanKey(plan.ProductID, plan.ID)]; exists || a.targetConflictLocked(plan.ProductID, plan.ID, plan.TargetKind) {
				return nil, ErrTestUnavailable
			}
			if plan.NextRunAt != "" {
				if _, err := time.Parse(time.RFC3339Nano, plan.NextRunAt); err != nil {
					return nil, ErrTestUnavailable
				}
			}
			if plan.ScheduleEnabled && plan.NextRunAt == "" {
				return nil, ErrTestUnavailable
			}
			a.plans[testPlanKey(plan.ProductID, plan.ID)] = plan
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	runDir := filepath.Join(dir, "test-runs")
	if info, err := os.Lstat(runDir); err == nil {
		if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return nil, ErrTestUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	entries, err := os.ReadDir(runDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(entries) > MaxTestRuns {
		return nil, ErrTestCapacity
	}
	for _, entry := range entries {
		var run TestRun
		if readPrivateJSON(filepath.Join(runDir, entry.Name()), maxTestRunBytes, true, &run) != nil || entry.Name() != run.ID+".json" || validateRun(run) != nil {
			return nil, ErrTestUnavailable
		}
		if run.State == "running" {
			run.State, run.Status, run.ErrorCode = "interrupted", "inconclusive", "process_interrupted"
			run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			if a.writeRunLocked(run) != nil {
				return nil, ErrTestUnavailable
			}
		} else {
			a.runs[run.ID] = summarizeTestRun(run)
		}
	}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	go a.loop()
	return a, nil
}

func validateTestPlan(in TestPlanInput) error {
	if in.TargetKind == "read_tool" {
		if !identifier.MatchString(in.ToolAlias) || in.ModelAlias != "" || in.MaxOutputTokens != 0 {
			return errors.New("read-tool plans require tool_alias, without model_alias or output tokens")
		}
	} else if in.TargetKind != "" || in.ToolAlias != "" || len(in.ModelAlias) < 1 || len(in.ModelAlias) > 100 || in.MaxOutputTokens < 1 || in.MaxOutputTokens > 1024 {
		return errors.New("model plans require a model alias and 1–1024 output tokens")
	}
	if !identifier.MatchString(in.ApplicationID) || !identifier.MatchString(in.TargetVersion) || !identifier.MatchString(in.SuiteID) || !identifier.MatchString(in.SuiteVersion) || len(in.Context) < 1 || len(in.Context) > 1000 || in.IntervalSeconds < 300 || in.IntervalSeconds > 2592000 || in.TimeoutSeconds < 1 || in.TimeoutSeconds > 30 {
		return errors.New("test plans require an explicit target/version, context, interval 300–2592000 seconds, timeout 1–30 seconds and output budget 1–1024 tokens")
	}
	return nil
}

func (a *ActiveTests) Catalog() []TestSuiteDescriptor {
	result := []TestSuiteDescriptor{}
	for _, suite := range a.suites {
		result = append(result, TestSuiteDescriptor{suite.ID, suite.Version, suite.Name, digestJSON(suite), len(suite.Cases)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID+"/"+result[i].Version < result[j].ID+"/"+result[j].Version })
	return result
}

func (a *ActiveTests) Suite(id, version string) (TestSuite, error) {
	suite, ok := a.suites[id+"/"+version]
	if !ok {
		return TestSuite{}, gateway.ErrNotFound
	}
	data, _ := json.Marshal(suite)
	var out TestSuite
	_ = json.Unmarshal(data, &out)
	return out, nil
}

func (a *ActiveTests) Plan(productID string) (TestPlan, error) {
	return a.NamedPlan(productID, "")
}

func (a *ActiveTests) NamedPlan(productID, planID string) (TestPlan, error) {
	if !validPlanID(planID) {
		return TestPlan{}, errors.New("invalid plan ID")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	plan, exists := a.plans[testPlanKey(productID, planID)]
	if !exists {
		return TestPlan{}, gateway.ErrNotFound
	}
	return plan, nil
}

func (a *ActiveTests) persistPlansLocked() error {
	state := testPlanState{SchemaVersion: 1, Plans: []TestPlan{}}
	for _, plan := range a.plans {
		state.Plans = append(state.Plans, plan)
	}
	sort.Slice(state.Plans, func(i, j int) bool {
		return testPlanKey(state.Plans[i].ProductID, state.Plans[i].ID) < testPlanKey(state.Plans[j].ProductID, state.Plans[j].ID)
	})
	data, err := json.Marshal(state)
	if err != nil || len(data) > 256<<10 {
		return gateway.ErrPersistence
	}
	if storage.AtomicWrite(filepath.Join(a.dir, "test-plans.json"), data) != nil {
		return gateway.ErrPersistence
	}
	return nil
}

func (a *ActiveTests) SavePlan(productID string, in TestPlanInput) (TestPlan, error) {
	return a.SaveNamedPlan(productID, "", in)
}

func (a *ActiveTests) SaveNamedPlan(productID, planID string, in TestPlanInput) (TestPlan, error) {
	if err := validatePlanIdentity(planID, in); err != nil {
		return TestPlan{}, err
	}
	if err := validateTestPlan(in); err != nil {
		return TestPlan{}, err
	}
	product, err := a.service.Products.Get(productID)
	if err != nil {
		return TestPlan{}, err
	}
	if !slices.Contains(product.ApplicationIDs, in.ApplicationID) {
		return TestPlan{}, errors.New("the test application must be bound to this product")
	}
	suite, err := a.Suite(in.SuiteID, in.SuiteVersion)
	if err != nil {
		return TestPlan{}, err
	}
	if _, err := a.resolveTestTarget(in, suite, capture(a.service.gateway)); err != nil {
		return TestPlan{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := testPlanKey(productID, planID)
	old := a.plans[key]
	if a.targetConflictLocked(productID, planID, in.TargetKind) {
		return TestPlan{}, ErrTestTargetConflict
	}
	if old.Revision != in.Revision || in.Revision == ^uint64(0) {
		return TestPlan{}, gateway.ErrConflict
	}
	in.Revision++
	plan := TestPlan{ProductID: productID, TestPlanInput: in, ID: planID}
	if in.ScheduleEnabled {
		plan.NextRunAt = time.Now().UTC().Add(time.Duration(in.IntervalSeconds) * time.Second).Format(time.RFC3339Nano)
	}
	a.plans[testPlanKey(productID, planID)] = plan
	if err := a.persistPlansLocked(); err != nil {
		if old.Revision == 0 {
			delete(a.plans, key)
		} else {
			a.plans[testPlanKey(productID, planID)] = old
		}
		return TestPlan{}, err
	}
	a.evidenceRevision++
	a.service.Notify()
	return plan, nil
}

func summarizeTestRun(run TestRun) TestRunSummary {
	return TestRunSummary{ID: run.ID, ProductID: run.Product.ID, Phase: run.Phase, State: run.State, Status: run.Status, StartedAt: run.StartedAt, SHA256: digestJSON(run), PlanID: run.Plan.ID}
}

func testStartedBefore(left, right string) bool {
	a, _ := time.Parse(time.RFC3339Nano, left)
	b, _ := time.Parse(time.RFC3339Nano, right)
	return a.Before(b)
}

func validateRun(run TestRun) error {
	if run.SchemaVersion != 1 || !slices.Contains([]string{TestRunnerVersion, toolTestRunnerVersion, canaryV2TestRunnerVersion, canaryV1TestRunnerVersion, legacyTestRunnerVersion}, run.RunnerVersion) || !testRunID.MatchString(run.ID) || !slices.Contains([]string{"pre_deployment", "operation"}, run.Phase) || !slices.Contains([]string{"manual", "scheduled"}, run.Trigger) || !slices.Contains([]string{"running", "completed", "error", "interrupted"}, run.State) || !slices.Contains([]string{"pending", "passed", "failed", "inconclusive"}, run.Status) || run.Plan.ProductID != run.Product.ID || validateProduct(run.Product.ProductInput) != nil || validateTestPlan(run.Plan.TestPlanInput) != nil || validateSuite(run.Suite) != nil || digestJSON(run.Suite) != run.SuiteSHA256 || compliance.ValidateInput(run.Input) != nil || compliance.ValidatePack(run.RulePack) != nil || len(run.Cases) > len(run.Suite.Cases) {
		return ErrTestUnavailable
	}
	if validatePlanIdentity(run.Plan.ID, run.Plan.TestPlanInput) != nil || run.Plan.TargetKind != run.Suite.TargetKind || (run.Plan.TargetKind == "read_tool") != (run.RunnerVersion == toolTestRunnerVersion) {
		return ErrTestUnavailable
	}
	if run.Plan.TargetKind == "read_tool" {
		if !identifier.MatchString(run.ToolID) || run.ToolRevision == 0 || run.ConnectionID != "" || run.ConnectionRevision != 0 {
			return ErrTestUnavailable
		}
	} else if run.ToolID != "" || run.ToolRevision != 0 {
		return ErrTestUnavailable
	}
	if _, err := time.Parse(time.RFC3339Nano, run.StartedAt); err != nil {
		return ErrTestUnavailable
	}
	if run.RunnerVersion == legacyTestRunnerVersion {
		for _, item := range run.Suite.Cases {
			if item.Check == "canary_absent" {
				return ErrTestUnavailable
			}
		}
	}
	if run.Plan.Revision == 0 || run.Product.Revision == 0 || run.Product.ID != run.Input.ProductID || run.Product.Version != run.Input.ProductVersion || run.RulePack.ID != run.Input.PackID || run.RulePack.Version != run.Input.PackVersion || run.Suite.ID != run.Plan.SuiteID || run.Suite.Version != run.Plan.SuiteVersion || !slices.Contains(run.Product.ApplicationIDs, run.Plan.ApplicationID) {
		return ErrTestUnavailable
	}
	if run.State == "running" {
		if run.Status != "pending" || run.Evaluation != nil || run.FinishedAt != "" {
			return ErrTestUnavailable
		}
	} else {
		start, _ := time.Parse(time.RFC3339Nano, run.StartedAt)
		finish, err := time.Parse(time.RFC3339Nano, run.FinishedAt)
		if err != nil || finish.Before(start) {
			return ErrTestUnavailable
		}
		if run.State != "completed" && (run.Evaluation != nil || run.Status != "inconclusive") {
			return ErrTestUnavailable
		}
	}
	for _, item := range run.Suite.Cases {
		if isReceiptCheck(item) && run.RunnerVersion != TestRunnerVersion && run.RunnerVersion != toolTestRunnerVersion {
			return ErrTestUnavailable
		}
	}
	for i, result := range run.Cases {
		if err := validateOutputCase(run.Suite.Cases[i], result, run); err != nil {
			return err
		}
		if err := validateCanaryCase(run.Suite.Cases[i], result, run.RunnerVersion); err != nil {
			return err
		}
		if result.CaseID != run.Suite.Cases[i].ID || !slices.Contains([]string{"pass", "fail", "unknown"}, result.Status) || result.HTTPStatus < 0 || result.HTTPStatus > 599 || result.DurationMS < 0 || result.ResponseBytes < 0 || result.ResponseBytes > 8192 {
			return ErrTestUnavailable
		}
		if result.Response != nil {
			if !run.Plan.RetainResponses || len(*result.Response) != result.ResponseBytes {
				return ErrTestUnavailable
			}
			if responseDigest(*result.Response) != result.ResponseSHA256 {
				return ErrTestUnavailable
			}
		}
	}
	if run.State == "completed" {
		if run.Evaluation == nil || len(run.Cases) != len(run.Suite.Cases) || testOutcome(run.Cases) != run.Status {
			return ErrTestUnavailable
		}
		at, err := time.Parse(time.RFC3339Nano, run.Evaluation.EvaluatedAt)
		if err != nil {
			return ErrTestUnavailable
		}
		replayed, err := compliance.EvaluateSnapshot(run.RulePack, run.Input, at)
		if err != nil || !reflect.DeepEqual(replayed, *run.Evaluation) {
			return ErrTestUnavailable
		}
	}
	return nil
}

func (a *ActiveTests) writeRunLocked(run TestRun) error {
	data, err := json.Marshal(run)
	if err != nil || len(data) > maxTestRunBytes {
		return ErrTestCapacity
	}
	path := filepath.Join(a.dir, "test-runs")
	if err := os.MkdirAll(path, 0700); err != nil {
		return gateway.ErrPersistence
	}
	if storage.AtomicWrite(filepath.Join(path, run.ID+".json"), data) != nil {
		return gateway.ErrPersistence
	}
	a.runs[run.ID] = summarizeTestRun(run)
	a.evidenceRevision++
	a.service.Notify()
	return nil
}

func (a *ActiveTests) getLocked(id string) (TestRun, error) {
	summary, ok := a.runs[id]
	if !ok || !testRunID.MatchString(id) {
		return TestRun{}, gateway.ErrNotFound
	}
	var run TestRun
	if readPrivateJSON(filepath.Join(a.dir, "test-runs", id+".json"), maxTestRunBytes, true, &run) != nil || digestJSON(run) != summary.SHA256 || validateRun(run) != nil {
		return TestRun{}, ErrTestUnavailable
	}
	return run, nil
}

func (a *ActiveTests) Get(id string) (TestRun, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.getLocked(id)
}

func (a *ActiveTests) List(productID string) []TestRunSummary {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := []TestRunSummary{}
	for _, summary := range a.runs {
		if summary.ProductID == productID {
			result = append(result, summary)
		}
	}
	sort.Slice(result, func(i, j int) bool { return testStartedBefore(result[j].StartedAt, result[i].StartedAt) })
	return result
}

// Start first reserves durable evidence space. It never holds an HTTP request
// open for model execution and never retries a billable inference automatically.
func (a *ActiveTests) Start(productID, phase, trigger string) (TestRunSummary, error) {
	return a.StartPlan(productID, "", phase, trigger)
}

func (a *ActiveTests) StartPlan(productID, planID, phase, trigger string) (TestRunSummary, error) {
	if !validPlanID(planID) {
		return TestRunSummary{}, errors.New("invalid plan ID")
	}
	if !slices.Contains([]string{"pre_deployment", "operation"}, phase) || !slices.Contains([]string{"manual", "scheduled"}, trigger) {
		return TestRunSummary{}, errors.New("invalid test phase or trigger")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx.Err() != nil || len(a.active) >= 2 || a.active[productID] {
		return TestRunSummary{}, ErrTestBusy
	}
	if len(a.runs) >= MaxTestRuns {
		return TestRunSummary{}, ErrTestCapacity
	}
	plan, exists := a.plans[testPlanKey(productID, planID)]
	if !exists {
		return TestRunSummary{}, gateway.ErrNotFound
	}
	if trigger == "scheduled" && (!plan.ScheduleEnabled || phase != "operation") {
		return TestRunSummary{}, errors.New("scheduled operation testing is disabled")
	}
	if trigger == "scheduled" {
		due, err := time.Parse(time.RFC3339Nano, plan.NextRunAt)
		if err != nil || time.Now().Before(due) {
			return TestRunSummary{}, ErrTestBusy
		}
	}
	product, err := a.service.Products.Get(productID)
	if err != nil {
		return TestRunSummary{}, err
	}
	if !slices.Contains(product.ApplicationIDs, plan.ApplicationID) {
		return TestRunSummary{}, gateway.ErrDenied
	}
	suite, err := a.Suite(plan.SuiteID, plan.SuiteVersion)
	if err != nil {
		return TestRunSummary{}, err
	}
	source := capture(a.service.gateway)
	target, err := a.resolveTestTarget(plan.TestPlanInput, suite, source)
	if err != nil {
		return TestRunSummary{}, err
	}
	pack, err := a.service.evaluator.PackSnapshot(product.PackID, product.PackVersion)
	if err != nil {
		return TestRunSummary{}, err
	}
	id, err := storage.ID("test_", 16)
	if err != nil {
		return TestRunSummary{}, gateway.ErrPersistence
	}
	now := time.Now().UTC()
	run := TestRun{SchemaVersion: 1, RunnerVersion: runnerFor(plan), ID: id, Phase: phase, Trigger: trigger, State: "running", Status: "pending", StartedAt: now.Format(time.RFC3339Nano), Product: product, Plan: plan, Suite: suite, SuiteSHA256: digestJSON(suite), GatewayRevision: source.resources.Revision, PolicyRevision: source.policy.Revision, ConnectionID: target.connection.ID, ConnectionRevision: target.connection.Revision, ToolID: target.tool.ID, ToolRevision: target.tool.Revision, Cases: []TestCaseResult{}, Input: source.input(product, now), RulePack: pack}
	// Reserve room for worst-case escaped assistant text and a rule evaluation
	// before making any billable request. Large snapshots fail without inference.
	probe, err := compliance.EvaluateSnapshot(pack, run.Input, now)
	if err != nil {
		return TestRunSummary{}, err
	}
	base, _ := json.Marshal(run)
	evaluationBytes, _ := json.Marshal(probe)
	caseBudget := 2048
	if plan.TargetKind == "read_tool" {
		caseBudget = 4096
	}
	if plan.RetainResponses {
		caseBudget += 6 * 8192
	}
	if len(base)+len(evaluationBytes)+len(suite.Cases)*caseBudget+16384 > maxTestRunBytes {
		return TestRunSummary{}, ErrTestCapacity
	}
	if err := a.writeRunLocked(run); err != nil {
		return TestRunSummary{}, err
	}
	oldPlan := plan
	plan.LastRunID, plan.LastError = id, ""
	if plan.ScheduleEnabled {
		plan.NextRunAt = now.Add(time.Duration(plan.IntervalSeconds) * time.Second).Format(time.RFC3339Nano)
	}
	a.plans[testPlanKey(productID, planID)] = plan
	if err := a.persistPlansLocked(); err != nil {
		a.plans[testPlanKey(productID, planID)] = oldPlan
		run.State, run.Status, run.ErrorCode, run.FinishedAt = "error", "inconclusive", "persistence_failed", now.Format(time.RFC3339Nano)
		_ = a.writeRunLocked(run)
		return TestRunSummary{}, err
	}
	a.active[productID] = true
	a.wg.Add(1)
	go a.execute(run)
	return a.runs[id], nil
}

func (a *ActiveTests) dispatchDue(now time.Time) {
	a.mu.Lock()
	due := []TestPlan{}
	for _, plan := range a.plans {
		at, _ := time.Parse(time.RFC3339Nano, plan.NextRunAt)
		if plan.ScheduleEnabled && !at.IsZero() && !now.Before(at) {
			due = append(due, plan)
		}
	}
	a.mu.Unlock()
	// Oldest due first, so a busy product's second plan is not starved.
	sort.Slice(due, func(i, j int) bool {
		if due[i].NextRunAt != due[j].NextRunAt {
			return testStartedBefore(due[i].NextRunAt, due[j].NextRunAt)
		}
		return testPlanKey(due[i].ProductID, due[i].ID) < testPlanKey(due[j].ProductID, due[j].ID)
	})
	for _, scheduled := range due {
		if _, err := a.StartPlan(scheduled.ProductID, scheduled.ID, "operation", "scheduled"); err != nil && !errors.Is(err, ErrTestBusy) {
			a.mu.Lock()
			key := testPlanKey(scheduled.ProductID, scheduled.ID)
			old := a.plans[key]
			// A manual run or plan edit can supersede this due snapshot.
			if old.Revision != scheduled.Revision || old.NextRunAt != scheduled.NextRunAt {
				a.mu.Unlock()
				continue
			}
			plan := old
			plan.LastError = "scheduled_test_unavailable"
			if errors.Is(err, ErrTestCapacity) {
				plan.LastError = "test_capacity"
			}
			plan.NextRunAt = now.Add(time.Duration(plan.IntervalSeconds) * time.Second).UTC().Format(time.RFC3339Nano)
			a.plans[key] = plan
			if a.persistPlansLocked() != nil {
				a.plans[key] = old
			} else {
				a.evidenceRevision++
				a.service.Notify()
			}
			a.mu.Unlock()
		}
	}
}

func (a *ActiveTests) loop() {
	defer close(a.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case now := <-ticker.C:
			a.dispatchDue(now)
		}
	}
}

func (a *ActiveTests) close() { a.cancel(); <-a.done; a.wg.Wait() }
