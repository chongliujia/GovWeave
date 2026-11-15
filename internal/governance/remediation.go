package governance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"govweave/internal/compliance"
	"govweave/internal/config"
	"govweave/internal/gateway"
	"govweave/internal/storage"
)

const MaxRemediations = 128
const MaxRemediationEvents = 64
const maxRemediationBytes = 2 << 20

var ErrRemediationCapacity = errors.New("remediation capacity reached; existing history is retained")
var ErrRemediationUnavailable = errors.New("remediation history or its evidence is unavailable or invalid")
var ErrRemediationDuplicate = errors.New("this control and application scope already have a remediation; reopen the existing record")
var ErrRemediationScope = errors.New("the rule pack or application scope changed; verify the original scope or create a new remediation")
var ErrRemediationState = errors.New("mark remediation ready for recheck before verifying; verified records must be reopened before editing")
var ErrRemediationTest = errors.New("select a completed, current test for this product that started after remediation was marked ready")
var remediationID = regexp.MustCompile(`^rem_[A-Za-z0-9_-]{22}$`)

type RemediationInput struct {
	Revision uint64 `json:"revision"`
	Status   string `json:"status"`
	Owner    string `json:"owner"`
	DueDate  string `json:"due_date"`
	Note     string `json:"note"`
}

type RemediationCreate struct {
	ReportID  string `json:"report_id"`
	ControlID string `json:"control_id"`
	Owner     string `json:"owner"`
	DueDate   string `json:"due_date"`
	Note      string `json:"note"`
}

type RemediationCheck struct {
	Revision  uint64 `json:"revision"`
	TestRunID string `json:"test_run_id,omitempty"`
}

// Evidence references point to retained snapshots, never copied model bodies.
type RemediationVerification struct {
	ReportID      string `json:"report_id"`
	ReportSHA256  string `json:"report_sha256"`
	ControlStatus string `json:"control_status"`
	Result        string `json:"result"`
	TestRunID     string `json:"test_run_id,omitempty"`
	TestSHA256    string `json:"test_sha256,omitempty"`
}

type RemediationEvent struct {
	RemediationInput
	At           string                   `json:"at"`
	Verification *RemediationVerification `json:"verification,omitempty"`
}

type Remediation struct {
	ID             string             `json:"id"`
	ProductID      string             `json:"product_id"`
	ControlID      string             `json:"control_id"`
	Title          string             `json:"title"`
	SourceReportID string             `json:"source_report_id"`
	SourceSHA256   string             `json:"source_sha256"`
	PackSHA256     string             `json:"pack_sha256"`
	ApplicationIDs []string           `json:"application_ids"`
	Events         []RemediationEvent `json:"events"`
}

type RemediationView struct {
	Remediation
	Current           RemediationEvent `json:"current"`
	VerificationState string           `json:"verification_state"`
}

type remediationState struct {
	SchemaVersion int           `json:"schema_version"`
	Items         []Remediation `json:"items"`
}

type Remediations struct {
	mu      sync.Mutex
	path    string
	state   remediationState
	service *Service
}

func openRemediations(dir string, service *Service) (*Remediations, error) {
	m := &Remediations{path: filepath.Join(dir, "remediations.json"), service: service, state: remediationState{1, []Remediation{}}}
	info, err := os.Lstat(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxRemediationBytes {
		return nil, ErrRemediationUnavailable
	}
	f, err := os.Open(m.path)
	if err != nil {
		return nil, ErrRemediationUnavailable
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRemediationBytes+1))
	if err != nil || len(data) > maxRemediationBytes || config.DecodeStrict(bytes.NewReader(data), &m.state) != nil || m.state.SchemaVersion != 1 || m.state.Items == nil || len(m.state.Items) > MaxRemediations {
		return nil, ErrRemediationUnavailable
	}
	seen := map[string]bool{}
	bindings := map[string]bool{}
	for _, item := range m.state.Items {
		apps := slices.Clone(item.ApplicationIDs)
		slices.Sort(apps)
		binding := digestJSON([]any{item.ProductID, item.ControlID, item.PackSHA256, apps})
		if seen[item.ID] || bindings[binding] || m.validate(item) != nil {
			return nil, ErrRemediationUnavailable
		}
		seen[item.ID] = true
		bindings[binding] = true
	}
	return m, nil
}

func validRemediationText(value string, limit int) bool {
	return utf8.ValidString(value) && len(value) <= limit && value == strings.TrimSpace(value) && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' })
}

func validateRemediationInput(in RemediationInput) error {
	if !slices.Contains([]string{"open", "in_progress", "ready_for_recheck"}, in.Status) || !validRemediationText(in.Owner, 100) || !validRemediationText(in.Note, 2000) {
		return errors.New("use a valid remediation status, owner (100 bytes) and note (2000 bytes), without surrounding whitespace")
	}
	if in.DueDate != "" {
		if _, err := time.Parse("2006-01-02", in.DueDate); err != nil {
			return errors.New("due_date must be an ISO date or empty")
		}
	}
	if in.Status == "ready_for_recheck" && in.Note == "" {
		return errors.New("describe the remediation before marking it ready for recheck")
	}
	return nil
}

func sameApplications(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func reportControl(report ArchivedReport, id string) (compliance.ControlResult, error) {
	for _, c := range report.Snapshot.Report.Evaluation.Controls {
		if c.ID == id {
			return c, nil
		}
	}
	return compliance.ControlResult{}, gateway.ErrNotFound
}

func (m *Remediations) validate(item Remediation) error {
	if !remediationID.MatchString(item.ID) || len(item.Events) < 1 || len(item.Events) > MaxRemediationEvents {
		return ErrRemediationUnavailable
	}
	source, err := m.service.Archives.Get(item.SourceReportID)
	if err != nil {
		return err
	}
	c, err := reportControl(source, item.ControlID)
	if err != nil || !slices.Contains([]string{"fail", "unknown"}, c.Status) || source.Summary.SHA256 != item.SourceSHA256 || source.Summary.ProductID != item.ProductID || source.Summary.PackSHA256 != item.PackSHA256 || c.Title != item.Title || !slices.Equal(source.Snapshot.Product.ApplicationIDs, item.ApplicationIDs) {
		return ErrRemediationUnavailable
	}
	var previous time.Time
	for i, event := range item.Events {
		at, err := time.Parse(time.RFC3339Nano, event.At)
		if err != nil || at.Before(previous) || event.Revision != uint64(i+1) {
			return ErrRemediationUnavailable
		}
		previous = at
		in := event.RemediationInput
		if in.Status == "verified" {
			in.Status = "ready_for_recheck"
		}
		if validateRemediationInput(in) != nil || i == 0 && (event.Status != "open" || event.Verification != nil) {
			return ErrRemediationUnavailable
		}
		if event.Verification == nil {
			if event.Status == "verified" || i > 0 && item.Events[i-1].Status == "verified" && event.Status != "open" {
				return ErrRemediationUnavailable
			}
			continue
		}
		if i == 0 || item.Events[i-1].Status != "ready_for_recheck" {
			return ErrRemediationUnavailable
		}
		v := event.Verification
		report, err := m.service.Archives.Get(v.ReportID)
		if err != nil || report.Summary.SHA256 != v.ReportSHA256 || m.matches(item, report) != nil {
			return ErrRemediationUnavailable
		}
		control, err := reportControl(report, item.ControlID)
		evaluated, _ := time.Parse(time.RFC3339Nano, report.Snapshot.Report.Evaluation.EvaluatedAt)
		ready, _ := time.Parse(time.RFC3339Nano, item.Events[i-1].At)
		if err != nil || evaluated.Before(ready) || evaluated.After(at) || control.Status != v.ControlStatus || event.Owner != item.Events[i-1].Owner || event.Note != item.Events[i-1].Note || event.DueDate != item.Events[i-1].DueDate {
			return ErrRemediationUnavailable
		}
		result := control.Status
		if v.TestRunID != "" {
			run, err := m.service.Tests.Get(v.TestRunID)
			started, _ := time.Parse(time.RFC3339Nano, run.StartedAt)
			finished, _ := time.Parse(time.RFC3339Nano, run.FinishedAt)
			stamp := report.Snapshot.Report.Snapshot
			output, _, validOutput := retainedRevision(run, "runtime.output_policy_revision")
			tool, _, validTool := retainedToolRevision(run)
			if err != nil || digestJSON(run) != v.TestSHA256 || run.Product.ID != item.ProductID || run.Product.Revision != report.Summary.ProductRevision || run.GatewayRevision != stamp.GatewayRevision || run.PolicyRevision != stamp.PolicyRevision || !validOutput || output != stamp.OutputPolicyRevision || !validTool || tool != stamp.ToolRevision || run.State != "completed" || started.Before(ready) || finished.After(evaluated) || !evaluated.Before(remediationTestExpiry(run)) {
				return ErrRemediationUnavailable
			}
			if run.Status != "passed" {
				result = "unknown"
				if run.Status == "failed" {
					result = "fail"
				}
			}
		} else if v.TestSHA256 != "" {
			return ErrRemediationUnavailable
		}
		if result != v.Result || (result == "pass") != (event.Status == "verified") || result != "pass" && event.Status != "in_progress" {
			return ErrRemediationUnavailable
		}
	}
	return nil
}

func (m *Remediations) matches(item Remediation, report ArchivedReport) error {
	if report.Summary.ProductID != item.ProductID || report.Summary.PackSHA256 != item.PackSHA256 || !sameApplications(report.Snapshot.Product.ApplicationIDs, item.ApplicationIDs) {
		return ErrRemediationScope
	}
	return nil
}

func cloneRemediation(item Remediation) Remediation {
	item.ApplicationIDs = slices.Clone(item.ApplicationIDs)
	item.Events = slices.Clone(item.Events)
	for i := range item.Events {
		if item.Events[i].Verification != nil {
			v := *item.Events[i].Verification
			item.Events[i].Verification = &v
		}
	}
	return item
}

func (m *Remediations) index(productID, id string) (int, error) {
	for i, item := range m.state.Items {
		if item.ID == id && item.ProductID == productID {
			return i, nil
		}
	}
	return 0, gateway.ErrNotFound
}

func (m *Remediations) save(index int, item Remediation) error {
	if len(item.Events) > MaxRemediationEvents || index < 0 && len(m.state.Items) >= MaxRemediations {
		return ErrRemediationCapacity
	}
	next := remediationState{1, slices.Clone(m.state.Items)}
	if index < 0 {
		next.Items = append(next.Items, item)
	} else {
		next.Items[index] = item
	}
	data, err := json.Marshal(next)
	if err != nil || len(data) > maxRemediationBytes {
		return ErrRemediationCapacity
	}
	if storage.AtomicWrite(m.path, data) != nil {
		return gateway.ErrPersistence
	}
	m.state = next
	return nil
}

func (m *Remediations) Create(productID string, in RemediationCreate) (RemediationView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	input := RemediationInput{Status: "open", Owner: in.Owner, DueDate: in.DueDate, Note: in.Note}
	if err := validateRemediationInput(input); err != nil {
		return RemediationView{}, err
	}
	source, err := m.service.Archives.Get(in.ReportID)
	if err != nil {
		return RemediationView{}, err
	}
	if source.Summary.ProductID != productID {
		return RemediationView{}, gateway.ErrNotFound
	}
	control, err := reportControl(source, in.ControlID)
	if err != nil {
		return RemediationView{}, err
	}
	if control.Status != "fail" && control.Status != "unknown" {
		return RemediationView{}, errors.New("remediations require a retained control gap or unknown result")
	}
	for _, existing := range m.state.Items {
		if existing.ProductID == productID && existing.ControlID == in.ControlID && existing.PackSHA256 == source.Summary.PackSHA256 && sameApplications(existing.ApplicationIDs, source.Snapshot.Product.ApplicationIDs) {
			return RemediationView{}, ErrRemediationDuplicate
		}
	}
	id, err := storage.ID("rem_", 16)
	if err != nil {
		return RemediationView{}, gateway.ErrPersistence
	}
	input.Revision = 1
	item := Remediation{ID: id, ProductID: productID, ControlID: in.ControlID, Title: control.Title, SourceReportID: in.ReportID, SourceSHA256: source.Summary.SHA256, PackSHA256: source.Summary.PackSHA256, ApplicationIDs: slices.Clone(source.Snapshot.Product.ApplicationIDs), Events: []RemediationEvent{{RemediationInput: input, At: time.Now().UTC().Format(time.RFC3339Nano)}}}
	if err := m.save(-1, item); err != nil {
		return RemediationView{}, err
	}
	return m.view(item), nil
}

func (m *Remediations) Update(productID, id string, in RemediationInput) (RemediationView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, err := m.index(productID, id)
	if err != nil {
		return RemediationView{}, err
	}
	item := cloneRemediation(m.state.Items[i])
	current := item.Events[len(item.Events)-1]
	if in.Revision != current.Revision {
		return RemediationView{}, gateway.ErrConflict
	}
	if err := validateRemediationInput(in); err != nil {
		return RemediationView{}, err
	}
	if current.Status == "verified" && in.Status != "open" {
		return RemediationView{}, ErrRemediationState
	}
	in.Revision++
	item.Events = append(item.Events, RemediationEvent{RemediationInput: in, At: time.Now().UTC().Format(time.RFC3339Nano)})
	if err := m.save(i, item); err != nil {
		return RemediationView{}, err
	}
	return m.view(item), nil
}

func (m *Remediations) Check(productID, id string, in RemediationCheck) (RemediationView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, err := m.index(productID, id)
	if err != nil {
		return RemediationView{}, err
	}
	item := cloneRemediation(m.state.Items[i])
	current := item.Events[len(item.Events)-1]
	if in.Revision != current.Revision {
		return RemediationView{}, gateway.ErrConflict
	}
	if current.Status != "ready_for_recheck" {
		return RemediationView{}, ErrRemediationState
	}
	if len(item.Events) >= MaxRemediationEvents {
		return RemediationView{}, ErrRemediationCapacity
	}
	product, err := m.service.Products.Get(productID)
	if err != nil {
		return RemediationView{}, err
	}
	pack, err := m.service.evaluator.PackSnapshot(product.PackID, product.PackVersion)
	if err != nil {
		return RemediationView{}, err
	}
	if digestJSON(pack) != item.PackSHA256 || !sameApplications(product.ApplicationIDs, item.ApplicationIDs) {
		return RemediationView{}, ErrRemediationScope
	}
	var run TestRun
	if in.TestRunID != "" {
		run, err = m.service.Tests.Get(in.TestRunID)
		ready, _ := time.Parse(time.RFC3339Nano, current.At)
		started, _ := time.Parse(time.RFC3339Nano, run.StartedAt)
		if err != nil || run.Product.ID != productID || run.State != "completed" || started.Before(ready) || !m.service.Tests.sourceMatches(run) || !time.Now().Before(remediationTestExpiry(run)) {
			return RemediationView{}, ErrRemediationTest
		}
	}
	// A fresh local assessment consumes saved facts; it does not invoke a model.
	report, err := m.service.Archive(productID)
	if err != nil {
		return RemediationView{}, err
	}
	if m.matches(item, report) != nil {
		return RemediationView{}, ErrRemediationScope
	}
	control, err := reportControl(report, item.ControlID)
	if err != nil {
		return RemediationView{}, err
	}
	latest, err := m.service.Products.Get(productID)
	if err != nil || *report.Snapshot.Report.Snapshot != m.service.currentStamp(latest) || in.TestRunID != "" && (!m.service.Tests.sourceMatches(run) || !time.Now().Before(remediationTestExpiry(run))) {
		return RemediationView{}, ErrSnapshotChanged
	}
	v := &RemediationVerification{ReportID: report.Summary.ID, ReportSHA256: report.Summary.SHA256, ControlStatus: control.Status, Result: control.Status}
	if in.TestRunID != "" {
		v.TestRunID, v.TestSHA256 = in.TestRunID, digestJSON(run)
		if run.Status != "passed" {
			v.Result = "unknown"
			if run.Status == "failed" {
				v.Result = "fail"
			}
		}
	}
	current.Revision++
	current.At = time.Now().UTC().Format(time.RFC3339Nano)
	current.Verification = v
	current.Status = "in_progress"
	if v.Result == "pass" {
		current.Status = "verified"
	}
	item.Events = append(item.Events, current)
	if err := m.save(i, item); err != nil {
		return RemediationView{}, err
	}
	return m.view(item), nil
}

func remediationTestExpiry(run TestRun) time.Time {
	finished, _ := time.Parse(time.RFC3339Nano, run.FinishedAt)
	lifetime := 30 * 24 * time.Hour
	if run.Phase == "operation" {
		lifetime = 2 * time.Duration(run.Plan.IntervalSeconds) * time.Second
	}
	return finished.Add(lifetime)
}

func (m *Remediations) view(item Remediation) RemediationView {
	item = cloneRemediation(item)
	current := item.Events[len(item.Events)-1]
	v := RemediationView{Remediation: item, Current: current, VerificationState: "not_verified"}
	if current.Status != "verified" {
		return v
	}
	v.VerificationState = "unavailable"
	report, err := m.service.Archives.Get(current.Verification.ReportID)
	if err != nil || report.Summary.SHA256 != current.Verification.ReportSHA256 {
		return v
	}
	product, err := m.service.Products.Get(item.ProductID)
	if err != nil {
		return v
	}
	v.VerificationState = "stale"
	pack, err := m.service.evaluator.PackSnapshot(product.PackID, product.PackVersion)
	if err != nil || digestJSON(pack) != item.PackSHA256 || report.Snapshot.Report.Evaluation.EngineVersion != compliance.EngineVersion || *report.Snapshot.Report.Snapshot != m.service.currentStamp(product) {
		return v
	}
	// Re-evaluate retained evidence at the read time so expired facts cannot stay current.
	evaluation, err := compliance.EvaluateSnapshot(report.Snapshot.RulePack, report.Snapshot.Input, time.Now())
	if err != nil {
		return v
	}
	passed := slices.ContainsFunc(evaluation.Controls, func(c compliance.ControlResult) bool { return c.ID == item.ControlID && c.Status == "pass" })
	if !passed {
		return v
	}
	if current.Verification.TestRunID != "" {
		run, err := m.service.Tests.Get(current.Verification.TestRunID)
		if err != nil || digestJSON(run) != current.Verification.TestSHA256 {
			v.VerificationState = "unavailable"
			return v
		}
		if !m.service.Tests.sourceMatches(run) {
			return v
		}
		if !time.Now().Before(remediationTestExpiry(run)) {
			return v
		}
	}
	v.VerificationState = "current"
	return v
}

func (m *Remediations) List(productID string) ([]RemediationView, error) {
	if _, err := m.service.Products.Get(productID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	items := []RemediationView{}
	for _, item := range m.state.Items {
		if item.ProductID == productID {
			items = append(items, m.view(item))
		}
	}
	slices.Reverse(items)
	return items, nil
}

func (m *Remediations) Get(productID, id string) (RemediationView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, err := m.index(productID, id)
	if err != nil {
		return RemediationView{}, err
	}
	return m.view(m.state.Items[i]), nil
}
