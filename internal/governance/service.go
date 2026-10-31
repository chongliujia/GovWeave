package governance

import (
	"errors"
	"slices"
	"sync"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/gateway"
)

const RefreshInterval = 30 * time.Second
const coalesceInterval = 250 * time.Millisecond

var ErrSnapshotChanged = errors.New("the product or gateway changed during assessment; retry")

type Report struct {
	SchemaVersion   int                    `json:"schema_version"`
	ProductID       string                 `json:"product_id"`
	ProductRevision uint64                 `json:"product_revision"`
	State           string                 `json:"state"`
	ErrorCode       string                 `json:"error_code,omitempty"`
	NextRefreshAt   string                 `json:"next_refresh_at,omitempty"`
	SampleLimit     int                    `json:"sample_limit"`
	Snapshot        *SourceStamp           `json:"snapshot,omitempty"`
	Evaluation      *compliance.Evaluation `json:"evaluation,omitempty"`
	RuntimeEvidence *RuntimeEvidence       `json:"runtime_evidence,omitempty"`
}

type Service struct {
	Products  *Products
	Archives  *Archives
	Tests     *ActiveTests
	gateway   *gateway.Engine
	evaluator *compliance.Engine
	trigger   chan struct{}
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	reports   map[string]Report
}

func Open(dir string, g *gateway.Engine, evaluator *compliance.Engine) (*Service, error) {
	products, err := openProducts(dir)
	if err != nil {
		return nil, err
	}
	archives, err := openArchives(dir)
	if err != nil {
		return nil, err
	}
	s := &Service{Products: products, Archives: archives, gateway: g, evaluator: evaluator, trigger: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), reports: map[string]Report{}}
	s.Tests, err = openActiveTests(dir, s)
	if err != nil {
		return nil, err
	}
	g.SetChangeChannel(s.trigger)
	go s.run()
	s.Notify()
	return s, nil
}

func (s *Service) Notify() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

func (s *Service) Close() {
	s.closeOnce.Do(func() { s.Tests.close(); s.gateway.SetChangeChannel(nil); close(s.stop); <-s.done })
}

func (s *Service) Save(id string, in ProductInput) (Product, error) {
	product, err := s.Products.save(id, in, s.gateway.Store.Snapshot(), s.evaluator.Catalog())
	if err == nil {
		s.Notify()
	}
	return product, err
}

func cloneReport(report Report) Report {
	report.RuntimeEvidence = cloneRuntimeEvidence(report.RuntimeEvidence)
	if report.Snapshot != nil {
		stamp := *report.Snapshot
		report.Snapshot = &stamp
	}
	if report.Evaluation != nil {
		result := *report.Evaluation
		result.Controls = slices.Clone(result.Controls)
		result.Findings = slices.Clone(result.Findings)
		for i := range result.Findings {
			result.Findings[i].EvidenceFacts = slices.Clone(result.Findings[i].EvidenceFacts)
		}
		for i := range result.Controls {
			result.Controls[i].Evidence = slices.Clone(result.Controls[i].Evidence)
			result.Controls[i].Issues = slices.Clone(result.Controls[i].Issues)
		}
		report.Evaluation = &result
	}
	return report
}

// Latest never presents a previous success as current after input changes or a
// known clock boundary. Pending responses contain no stale evaluation payload.
func (s *Service) Latest(id string) (Report, error) {
	product, err := s.Products.Get(id)
	if err != nil {
		return Report{}, err
	}
	s.mu.Lock()
	report, ok := s.reports[id]
	s.mu.Unlock()
	if ok && report.ProductRevision == product.Revision && report.Snapshot != nil && *report.Snapshot == s.currentStamp(product) {
		if report.State == "error" {
			s.Notify()
			return cloneReport(report), nil
		}
		deadline, err := time.Parse(time.RFC3339Nano, report.NextRefreshAt)
		if err == nil && time.Now().Before(deadline) {
			return cloneReport(report), nil
		}
	}
	s.Notify()
	return Report{SchemaVersion: 1, ProductID: id, ProductRevision: product.Revision, State: "pending", SampleLimit: SampleLimit}, nil
}

func (s *Service) Refresh(id string) (Report, error) {
	_, _, report, err := s.assess(id)
	return report, err
}

func (s *Service) Archive(id string) (ArchivedReport, error) {
	product, input, report, err := s.assess(id)
	if err != nil {
		return ArchivedReport{}, err
	}
	if report.State != "ready" {
		return ArchivedReport{}, ErrAssessmentUnavailable
	}
	pack, err := s.evaluator.PackSnapshot(product.PackID, product.PackVersion)
	if err != nil {
		return ArchivedReport{}, err
	}
	return s.Archives.save(ReportSnapshot{Product: product, Input: input, Report: report, RulePack: pack})
}

func (s *Service) assess(id string) (Product, compliance.Input, Report, error) {
	for attempt := 0; attempt < 3; attempt++ {
		product, err := s.Products.Get(id)
		if err != nil {
			return Product{}, compliance.Input{}, Report{}, err
		}
		source := capture(s.gateway)
		stamp := source.stamp(product)
		input := source.input(product, time.Now())
		stamp.TestEvidenceRevision = s.Tests.addOutputEvidence(product, source, &input)
		result, evaluationErr := s.evaluator.Evaluate(input)
		report := Report{SchemaVersion: 1, ProductID: id, ProductRevision: product.Revision, State: "ready", SampleLimit: SampleLimit, Snapshot: &stamp, Evaluation: &result}
		if evaluationErr != nil {
			report.State, report.Evaluation = "error", nil
			switch {
			case errors.Is(evaluationErr, compliance.ErrPackNotFound):
				report.ErrorCode = "rule_pack_not_found"
			case errors.Is(evaluationErr, compliance.ErrBusy):
				report.ErrorCode = "compliance_busy"
			default:
				report.ErrorCode = "evaluation_failed"
			}
		} else {
			report.RuntimeEvidence = runtimeEvidence(product, input, source)
			deadline := time.Now().Add(RefreshInterval)
			if result.ReevaluateAt != "" {
				boundary, _ := time.Parse(time.RFC3339Nano, result.ReevaluateAt)
				if boundary.Before(deadline) {
					deadline = boundary
				}
			}
			report.NextRefreshAt = deadline.UTC().Format(time.RFC3339Nano)
		}
		s.mu.Lock()
		latest, productErr := s.Products.Get(id)
		deadline, _ := time.Parse(time.RFC3339Nano, report.NextRefreshAt)
		fresh := report.State == "error" || time.Now().Before(deadline)
		if productErr == nil && fresh && stamp == s.currentStamp(latest) {
			s.reports[id] = report
			s.mu.Unlock()
			return product, input, cloneReport(report), nil
		}
		s.mu.Unlock()
	}
	s.Notify()
	return Product{}, compliance.Input{}, Report{}, ErrSnapshotChanged
}

func (s *Service) currentStamp(product Product) SourceStamp {
	stamp := currentStamp(s.gateway, product)
	s.Tests.mu.Lock()
	stamp.TestEvidenceRevision = s.Tests.evidenceRevision
	s.Tests.mu.Unlock()
	return stamp
}

func (s *Service) run() {
	defer close(s.done)
	ticker := time.NewTicker(RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		case <-s.trigger:
			timer := time.NewTimer(coalesceInterval)
			select {
			case <-s.stop:
				timer.Stop()
				return
			case <-timer.C:
			}
			// Signals accumulated before this snapshot are represented by the
			// current source state; signals arriving during work queue a new pass.
			select {
			case <-s.trigger:
			default:
			}
		}
		for _, product := range s.Products.List() {
			select {
			case <-s.stop:
				return
			default:
			}
			_, _ = s.Refresh(product.ID) // Failures are observable via Latest.
		}
	}
}
