// Package compliance evaluates versioned technical controls against supplied
// evidence. It does not issue legal conclusions or execute enforcement actions.
package compliance

import (
	"encoding/json"
	"math/big"
	"slices"
	"sort"
	"time"
)

const EngineVersion = "declarative-controls-v2"

type Source struct {
	Title     string `json:"title"`
	URL       string `json:"url,omitempty"`
	Version   string `json:"version"`
	CheckedOn string `json:"checked_on,omitempty"`
}

type Review struct {
	Status     string `json:"status"`
	Reviewer   string `json:"reviewer,omitempty"`
	ReviewedAt string `json:"reviewed_at,omitempty"`
}

type Pack struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	Version       string    `json:"version"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Limitations   []string  `json:"limitations,omitempty"`
	FrameworkKind string    `json:"framework_kind"`
	Sources       []Source  `json:"sources"`
	Review        Review    `json:"review"`
	EffectiveFrom string    `json:"effective_from,omitempty"`
	EffectiveTo   string    `json:"effective_to,omitempty"`
	Controls      []Control `json:"controls"`
}

type Control struct {
	ID               string      `json:"id"`
	Title            string      `json:"title"`
	Citation         string      `json:"citation"`
	Severity         string      `json:"severity"`
	AssessmentMethod string      `json:"assessment_method,omitempty"`
	Basis            string      `json:"basis,omitempty"`
	Remediation      string      `json:"remediation,omitempty"`
	AppliesWhen      *Expression `json:"applies_when,omitempty"`
	Requirement      Expression  `json:"requirement"`
}

// Expressions are bounded data, never scripts, regexes or external calls.
type Expression struct {
	All           []Expression    `json:"all,omitempty"`
	Any           []Expression    `json:"any,omitempty"`
	Not           *Expression     `json:"not,omitempty"`
	Fact          string          `json:"fact,omitempty"`
	Operator      string          `json:"operator,omitempty"`
	Value         json.RawMessage `json:"value,omitempty"`
	Source        string          `json:"source,omitempty"`
	MaxAgeSeconds int64           `json:"max_age_seconds,omitempty"`
}

type Fact struct {
	Value      json.RawMessage `json:"value"`
	EvidenceID string          `json:"evidence_id"`
	Source     string          `json:"source"`
	ObservedAt string          `json:"observed_at"`
	ExpiresAt  string          `json:"expires_at,omitempty"`
}

type Input struct {
	PackID         string          `json:"pack_id"`
	PackVersion    string          `json:"pack_version"`
	ProductID      string          `json:"product_id"`
	ProductVersion string          `json:"product_version"`
	Facts          map[string]Fact `json:"facts"`
}

type EvidenceReference struct {
	Fact       string `json:"fact"`
	EvidenceID string `json:"evidence_id"`
	Source     string `json:"source"`
	ObservedAt string `json:"observed_at"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type Issue struct {
	Fact string `json:"fact"`
	Code string `json:"code"`
}

type ControlResult struct {
	ID               string              `json:"id"`
	Title            string              `json:"title"`
	Citation         string              `json:"citation"`
	Severity         string              `json:"severity"`
	AssessmentMethod string              `json:"assessment_method"`
	Basis            string              `json:"basis,omitempty"`
	Status           string              `json:"status"`
	Reason           string              `json:"reason"`
	Evidence         []EvidenceReference `json:"evidence"`
	Issues           []Issue             `json:"issues"`
}

type Finding struct {
	ControlID     string   `json:"control_id"`
	Citation      string   `json:"citation"`
	Basis         string   `json:"basis,omitempty"`
	Category      string   `json:"category"`
	Severity      string   `json:"severity"`
	Action        string   `json:"action"`
	EvidenceFacts []string `json:"evidence_facts"`
}

type Evaluation struct {
	SchemaVersion   int             `json:"schema_version"`
	EngineVersion   string          `json:"engine_version"`
	ProductID       string          `json:"product_id"`
	ProductVersion  string          `json:"product_version"`
	PackID          string          `json:"pack_id"`
	PackVersion     string          `json:"pack_version"`
	PackSHA256      string          `json:"pack_sha256"`
	PackReview      string          `json:"pack_review_status"`
	EvaluatedAt     string          `json:"evaluated_at"`
	ReevaluateAt    string          `json:"reevaluate_at,omitempty"`
	EvaluationOnly  bool            `json:"evaluation_only"`
	LegalCompliance string          `json:"legal_compliance"`
	Status          string          `json:"status"`
	Controls        []ControlResult `json:"controls"`
	Findings        []Finding       `json:"findings"`
}

type truth int

const (
	unknown truth = iota
	no
	yes
)

type assessment struct {
	facts    map[string]Fact
	now      time.Time
	evidence map[string]EvidenceReference
	issues   map[Issue]bool
}

func (a *assessment) evaluate(e Expression) truth {
	if e.Not != nil {
		v := a.evaluate(*e.Not)
		if v == yes {
			return no
		}
		if v == no {
			return yes
		}
		return unknown
	}
	if e.All != nil || e.Any != nil {
		items, result := e.All, yes
		if e.Any != nil {
			items, result = e.Any, no
		}
		uncertain := false
		for _, child := range items {
			v := a.evaluate(child)
			uncertain = uncertain || v == unknown
			if e.All != nil && v == no {
				result = no
			}
			if e.Any != nil && v == yes {
				result = yes
			}
		}
		if (e.All != nil && result == no) || (e.Any != nil && result == yes) {
			return result
		}
		if uncertain {
			return unknown
		}
		return result
	}
	fact, ok := a.facts[e.Fact]
	issue := func(code string) truth { a.issues[Issue{Fact: e.Fact, Code: code}] = true; return unknown }
	if !ok {
		return issue("missing_evidence")
	}
	a.evidence[e.Fact] = EvidenceReference{Fact: e.Fact, EvidenceID: fact.EvidenceID, Source: fact.Source, ObservedAt: fact.ObservedAt, ExpiresAt: fact.ExpiresAt}
	observed, _ := time.Parse(time.RFC3339Nano, fact.ObservedAt)
	if observed.After(a.now) {
		return issue("future_evidence")
	}
	if e.MaxAgeSeconds > 0 && !a.now.Before(observed.Add(time.Duration(e.MaxAgeSeconds)*time.Second)) {
		return issue("stale_evidence")
	}
	if fact.ExpiresAt != "" {
		expires, _ := time.Parse(time.RFC3339Nano, fact.ExpiresAt)
		if !a.now.Before(expires) {
			return issue("expired_evidence")
		}
	}
	if e.Source != "" && e.Source != fact.Source {
		return issue("source_mismatch")
	}
	if e.Operator == "exists" {
		return yes
	}
	value, _ := scalar(fact.Value)
	if e.Operator == "in" {
		var choices []json.RawMessage
		_ = json.Unmarshal(e.Value, &choices)
		for _, choice := range choices {
			expected, _ := scalar(choice)
			comparison, compatible := compare(value, expected)
			if !compatible {
				return issue("type_mismatch")
			}
			if comparison == 0 {
				return yes
			}
		}
		return no
	}
	expected, _ := scalar(e.Value)
	comparison, compatible := compare(value, expected)
	if !compatible {
		return issue("type_mismatch")
	}
	matched := false
	switch e.Operator {
	case "eq":
		matched = comparison == 0
	case "neq":
		matched = comparison != 0
	case "gt":
		matched = comparison > 0
	case "gte":
		matched = comparison >= 0
	case "lt":
		matched = comparison < 0
	case "lte":
		matched = comparison <= 0
	}
	if matched {
		return yes
	}
	return no
}

func compare(a, b any) (int, bool) {
	switch value := a.(type) {
	case bool:
		other, ok := b.(bool)
		if !ok {
			return 0, false
		}
		if value == other {
			return 0, true
		}
		return 1, true
	case string:
		other, ok := b.(string)
		if !ok {
			return 0, false
		}
		if value == other {
			return 0, true
		}
		return 1, true
	case json.Number:
		other, ok := b.(json.Number)
		if !ok {
			return 0, false
		}
		left, _ := new(big.Rat).SetString(string(value))
		right, _ := new(big.Rat).SetString(string(other))
		return left.Cmp(right), true
	}
	return 0, false
}

func evaluate(pack Pack, digest string, input Input, now time.Time) Evaluation {
	result := Evaluation{SchemaVersion: 1, EngineVersion: EngineVersion, ProductID: input.ProductID, ProductVersion: input.ProductVersion, PackID: pack.ID, PackVersion: pack.Version, PackSHA256: digest, PackReview: pack.Review.Status, EvaluatedAt: now.UTC().Format(time.RFC3339Nano), EvaluationOnly: true, LegalCompliance: "not_determined", Status: "not_applicable", Controls: []ControlResult{}, Findings: []Finding{}}
	result.ReevaluateAt = nextClockChange(pack, input, now)
	active := true
	if pack.EffectiveFrom != "" {
		start, _ := time.Parse(time.RFC3339Nano, pack.EffectiveFrom)
		active = !now.Before(start)
	}
	if pack.EffectiveTo != "" {
		end, _ := time.Parse(time.RFC3339Nano, pack.EffectiveTo)
		active = active && now.Before(end)
	}
	for _, control := range pack.Controls {
		a := assessment{facts: input.Facts, now: now, evidence: map[string]EvidenceReference{}, issues: map[Issue]bool{}}
		method := control.AssessmentMethod
		if method == "" {
			method = "evidence"
		}
		item := ControlResult{ID: control.ID, Title: control.Title, Citation: control.Citation, Severity: control.Severity, AssessmentMethod: method, Basis: control.Basis, Status: "not_applicable", Reason: "outside_effective_window", Evidence: []EvidenceReference{}, Issues: []Issue{}}
		if active {
			applicable := yes
			if control.AppliesWhen != nil {
				applicable = a.evaluate(*control.AppliesWhen)
			}
			switch applicable {
			case no:
				item.Reason = "outside_scope"
			case unknown:
				item.Status, item.Reason = "unknown", "applicability_unknown"
			case yes:
				requirement := a.evaluate(control.Requirement)
				switch requirement {
				case yes:
					item.Status, item.Reason = "pass", "requirement_satisfied"
				case no:
					item.Status, item.Reason = "fail", "requirement_not_satisfied"
				case unknown:
					item.Status, item.Reason = "unknown", "insufficient_evidence"
				}
				if method == "manual" {
					item.Status, item.Reason = "unknown", "manual_review_required"
				}
			}
		}
		for _, reference := range a.evidence {
			item.Evidence = append(item.Evidence, reference)
		}
		for issue := range a.issues {
			item.Issues = append(item.Issues, issue)
		}
		sort.Slice(item.Evidence, func(i, j int) bool { return item.Evidence[i].Fact < item.Evidence[j].Fact })
		sort.Slice(item.Issues, func(i, j int) bool {
			if item.Issues[i].Fact == item.Issues[j].Fact {
				return item.Issues[i].Code < item.Issues[j].Code
			}
			return item.Issues[i].Fact < item.Issues[j].Fact
		})
		result.Controls = append(result.Controls, item)
		if item.Status == "fail" || item.Status == "unknown" {
			finding := Finding{ControlID: item.ID, Citation: item.Citation, Basis: item.Basis, Category: "evidence_gap", Severity: item.Severity, Action: control.Remediation, EvidenceFacts: []string{}}
			if item.Status == "fail" {
				finding.Category = "control_gap"
			}
			if item.AssessmentMethod == "manual" || item.Reason == "applicability_unknown" {
				finding.Category = "manual_review"
			}
			if finding.Action == "" {
				switch finding.Category {
				case "control_gap":
					finding.Action = "Correct the failed technical control and provide current verification evidence."
				case "manual_review":
					finding.Action = "Have a qualified reviewer assess applicability or the interpretive requirement and retain their evidence."
				default:
					finding.Action = "Supply current evidence of the expected type and source, then reassess."
				}
			}
			for _, issue := range item.Issues {
				if !slices.Contains(finding.EvidenceFacts, issue.Fact) {
					finding.EvidenceFacts = append(finding.EvidenceFacts, issue.Fact)
				}
			}
			result.Findings = append(result.Findings, finding)
		}
	}
	for _, status := range []struct{ control, overall string }{{"fail", "gaps_detected"}, {"unknown", "insufficient_evidence"}, {"pass", "satisfied"}} {
		if slices.ContainsFunc(result.Controls, func(c ControlResult) bool { return c.Status == status.control }) {
			result.Status = status.overall
			break
		}
	}
	return result
}
