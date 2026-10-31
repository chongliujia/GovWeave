package compliance

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var evaluationTime = time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)

func demo(t *testing.T) (Pack, Input) {
	t.Helper()
	var pack Pack
	var input Input
	for name, target := range map[string]any{"../../examples/rule-packs/demo-ai-governance.json": &pack, "../../examples/compliance-evaluation.json": &input} {
		data, err := os.ReadFile(name)
		if err != nil || json.Unmarshal(data, target) != nil {
			t.Fatal("invalid example fixture", err)
		}
	}
	if err := ValidatePack(pack); err != nil {
		t.Fatal(err)
	}
	if err := validateInput(input); err != nil {
		t.Fatal(err)
	}
	return pack, input
}

func fact(value string) Fact {
	return Fact{Value: json.RawMessage(value), EvidenceID: "synthetic-evidence", Source: "assessment", ObservedAt: "2026-01-01T00:00:00Z"}
}

func TestEvaluationApplicabilityEvidenceAndPrivacy(t *testing.T) {
	for _, tc := range []struct {
		name, status, controlStatus, reason string
		change                              func(*Pack, *Input)
	}{
		{"missing", "insufficient_evidence", "unknown", "insufficient_evidence", func(p *Pack, in *Input) {}},
		{"satisfied", "satisfied", "pass", "requirement_satisfied", func(p *Pack, in *Input) { in.Facts["transparency.disclosure_verified"] = fact("true") }},
		{"gap", "gaps_detected", "fail", "requirement_not_satisfied", func(p *Pack, in *Input) { in.Facts["transparency.disclosure_verified"] = fact("false") }},
		{"unknown applicability", "insufficient_evidence", "unknown", "applicability_unknown", func(p *Pack, in *Input) { delete(in.Facts, "product.user_facing") }},
		{"out of scope", "satisfied", "not_applicable", "outside_scope", func(p *Pack, in *Input) {
			f := in.Facts["product.user_facing"]
			f.Value = json.RawMessage("false")
			in.Facts["product.user_facing"] = f
		}},
		{"all not applicable", "not_applicable", "not_applicable", "outside_effective_window", func(p *Pack, in *Input) { p.EffectiveFrom = "2027-01-01T00:00:00Z" }},
		{"end exclusive", "not_applicable", "not_applicable", "outside_effective_window", func(p *Pack, in *Input) { p.EffectiveTo = evaluationTime.Format(time.RFC3339) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pack, input := demo(t)
			tc.change(&pack, &input)
			input.Facts["unused.secret"] = fact(`"synthetic-sensitive-value"`)
			result := evaluate(pack, "test-digest", input, evaluationTime)
			if result.Status != tc.status || result.Controls[0].Status != tc.controlStatus || result.Controls[0].Reason != tc.reason {
				t.Fatalf("unexpected evaluation: %+v", result)
			}
			if !result.EvaluationOnly || result.LegalCompliance != "not_determined" || result.PackReview != "draft" {
				t.Fatal("technical results became legal conclusions")
			}
			data, _ := json.Marshal(result)
			if strings.Contains(string(data), "synthetic-sensitive-value") || strings.Contains(string(data), `"value"`) {
				t.Fatal("fact values leaked into results")
			}
		})
	}
}

func TestEvidenceValidityAndTypes(t *testing.T) {
	for _, tc := range []struct {
		name, issue string
		value       Fact
	}{
		{"expired", "expired_evidence", func() Fact { f := fact("true"); f.ExpiresAt = evaluationTime.Format(time.RFC3339); return f }()},
		{"future", "future_evidence", func() Fact { f := fact("true"); f.ObservedAt = "2027-01-01T00:00:00Z"; return f }()},
		{"claimed declaration", "source_mismatch", func() Fact { f := fact("true"); f.Source = "declared"; return f }()},
		{"type mismatch", "type_mismatch", fact(`"true"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pack, input := demo(t)
			input.Facts["transparency.disclosure_verified"] = tc.value
			result := evaluate(pack, "digest", input, evaluationTime)
			control := result.Controls[0]
			if control.Status != "unknown" || len(control.Issues) != 1 || control.Issues[0].Code != tc.issue {
				t.Fatalf("unreliable evidence accepted: %+v", control)
			}
		})
	}
	pack, input := demo(t)
	pack.Controls[0].Requirement.MaxAgeSeconds = 300
	input.Facts["transparency.disclosure_verified"] = fact("true")
	result := evaluate(pack, "digest", input, evaluationTime)
	if result.Controls[0].Status != "unknown" || result.Controls[0].Issues[0].Code != "stale_evidence" {
		t.Fatal("old evidence without an explicit expiry bypassed rule freshness")
	}
}

func TestThreeValuedExpressionsAndExactNumbers(t *testing.T) {
	for _, tc := range []struct {
		expression string
		want       truth
	}{
		{`{"all":[{"fact":"a","operator":"eq","value":false},{"fact":"missing","operator":"exists"}]}`, no},
		{`{"all":[{"fact":"a","operator":"eq","value":true},{"fact":"missing","operator":"exists"}]}`, unknown},
		{`{"any":[{"fact":"missing","operator":"exists"},{"fact":"a","operator":"eq","value":true}]}`, yes},
		{`{"any":[{"fact":"missing","operator":"exists"},{"fact":"a","operator":"eq","value":false}]}`, unknown},
		{`{"not":{"fact":"missing","operator":"exists"}}`, unknown},
		{`{"not":{"fact":"a","operator":"eq","value":false}}`, yes},
		{`{"fact":"a","operator":"neq","value":false}`, yes},
		{`{"fact":"a","operator":"in","value":[false,true]}`, yes},
		{`{"fact":"n","operator":"gt","value":9007199254740992}`, yes},
		{`{"fact":"n","operator":"lte","value":9007199254740992}`, no},
		{`{"fact":"decimal","operator":"eq","value":0.3}`, yes},
	} {
		var expression Expression
		if json.Unmarshal([]byte(tc.expression), &expression) != nil {
			t.Fatal("bad test expression")
		}
		count := 0
		if err := validateExpression(expression, 1, &count); err != nil {
			t.Fatal(err)
		}
		a := assessment{facts: map[string]Fact{"a": fact("true"), "n": fact("9007199254740993"), "decimal": fact("3e-1")}, now: evaluationTime, evidence: map[string]EvidenceReference{}, issues: map[Issue]bool{}}
		if got := a.evaluate(expression); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.expression, got, tc.want)
		}
	}
}

func TestValidationRejectsUnsafeOrAmbiguousRules(t *testing.T) {
	for _, raw := range []string{`{}`, `{"all":[]}`, `{"fact":"a","operator":"execute","value":"command"}`, `{"fact":"a","operator":"gt","value":"word"}`, `{"fact":"a","operator":"eq","value":null}`, `{"fact":"a","operator":"eq","value":1e999999}`, `{"fact":"a","operator":"in","value":[true,1]}`, `{"fact":"a","operator":"eq","value":true,"any":[]}`, `{"not":{"fact":"a","operator":"exists"},"value":true}`} {
		var expression Expression
		_ = json.Unmarshal([]byte(raw), &expression)
		count := 0
		if validateExpression(expression, 1, &count) == nil {
			t.Fatalf("invalid expression accepted: %s", raw)
		}
	}
	pack, input := demo(t)
	pack.Controls[0].Requirement = Expression{Fact: "a", Operator: "exists"}
	for i := 0; i < 9; i++ {
		child := pack.Controls[0].Requirement
		pack.Controls[0].Requirement = Expression{Not: &child}
	}
	if ValidatePack(pack) == nil {
		t.Fatal("unbounded expression depth")
	}
	input.Facts["bad"] = fact(`{"arbitrary":"object"}`)
	if validateInput(input) == nil {
		t.Fatal("structured unbounded facts accepted")
	}
}

func installDemo(t *testing.T) (string, *Engine, Input) {
	t.Helper()
	pack, input := demo(t)
	dir := t.TempDir()
	data, _ := json.Marshal(pack)
	if err := os.WriteFile(filepath.Join(dir, "demo.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, e, input
}

func TestLocalPluginsVersioningAndConcurrentIsolation(t *testing.T) {
	dir, engine, input := installDemo(t)
	first, err := engine.Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	catalog := engine.Catalog()
	catalog[0].ID = "mutated"
	pack, _ := demo(t)
	pack.Controls[0].Requirement.Value = json.RawMessage("false")
	data, _ := json.Marshal(pack)
	if err := os.WriteFile(filepath.Join(dir, "demo.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if engine.Catalog()[0].SHA256 != first.PackSHA256 {
		t.Fatal("disk or caller mutation changed loaded plugin")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Catalog()[0].SHA256 == first.PackSHA256 {
		t.Fatal("changed contents retained old digest")
	}
	input.PackVersion = "missing"
	if _, err := engine.Evaluate(input); !errors.Is(err, ErrPackNotFound) {
		t.Fatal("silently substituted another pack version")
	}
	input.PackVersion = pack.Version
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				result, err := engine.Evaluate(input)
				if err != nil || result.PackSHA256 != first.PackSHA256 || !reflect.DeepEqual(result.Controls, first.Controls) {
					t.Error("inconsistent concurrent evaluation")
				}
			}
		}()
	}
	wg.Wait()
}

func TestPluginLoadFailures(t *testing.T) {
	dir, _, _ := installDemo(t)
	data, _ := os.ReadFile(filepath.Join(dir, "demo.json"))
	if err := os.WriteFile(filepath.Join(dir, "duplicate.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("duplicate plugin accepted")
	}
	_ = os.Remove(filepath.Join(dir, "duplicate.json"))
	if err := os.WriteFile(filepath.Join(dir, "demo.json"), []byte(strings.Replace(string(data), `"schema_version":1`, `"schema_version":2`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("unsupported schema accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "demo.json"), []byte(`{"script":"anything"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("unknown plugin fields accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "demo.json"), []byte(strings.Repeat(" ", MaxPackBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("oversized plugin accepted")
	}
	_ = os.Remove(filepath.Join(dir, "demo.json"))
	if err := os.Symlink("missing.json", filepath.Join(dir, "link.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("plugin symlink accepted")
	}
	empty, err := Open(filepath.Join(t.TempDir(), "absent"))
	if err != nil || len(empty.Catalog()) != 0 {
		t.Fatal("missing directory should yield empty catalog")
	}
}

func TestEvaluationAdmissionLimit(t *testing.T) {
	_, engine, input := installDemo(t)
	for i := 0; i < MaxConcurrentEvaluations; i++ {
		engine.slots <- struct{}{}
	}
	if _, err := engine.Evaluate(input); !errors.Is(err, ErrBusy) {
		t.Fatal("evaluation limit bypassed")
	}
	<-engine.slots
	if _, err := engine.Evaluate(input); err != nil {
		t.Fatal("evaluation slot was not reusable", err)
	}
}
