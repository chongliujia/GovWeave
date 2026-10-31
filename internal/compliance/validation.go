package compliance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

func sourceOK(source string) bool {
	return slices.Contains([]string{"declared", "runtime", "document", "assessment"}, source)
}

func scalar(raw json.RawMessage) (any, error) {
	if len(raw) == 0 || len(raw) > 1024 {
		return nil, errors.New("invalid scalar")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value, extra any
	if d.Decode(&value) != nil || d.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid scalar")
	}
	switch v := value.(type) {
	case bool:
		return value, nil
	case string:
		if len(v) <= 512 {
			return value, nil
		}
	case json.Number:
		// Bound exponent expansion before exact rational comparisons.
		text := string(v)
		if len(text) > 64 {
			break
		}
		if at := strings.IndexAny(text, "eE"); at >= 0 {
			exponent, err := strconv.Atoi(text[at+1:])
			if err != nil || exponent < -100 || exponent > 100 {
				break
			}
		}
		if _, ok := new(big.Rat).SetString(text); ok {
			return value, nil
		}
	}
	return nil, errors.New("facts and comparison values must be bounded booleans, strings or numbers")
}

func validateExpression(e Expression, depth int, count *int) error {
	(*count)++
	if depth > 8 || *count > 512 {
		return errors.New("rule expression limits exceeded")
	}
	forms := 0
	for _, present := range []bool{e.All != nil, e.Any != nil, e.Not != nil, e.Fact != ""} {
		if present {
			forms++
		}
	}
	if forms != 1 {
		return errors.New("use exactly one expression form: all, any, not, or fact")
	}
	if e.Fact == "" {
		if e.Operator != "" || len(e.Value) != 0 || e.Source != "" || e.MaxAgeSeconds != 0 {
			return errors.New("group expressions cannot contain predicate fields")
		}
		if e.Not != nil {
			return validateExpression(*e.Not, depth+1, count)
		}
		items := e.All
		if e.Any != nil {
			items = e.Any
		}
		if len(items) == 0 || len(items) > 64 {
			return errors.New("expression groups require 1–64 children")
		}
		for _, item := range items {
			if err := validateExpression(item, depth+1, count); err != nil {
				return err
			}
		}
		return nil
	}
	if !identifier.MatchString(e.Fact) || (e.Source != "" && !sourceOK(e.Source)) || e.MaxAgeSeconds < 0 || e.MaxAgeSeconds > 31536000 {
		return errors.New("invalid fact identifier or source")
	}
	if e.Operator == "exists" {
		if len(e.Value) != 0 {
			return errors.New("exists does not accept a comparison value")
		}
		return nil
	}
	if e.Operator == "in" {
		var values []json.RawMessage
		if json.Unmarshal(e.Value, &values) != nil || len(values) < 1 || len(values) > 32 {
			return errors.New("in requires 1–32 scalar comparison values")
		}
		var first any
		for i, raw := range values {
			value, err := scalar(raw)
			if err != nil {
				return err
			}
			if i == 0 {
				first = value
			} else if _, compatible := compare(first, value); !compatible {
				return errors.New("in comparison values must share a type")
			}
		}
		return nil
	}
	if !slices.Contains([]string{"eq", "neq", "gt", "gte", "lt", "lte"}, e.Operator) {
		return errors.New("unsupported rule operator")
	}
	value, err := scalar(e.Value)
	if err != nil {
		return err
	}
	if e.Operator != "eq" && e.Operator != "neq" {
		if _, ok := value.(json.Number); !ok {
			return errors.New("ordered comparisons require a number")
		}
	}
	return nil
}

func ValidatePack(p Pack) error {
	if p.SchemaVersion != 1 || !identifier.MatchString(p.ID) || !identifier.MatchString(p.Version) || len(p.Name) < 1 || len(p.Name) > 160 {
		return errors.New("invalid rule pack identity")
	}
	if !slices.Contains([]string{"internal_policy", "law", "regulation", "standard", "voluntary_framework"}, p.FrameworkKind) {
		return errors.New("invalid framework kind")
	}
	if len(p.Description) > 2000 || len(p.Limitations) > 16 {
		return errors.New("rule pack description or limitations exceed limits")
	}
	for _, limitation := range p.Limitations {
		if len(limitation) < 1 || len(limitation) > 512 {
			return errors.New("invalid rule pack limitation")
		}
	}
	if len(p.Sources) < 1 || len(p.Sources) > 16 {
		return errors.New("rule packs require 1–16 versioned sources")
	}
	for _, source := range p.Sources {
		if len(source.Title) < 1 || len(source.Title) > 160 || len(source.Version) < 1 || len(source.Version) > 100 {
			return errors.New("invalid rule source metadata")
		}
		if source.CheckedOn != "" {
			if _, err := time.Parse("2006-01-02", source.CheckedOn); err != nil {
				return errors.New("invalid source check date")
			}
		}
		if source.URL != "" {
			u, err := url.Parse(source.URL)
			if err != nil || len(source.URL) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
				return errors.New("source URLs must be HTTPS without credentials")
			}
		} else if p.FrameworkKind != "internal_policy" {
			return errors.New("external frameworks require source URLs")
		}
	}
	if p.Review.Status != "draft" && p.Review.Status != "reviewed" {
		return errors.New("invalid review status")
	}
	if p.Review.Status == "reviewed" {
		if len(p.Review.Reviewer) < 1 || len(p.Review.Reviewer) > 160 {
			return errors.New("reviewed packs require reviewer metadata")
		}
		if _, err := time.Parse(time.RFC3339Nano, p.Review.ReviewedAt); err != nil {
			return errors.New("invalid review timestamp")
		}
	} else if p.Review.Reviewer != "" || p.Review.ReviewedAt != "" {
		return errors.New("draft packs cannot declare review completion")
	}
	if err := validateWindow(p.EffectiveFrom, p.EffectiveTo); err != nil {
		return err
	}
	if len(p.Controls) < 1 || len(p.Controls) > 64 {
		return errors.New("rule packs require 1–64 controls")
	}
	seen, count := map[string]bool{}, 0
	for _, control := range p.Controls {
		if !identifier.MatchString(control.ID) || seen[control.ID] || len(control.Title) < 1 || len(control.Title) > 160 || len(control.Citation) < 1 || len(control.Citation) > 256 {
			return errors.New("invalid or duplicate control metadata")
		}
		seen[control.ID] = true
		if (control.AssessmentMethod != "" && control.AssessmentMethod != "evidence" && control.AssessmentMethod != "manual") || (control.Basis != "" && control.Basis != "legal_obligation" && control.Basis != "supporting_practice") || len(control.Remediation) > 1000 {
			return errors.New("invalid assessment method, control basis or remediation")
		}
		if !slices.Contains([]string{"info", "low", "medium", "high", "critical"}, control.Severity) {
			return errors.New("invalid control severity")
		}
		if control.AppliesWhen != nil {
			if err := validateExpression(*control.AppliesWhen, 1, &count); err != nil {
				return err
			}
		}
		if err := validateExpression(control.Requirement, 1, &count); err != nil {
			return err
		}
	}
	return nil
}

func validateWindow(start, end string) error {
	var from, to time.Time
	var err error
	if start != "" {
		from, err = time.Parse(time.RFC3339Nano, start)
		if err != nil {
			return errors.New("invalid effective or evidence timestamp")
		}
	}
	if end != "" {
		to, err = time.Parse(time.RFC3339Nano, end)
		if err != nil {
			return errors.New("invalid effective or evidence timestamp")
		}
	}
	if start != "" && end != "" && !to.After(from) {
		return errors.New("end timestamp must follow start timestamp")
	}
	return nil
}

func validateInput(input Input) error {
	if !identifier.MatchString(input.PackID) || !identifier.MatchString(input.PackVersion) || !identifier.MatchString(input.ProductID) || !identifier.MatchString(input.ProductVersion) || input.Facts == nil || len(input.Facts) > 160 {
		return errors.New("invalid evaluation identity or fact count")
	}
	for key, fact := range input.Facts {
		if !identifier.MatchString(key) || !identifier.MatchString(fact.EvidenceID) || !sourceOK(fact.Source) || fact.ObservedAt == "" {
			return errors.New("invalid fact provenance")
		}
		if _, err := scalar(fact.Value); err != nil {
			return err
		}
		if err := validateWindow(fact.ObservedAt, fact.ExpiresAt); err != nil {
			return err
		}
	}
	return nil
}

// ValidateInput checks evidence shape and bounds without running a rule pack.
func ValidateInput(input Input) error { return validateInput(input) }
