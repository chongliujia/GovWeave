package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"

	"govweave/internal/instruction"
)

const instructionReviewVersion = "exact-instruction-review-v1"

var reviewDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// InstructionReview grants only named instruction-rule exceptions for one
// operator-reviewed byte-exact document and the enclosing resource's app grants.
// It never replaces authorization or sensitive-output/credential checks.
type InstructionReview struct {
	Version         string   `json:"version"`
	DetectorVersion string   `json:"detector_version"`
	ContentSHA256   string   `json:"content_sha256"`
	RuleIDs         []string `json:"rule_ids"`
}

// Review evidence omits the input digest: the immutable tool snapshot identifies
// the operator setting without creating a runtime document fingerprint in audit.
type InstructionReviewEvidence struct {
	Version         string   `json:"version"`
	State           string   `json:"state"`
	ExemptedRuleIDs []string `json:"exempted_rule_ids"`
}

func cloneInstructionReview(r *InstructionReview) *InstructionReview {
	if r == nil {
		return nil
	}
	out := *r
	out.RuleIDs = slices.Clone(r.RuleIDs)
	return &out
}

func validateInstructionReview(r *InstructionReview, p *InstructionPolicy) error {
	if r == nil {
		return nil
	}
	invalid := errors.New("Instruction review requires exact-instruction-review-v1, the current instruction detector version, a lowercase SHA-256 digest and one to four unique rules from that detector.")
	if p == nil || r.DetectorVersion != p.Version || r.Version != instructionReviewVersion || !reviewDigest.MatchString(r.ContentSHA256) || len(r.RuleIDs) < 1 || len(r.RuleIDs) > 4 {
		return invalid
	}
	for i, rule := range r.RuleIDs {
		if !instruction.SupportedRule(p.Version, rule) || i > 0 && rule == r.RuleIDs[i-1] {
			return invalid
		}
	}
	return nil
}

func applyInstructionReview(a *InstructionAssessment, text string, r *InstructionReview) {
	if r == nil {
		return
	}
	a.Review = &InstructionReviewEvidence{Version: instructionReviewVersion, State: "unavailable", ExemptedRuleIDs: []string{}}
	if a.State == "unknown" {
		return
	}
	digest := sha256.Sum256([]byte(text))
	if hex.EncodeToString(digest[:]) != r.ContentSHA256 {
		a.Review.State = "mismatch"
		return
	}
	a.Review.State = "matched"
	for _, rule := range a.RuleIDs {
		if slices.Contains(r.RuleIDs, rule) {
			a.Review.ExemptedRuleIDs = append(a.Review.ExemptedRuleIDs, rule)
		}
	}
	if len(a.Review.ExemptedRuleIDs) == len(a.RuleIDs) {
		a.Decision = "allow"
	}
}
