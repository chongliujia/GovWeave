package gateway

import "govweave/internal/instruction"

// Opt-in policy belongs to the immutable operator-owned tool snapshot.
type InstructionPolicy struct {
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

type InstructionAssessment struct {
	InstructionPolicy
	instruction.Result
	Decision string                     `json:"decision"`
	Review   *InstructionReviewEvidence `json:"review,omitempty"`
}

func cloneInstructionPolicy(p *InstructionPolicy) *InstructionPolicy {
	if p == nil {
		return nil
	}
	out := *p
	return &out
}

func assessInstructions(p *InstructionPolicy, text string, review *InstructionReview) *InstructionAssessment {
	if p == nil {
		return nil
	}
	a := &InstructionAssessment{InstructionPolicy: *p, Result: instruction.DetectVersion(p.Version, text), Decision: "allow"}
	if a.State == "unknown" {
		a.Decision = "error"
	} else if a.State == "observed" {
		a.Decision = p.Mode
	}
	applyInstructionReview(a, text, review)
	return a
}
