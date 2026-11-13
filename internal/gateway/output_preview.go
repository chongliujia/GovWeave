package gateway

import (
	"errors"
	"strings"
	"unicode/utf8"

	"govweave/internal/sensitive"
)

type OutputPreviewInput struct {
	Text            string   `json:"text"`
	DetectorVersion string   `json:"detector_version"`
	Mode            string   `json:"mode"`
	Categories      []string `json:"categories"`
	PublicEmails    []string `json:"public_emails,omitempty"`
}

type OutputPreview struct {
	PreviewOnly           bool               `json:"preview_only"`
	DetectorVersion       string             `json:"detector_version"`
	Mode                  string             `json:"mode"`
	State                 string             `json:"state"`
	Result                string             `json:"result"`
	Reason                string             `json:"reason"`
	MatchedCategories     []string           `json:"matched_categories"`
	MatchedRules          []string           `json:"matched_rules"`
	PublicEmailExceptions int                `json:"public_email_exceptions"`
	Redaction             *RedactionEvidence `json:"redaction,omitempty"`
	Output                *string            `json:"output,omitempty"`
}

func PreviewSensitiveOutput(input OutputPreviewInput) (OutputPreview, error) {
	if strings.TrimSpace(input.Text) == "" || len(input.Text) > sensitive.MaxBytes || !utf8.ValidString(input.Text) || strings.ContainsRune(input.Text, utf8.RuneError) {
		return OutputPreview{}, errors.New("Provide nonempty UTF-8 sample text of at most 8192 bytes, without replacement characters.")
	}
	settings, err := normalizeOutputPolicy(OutputPolicyInput{
		DetectorVersion: input.DetectorVersion, Mode: input.Mode,
		Categories: input.Categories, PublicEmails: input.PublicEmails,
	}, Snapshot{})
	if err != nil {
		return OutputPreview{}, err
	}
	preview := OutputPreview{
		PreviewOnly: true, DetectorVersion: settings.DetectorVersion, Mode: settings.Mode,
		State: "not_evaluated", Result: "disabled", Reason: "policy_disabled",
		MatchedCategories: []string{}, MatchedRules: []string{},
	}
	if settings.Mode == "disabled" {
		preview.Output = &input.Text
		return preview, nil
	}
	policy := OutputPolicySnapshot{OutputPolicyInput: settings, RedactionVersion: redactionVersion}
	detection := sensitive.Scan([]byte(input.Text), settings.DetectorVersion)
	assessment := assessOutputText(policy, "", input.Text, detection)
	output := input.Text
	if assessment.Result == "redact" {
		output, _ = applyOutputRedaction(input.Text, policy, detection, assessment)
	}
	preview.State, preview.Result, preview.Reason = assessment.State, assessment.Result, assessment.Reason
	preview.MatchedCategories, preview.MatchedRules = assessment.MatchedCategories, assessment.MatchedRules
	preview.PublicEmailExceptions, preview.Redaction = assessment.PublicEmailExceptions, assessment.Redaction
	if assessment.Result == "allow" || assessment.Result == "observe" || assessment.Result == "redacted" {
		preview.Output = &output
	}
	return preview, nil
}
