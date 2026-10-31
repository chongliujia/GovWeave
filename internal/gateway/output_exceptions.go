package gateway

import (
	"govweave/internal/sensitive"
	"slices"
)

// An exact operator-declared public email is a disclosure permission, not a
// detector correction. Never exempt credentials, normalized/encoded spellings,
// incomplete scans, tool arguments or other addresses on the same domain.
// V3 additionally recognizes whole addresses inside bounded paired markup.
func publicEmailException(p OutputPolicySnapshot, text string, r sensitive.Result, f sensitive.Finding) bool {
	raw := f.RuleID == "email_address"
	formatted := p.DetectorVersion == sensitive.Version3 && r.DetectorVersion == sensitive.Version3 && f.RuleID == "formatted_email_address"
	return r.State != "unknown" && !r.Truncated && r.InputBytes == len(text) &&
		f.Category == "email" && (raw || formatted) && f.StartByte >= 0 && f.EndByte > f.StartByte && f.EndByte <= len(text) &&
		slices.Contains(p.PublicEmails, text[f.StartByte:f.EndByte])
}

func assessOutputText(p OutputPolicySnapshot, appID, text string, r sensitive.Result) *OutputAssessment {
	filtered := r
	filtered.Findings = nil
	exempted := 0
	for _, f := range r.Findings {
		if p.Applies(appID) && slices.Contains(p.Categories, "email") && publicEmailException(p, text, r, f) {
			exempted++
			continue
		}
		filtered.Findings = append(filtered.Findings, f)
	}
	a := assessOutput(p, appID, filtered)
	a.PublicEmailExceptions = exempted
	return a
}
