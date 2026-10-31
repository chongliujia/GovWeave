package gateway

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
)

var integrationModelAlias = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,99}$`)

type IntegrationPolicyCheck struct {
	Mode     string `json:"mode"`
	Applies  bool   `json:"applies"`
	Revision uint64 `json:"revision"`
}

type IntegrationChecks struct {
	ModelAccess    string                 `json:"model_access"`
	AuditAvailable bool                   `json:"audit_available"`
	InputPolicy    IntegrationPolicyCheck `json:"input_policy"`
	OutputPolicy   IntegrationPolicyCheck `json:"output_policy"`
}

type IntegrationSupported struct {
	ChatCompletions                           bool `json:"chat_completions"`
	Streaming                                 bool `json:"streaming"`
	ToolGovernanceRequiresSeparateIntegration bool `json:"tool_governance_requires_separate_integration"`
}

// IntegrationCheckView describes local settings at inspection time. It neither
// reserves admission nor proves inference, policy effectiveness or compliance.
// Every subsequent model or tool call performs its own authorization and checks.
type IntegrationCheckView struct {
	SchemaVersion         int                  `json:"schema_version"`
	ApplicationID         string               `json:"application_id"`
	Model                 string               `json:"model"`
	ConfigurationRevision uint64               `json:"configuration_revision"`
	Checks                IntegrationChecks    `json:"checks"`
	Supported             IntegrationSupported `json:"supported"`
	UpstreamContacted     bool                 `json:"upstream_contacted"`
	Inference             string               `json:"inference"`
}

// Available reports the same capacity gate used by Begin without copying
// request records, reserving space or writing an audit event.
func (a *Audit) Available() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.failed && a.size+a.reserved+2*maxAuditEventBytes <= AuditMaxBytes
}

// IntegrationCheck is an application-key-only local configuration inspection.
// It makes no provider request and does not create inference/audit evidence.
func (g *Engine) IntegrationCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if len(r.Header.Values("Authorization")) != 1 {
		failure(w, http.StatusUnauthorized, "invalid_api_key", "")
		return
	}
	header := r.Header.Get("Authorization")
	app, _, err := g.Store.Authenticate(header)
	if err != nil {
		failure(w, http.StatusUnauthorized, "invalid_api_key", "")
		return
	}
	if len(r.URL.RawQuery) > 512 {
		failure(w, http.StatusBadRequest, "invalid_integration_query", "")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["model"]) != 1 || !integrationModelAlias.MatchString(query.Get("model")) {
		failure(w, http.StatusBadRequest, "invalid_integration_query", "")
		return
	}
	resolved, err := g.Store.Resolve(header, query.Get("model"))
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidKey):
			failure(w, http.StatusUnauthorized, "invalid_api_key", "")
		case errors.Is(err, ErrDenied):
			failure(w, http.StatusForbidden, "model_not_allowed", "")
		case errors.Is(err, ErrDisabled):
			failure(w, http.StatusForbidden, "connection_disabled", "")
		default:
			failure(w, http.StatusServiceUnavailable, "credential_unavailable", "")
		}
		return
	}
	input := g.Policies.Snapshot()
	output := g.OutputPolicies.Snapshot()
	inputApplies := input.Mode != "disabled" &&
		(len(input.ApplicationIDs) == 0 || slices.Contains(input.ApplicationIDs, app.ID)) &&
		(len(input.ConnectionIDs) == 0 || slices.Contains(input.ConnectionIDs, resolved.Connection.ID))
	outputApplies := output.Applies(app.ID)
	view := IntegrationCheckView{
		SchemaVersion: 1, ApplicationID: app.ID, Model: resolved.Connection.Alias,
		ConfigurationRevision: resolved.PolicyRevision,
		Checks: IntegrationChecks{
			ModelAccess: "allowed", AuditAvailable: g.Audit.Available(),
			InputPolicy:  IntegrationPolicyCheck{Mode: input.Mode, Applies: inputApplies, Revision: input.Revision},
			OutputPolicy: IntegrationPolicyCheck{Mode: output.Mode, Applies: outputApplies, Revision: output.Revision},
		},
		Supported:         IntegrationSupported{ChatCompletions: true, Streaming: !outputApplies, ToolGovernanceRequiresSeparateIntegration: true},
		UpstreamContacted: false, Inference: "not_tested",
	}
	current, _, err := g.Store.Authenticate(header)
	if err != nil || current.ID != app.ID || resolved.Application.ID != app.ID {
		failure(w, http.StatusUnauthorized, "invalid_api_key", "")
		return
	}
	respond(w, http.StatusOK, view)
}
