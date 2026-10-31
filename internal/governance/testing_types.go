package governance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"govweave/internal/compliance"
	"govweave/internal/config"
	"govweave/internal/leakage"
)

const TestRunnerVersion = "bounded-chat-tests-v4"
const toolTestRunnerVersion = "bounded-tool-tests-v1"
const canaryV2TestRunnerVersion = "bounded-chat-tests-v3"
const canaryV1TestRunnerVersion = "bounded-chat-tests-v2"
const legacyTestRunnerVersion = "bounded-chat-tests-v1"
const maxTestRunBytes = 512 << 10
const maxTestStorageBytes = 64 << 20
const MaxTestRuns = maxTestStorageBytes / maxTestRunBytes

var ErrTestBusy = errors.New("the test concurrency limit has been reached")
var ErrTestCapacity = errors.New("test storage capacity reached; existing evidence is retained")
var ErrTestTargetConflict = errors.New("a plan for this target kind already exists; update that plan")
var ErrTestUnavailable = errors.New("test evidence is unavailable or invalid")

type TestMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// TestCase is deliberately restricted to literal checks. Semantic claims need
// an independently validated detector or a human reviewer, not keywords.
type TestCase struct {
	ID         string        `json:"id"`
	Title      string        `json:"title"`
	Messages   []TestMessage `json:"messages,omitempty"`
	Check      string        `json:"check"`
	Expected   string        `json:"expected,omitempty"`
	Scope      string        `json:"scope"`
	Category   string        `json:"category,omitempty"`
	ResourceID string        `json:"resource_id,omitempty"`
}

type TestSuite struct {
	SchemaVersion int        `json:"schema_version"`
	ID            string     `json:"id"`
	Version       string     `json:"version"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Limitations   []string   `json:"limitations"`
	Cases         []TestCase `json:"cases"`
	TargetKind    string     `json:"target_kind,omitempty"`
}

type TestSuiteDescriptor struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Cases   int    `json:"cases"`
}

type TestPlanInput struct {
	Revision        uint64 `json:"revision"`
	ApplicationID   string `json:"application_id"`
	ModelAlias      string `json:"model_alias,omitempty"`
	TargetVersion   string `json:"target_version"`
	SuiteID         string `json:"suite_id"`
	SuiteVersion    string `json:"suite_version"`
	Context         string `json:"context"`
	ScheduleEnabled bool   `json:"schedule_enabled"`
	IntervalSeconds int    `json:"interval_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	MaxOutputTokens int    `json:"max_output_tokens,omitempty"`
	RetainResponses bool   `json:"retain_responses"`
	TargetKind      string `json:"target_kind,omitempty"`
	ToolAlias       string `json:"tool_alias,omitempty"`
}

type TestPlan struct {
	ProductID string `json:"product_id"`
	TestPlanInput
	NextRunAt string `json:"next_run_at,omitempty"`
	LastRunID string `json:"last_run_id,omitempty"`
	LastError string `json:"last_error,omitempty"`
	ID        string `json:"plan_id,omitempty"`
}

type TestCaseResult struct {
	CaseID          string               `json:"case_id"`
	Status          string               `json:"status"`
	Reason          string               `json:"reason"`
	RequestID       string               `json:"request_id,omitempty"`
	HTTPStatus      int                  `json:"http_status"`
	DurationMS      int64                `json:"duration_ms"`
	ResponseSHA256  string               `json:"response_sha256,omitempty"`
	ResponseBytes   int                  `json:"response_bytes"`
	Response        *string              `json:"response,omitempty"`
	SyntheticMarker string               `json:"synthetic_marker,omitempty"`
	Detection       *leakage.Result      `json:"detection,omitempty"`
	OutputCheck     *OutputCheckEvidence `json:"output_check,omitempty"`
}

type TestComparison struct {
	PreviousRunID string `json:"previous_run_id"`
	Regressions   int    `json:"regressions"`
	Recoveries    int    `json:"recoveries"`
}

type TestRun struct {
	SchemaVersion      int                    `json:"schema_version"`
	RunnerVersion      string                 `json:"runner_version"`
	ID                 string                 `json:"id"`
	Phase              string                 `json:"phase"`
	Trigger            string                 `json:"trigger"`
	State              string                 `json:"state"`
	Status             string                 `json:"status"`
	StartedAt          string                 `json:"started_at"`
	FinishedAt         string                 `json:"finished_at,omitempty"`
	Product            Product                `json:"product"`
	Plan               TestPlan               `json:"plan"`
	Suite              TestSuite              `json:"suite"`
	SuiteSHA256        string                 `json:"suite_sha256"`
	GatewayRevision    uint64                 `json:"gateway_revision"`
	PolicyRevision     uint64                 `json:"policy_revision"`
	ConnectionID       string                 `json:"connection_id"`
	ConnectionRevision uint64                 `json:"connection_revision"`
	Cases              []TestCaseResult       `json:"cases"`
	Comparison         *TestComparison        `json:"comparison,omitempty"`
	Input              compliance.Input       `json:"input"`
	RulePack           compliance.Pack        `json:"rule_pack"`
	Evaluation         *compliance.Evaluation `json:"evaluation,omitempty"`
	ErrorCode          string                 `json:"error_code,omitempty"`
	ToolID             string                 `json:"tool_id,omitempty"`
	ToolRevision       uint64                 `json:"tool_revision,omitempty"`
}

type TestRunSummary struct {
	ID        string `json:"id"`
	ProductID string `json:"product_id"`
	Phase     string `json:"phase"`
	State     string `json:"state"`
	Status    string `json:"status"`
	StartedAt string `json:"started_at"`
	SHA256    string `json:"sha256"`
	PlanID    string `json:"plan_id,omitempty"`
}

func digestJSON(value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func validateSuite(suite TestSuite) error {
	if suite.TargetKind != "" && suite.TargetKind != "read_tool" {
		return errors.New("unsupported suite target kind")
	}
	if suite.SchemaVersion != 1 || !identifier.MatchString(suite.ID) || !identifier.MatchString(suite.Version) || len(suite.Name) < 1 || len(suite.Name) > 160 || len(suite.Description) > 2000 || len(suite.Limitations) < 1 || len(suite.Limitations) > 16 || len(suite.Cases) < 1 || len(suite.Cases) > 16 {
		return errors.New("invalid test suite identity, limitations or case count")
	}
	for _, limitation := range suite.Limitations {
		if len(limitation) == 0 || len(limitation) > 1000 {
			return errors.New("invalid test limitation")
		}
	}
	seen := map[string]bool{}
	for _, item := range suite.Cases {
		if !identifier.MatchString(item.ID) || seen[item.ID] || len(item.Title) < 1 || len(item.Title) > 160 || len(item.Messages) > 8 || len(item.Expected) > 1024 {
			return errors.New("invalid or duplicate test case")
		}
		if suite.TargetKind == "read_tool" {
			if len(item.Messages) != 0 || !identifier.MatchString(item.ResourceID) || (!isOutputCheck(item) && item.Check != "tool_denied") {
				return errors.New("tool cases require a resource ID and an output or denial check, without messages")
			}
		} else if len(item.Messages) == 0 || item.ResourceID != "" || item.Check == "tool_denied" {
			return errors.New("model cases require messages and cannot select tool resources")
		}
		seen[item.ID] = true
		if !slices.Contains([]string{"equals", "contains", "not_contains", "json_valid", "manual", "credential_block", "canary_absent", "output_protected", "output_allowed", "tool_denied"}, item.Check) {
			return errors.New("unsupported test check")
		}
		if (item.Check == "credential_block" || isOutputCheck(item) || item.Check == "tool_denied") != (item.Scope == "gateway_control") || (item.Scope != "gateway_control" && item.Scope != "endpoint_output") {
			return errors.New("test check and measurement scope do not match")
		}
		if item.Check == "output_protected" {
			if !slices.Contains([]string{"credential", "email", "phone"}, item.Category) {
				return errors.New("output_protected requires a supported category")
			}
		} else if item.Category != "" {
			return errors.New("only output_protected accepts a category")
		}
		literal := slices.Contains([]string{"equals", "contains", "not_contains", "output_allowed"}, item.Check)
		if literal != (item.Expected != "") {
			return errors.New("literal checks require an expected value; other checks do not accept one")
		}
		size, placeholders := 0, 0
		userAfterMarker := false
		for _, message := range item.Messages {
			if !slices.Contains([]string{"system", "user", "assistant"}, message.Role) || len(message.Content) == 0 {
				return errors.New("invalid test message")
			}
			size += len(message.Content)
			if item.Check == "canary_absent" {
				count := strings.Count(message.Content, leakage.Placeholder)
				if count > 0 && message.Role != "system" {
					return errors.New("the synthetic canary placeholder must be in a system message")
				}
				placeholders += count
				if message.Role == "user" && placeholders > 0 {
					userAfterMarker = true
				}
			}
		}
		if item.Check == "canary_absent" {
			if placeholders != 1 || !userAfterMarker {
				return errors.New("canary_absent requires one system {{CANARY}} placeholder followed by a user message")
			}
			size += leakage.MarkerLength - len(leakage.Placeholder)
		}
		if size > 16<<10 {
			return errors.New("test messages exceed 16 KiB")
		}
	}
	return nil
}

func loadSuites(dir string) (map[string]TestSuite, error) {
	result := map[string]TestSuite{}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil || len(entries) > 32 {
		return nil, errors.New("invalid test suite directory")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var suite TestSuite
		if readPrivateJSON(filepath.Join(dir, entry.Name()), 64<<10, false, &suite) != nil || validateSuite(suite) != nil {
			return nil, errors.New("invalid test suite")
		}
		key := suite.ID + "/" + suite.Version
		if _, exists := result[key]; exists || len(result) >= 16 {
			return nil, errors.New("duplicate test suite or capacity exceeded")
		}
		result[key] = suite
	}
	return result, nil
}

func readPrivateJSON(path string, limit int64, private bool, out any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > limit || (private && info.Mode().Perm()&0077 != 0) {
		return ErrTestUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return ErrTestUnavailable
	}
	return config.DecodeStrict(bytes.NewReader(data), out)
}
