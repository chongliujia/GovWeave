package governance

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"govweave/internal/leakage"
)

func historicalCanaryRun(t *testing.T) (TestRun, []byte) {
	t.Helper()
	// Copied byte-for-byte from the prior local synthetic integration run's
	// dist/canary-integration/20261028-first/exposed.json, not regenerated.
	data, err := os.ReadFile("../../tests/testdata/canary-history-v1-exposed.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "b22d50c8c7e257811b8453a0f6434870d477814dd6e11be1c48f01a5155c6962" {
		t.Fatal("historical fixture bytes changed", got)
	}
	var run TestRun
	if err := json.Unmarshal(data, &run); err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		t.Fatal(err)
	}
	if got, original := digestJSON(run), fmt.Sprintf("%x", sha256.Sum256(compact.Bytes())); got != original {
		t.Fatal("decoding historical evidence changed its content hash", got, original)
	}
	if run.RunnerVersion != canaryV1TestRunnerVersion || validateRun(run) != nil {
		t.Fatal("historical runner v2 evidence rejected")
	}
	for _, result := range run.Cases {
		if result.Detection == nil || result.Detection.Version != leakage.VersionV1 {
			t.Fatal("fixture does not contain historical detector results")
		}
	}
	return run, data
}

func cloneCanaryCase(t *testing.T, result TestCaseResult) TestCaseResult {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var cloned TestCaseResult
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestHistoricalCanaryReadRestartReplayPreservesEvidence(t *testing.T) {
	for _, retain := range []bool{true, false} {
		t.Run(fmt.Sprintf("retain_responses=%t", retain), func(t *testing.T) {
			run, original := historicalCanaryRun(t)
			if !retain {
				run.Plan.RetainResponses = false
				for i := range run.Cases {
					run.Cases[i].Response = nil
				}
				var err error
				original, err = json.Marshal(run)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := validateRun(run); err != nil {
				t.Fatal("historical evidence variant rejected", err)
			}
			before := summarizeTestRun(run).SHA256
			f := setup(t)
			f.service.Close()
			dir := filepath.Join(f.dir, "test-runs")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, run.ID+".json")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			// Both opens must index the existing run without rewriting it. The
			// replay uses only the retained input/pack, without an inference call.
			for restart := 0; restart < 2; restart++ {
				reopened, err := Open(f.dir, f.gateway, f.evaluator)
				if err != nil {
					t.Fatal("historical canary evidence prevented startup", err)
				}
				t.Cleanup(reopened.Close)
				got, err := reopened.Tests.Get(run.ID)
				if err != nil || !reflect.DeepEqual(got, run) || summarizeTestRun(got).SHA256 != before {
					t.Fatal("historical evidence changed on read/restart", err)
				}
				replay, err := reopened.Tests.Replay(run.ID)
				if err != nil || !replay.Matches {
					t.Fatal("historical rule replay changed", err)
				}
				reopened.Close()
				stored, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(stored, original) {
					t.Fatal("read/restart/replay rewrote historical evidence", err)
				}
			}
		})
	}
}

func canaryEvidenceFor(t *testing.T, template TestCaseResult, version, response string) TestCaseResult {
	t.Helper()
	result := cloneCanaryCase(t, template)
	result.Response = &response
	result.ResponseBytes = len(response)
	result.ResponseSHA256 = responseDigest(response)
	detection, err := leakage.DetectVersion(version, result.SyntheticMarker, []byte(response))
	if err != nil {
		t.Fatal(err)
	}
	result.Detection = &detection
	result.Status, result.Reason = canaryStatus(detection.State)
	return result
}

func TestCanaryRunnerDetectorVersionBinding(t *testing.T) {
	run, _ := historicalCanaryRun(t)
	for _, edit := range []func(*TestRun){
		func(r *TestRun) { r.RunnerVersion = TestRunnerVersion },
		func(r *TestRun) { r.RunnerVersion = legacyTestRunnerVersion },
		func(r *TestRun) { r.RunnerVersion = "bounded-chat-tests-v999" },
	} {
		copy := run
		edit(&copy)
		if validateRun(copy) == nil {
			t.Fatal("mismatched or unsupported runner accepted historical canary results")
		}
	}
	marker := run.Cases[0].SyntheticMarker
	response := reverseCanaryASCII(marker)
	old := canaryEvidenceFor(t, run.Cases[0], leakage.VersionV1, response)
	current := canaryEvidenceFor(t, run.Cases[0], leakage.Version, response)
	if old.Detection.State != "not_observed" || current.Detection.State != "observed" {
		t.Fatal("test does not distinguish the historical and current matching semantics")
	}
	if err := validateCanaryCase(run.Suite.Cases[0], old, canaryV1TestRunnerVersion); err != nil {
		t.Fatal("historical retained text was checked under current matching semantics", err)
	}
	if err := validateCanaryCase(run.Suite.Cases[0], current, TestRunnerVersion); err != nil {
		t.Fatal("current runner rejected its detector result", err)
	}
	for _, pair := range []struct {
		runner string
		result TestCaseResult
	}{
		{TestRunnerVersion, old}, {canaryV1TestRunnerVersion, current},
	} {
		if validateCanaryCase(run.Suite.Cases[0], pair.result, pair.runner) == nil {
			t.Fatal("runner accepted another detector generation")
		}
	}
	for _, version := range []string{legacyTestRunnerVersion, canaryV1TestRunnerVersion, TestRunnerVersion} {
		left, right := run, run
		left.RunnerVersion, right.RunnerVersion = version, version
		if !comparableTestRuns(left, right) {
			t.Fatal("same-version baseline rejected")
		}
		for _, other := range []string{legacyTestRunnerVersion, canaryV1TestRunnerVersion, TestRunnerVersion} {
			right.RunnerVersion = other
			if version != other && comparableTestRuns(left, right) {
				t.Fatal("different runner versions shared a baseline")
			}
		}
	}
}

func reverseCanaryASCII(value string) string {
	data := []byte(value)
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	return string(data)
}

func TestCanaryMetadataVersionedTransformAndSpanValidation(t *testing.T) {
	run, _ := historicalCanaryRun(t)
	marker := run.Cases[0].SyntheticMarker
	b64 := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	var decimal, chunks []string
	for _, c := range []byte(marker) {
		decimal = append(decimal, strconv.Itoa(int(c)))
	}
	for at := 0; at < len(marker); at += 4 {
		chunks = append(chunks, b64(marker[at:min(at+4, len(marker))]))
	}
	rot13 := func(value string) string {
		return strings.Map(func(c rune) rune {
			if c >= 'A' && c <= 'Z' {
				return 'A' + (c-'A'+13)%26
			}
			if c >= 'a' && c <= 'z' {
				return 'a' + (c-'a'+13)%26
			}
			return c
		}, value)
	}
	type validEvidence struct {
		runner string
		result TestCaseResult
	}
	valid := map[string]validEvidence{}
	for _, item := range []struct {
		name, version, runner, response, representation string
	}{
		{"v1-exact", leakage.VersionV1, canaryV1TestRunnerVersion, marker, "exact"},
		{"v1-normalized", leakage.VersionV1, canaryV1TestRunnerVersion, strings.ToLower(marker), "normalized"},
		{"v1-base64", leakage.VersionV1, canaryV1TestRunnerVersion, b64(marker), "base64"},
		{"v2-exact", leakage.Version, TestRunnerVersion, marker, "exact"},
		{"v2-normalized", leakage.Version, TestRunnerVersion, strings.ToLower(marker), "normalized"},
		{"v2-base64-normalized", leakage.Version, TestRunnerVersion, b64(strings.ToLower(marker)), "base64"},
		{"v2-reversed", leakage.Version, TestRunnerVersion, reverseCanaryASCII(marker), "reversed"},
		{"v2-rot13", leakage.Version, TestRunnerVersion, rot13(marker), "rot13"},
		{"v2-decimal", leakage.Version, TestRunnerVersion, strings.Join(decimal, ","), "decimal"},
		{"v2-base64-chunks", leakage.Version, TestRunnerVersion, strings.Join(chunks, " "), "base64_chunks"},
		{"v2-composed-encoded", leakage.Version, TestRunnerVersion, b64(hex.EncodeToString([]byte(marker))), "composed"},
		{"v2-composed-transformed", leakage.Version, TestRunnerVersion, reverseCanaryASCII(b64(marker)), "composed"},
	} {
		result := canaryEvidenceFor(t, run.Cases[0], item.version, item.response)
		if result.Detection.State != "observed" || result.Detection.Matches[0].Representation != item.representation {
			t.Fatalf("invalid test construction %s: %+v", item.name, result.Detection)
		}
		result.Response = nil
		if err := validateCanaryCase(run.Suite.Cases[0], result, item.runner); err != nil {
			t.Fatal("valid metadata rejected", item.name, err)
		}
		valid[item.name] = validEvidence{item.runner, result}
	}
	for _, item := range []struct {
		name, source string
		edit         func(*TestCaseResult)
	}{
		{"legacy-transformations", "v1-base64", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations = []string{"base64"} }},
		{"legacy-empty-transformations", "v1-base64", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations = []string{} }},
		{"legacy-normalized-field", "v1-base64", func(r *TestCaseResult) { r.Detection.Matches[0].Normalized = true }},
		{"legacy-new-representation", "v1-base64", func(r *TestCaseResult) { r.Detection.Matches[0].Representation = "decimal" }},
		{"legacy-encoded-raw-scope", "v1-base64", func(r *TestCaseResult) { r.Detection.Matches[0].SpanScope = "raw_fragment" }},
		{"legacy-normalized-encoded-scope", "v1-normalized", func(r *TestCaseResult) { r.Detection.Matches[0].SpanScope = "encoded_candidate" }},
		{"raw-normalized-field", "v2-exact", func(r *TestCaseResult) { r.Detection.Matches[0].Normalized = true }},
		{"raw-transformations", "v2-normalized", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations = []string{"rot13"} }},
		{"raw-encoded-scope", "v2-exact", func(r *TestCaseResult) { r.Detection.Matches[0].SpanScope = "encoded_candidate" }},
		{"exact-short-span", "v2-exact", func(r *TestCaseResult) { r.Detection.Matches[0].EndByte-- }},
		{"negative-span", "v2-exact", func(r *TestCaseResult) { r.Detection.Matches[0].StartByte = -1 }},
		{"empty-span", "v2-exact", func(r *TestCaseResult) { r.Detection.Matches[0].EndByte = 0 }},
		{"oversized-span", "v2-exact", func(r *TestCaseResult) { r.Detection.Matches[0].EndByte++ }},
		{"encoded-transformed-scope", "v2-decimal", func(r *TestCaseResult) { r.Detection.Matches[0].SpanScope = "transformed_region" }},
		{"single-wrong-path", "v2-decimal", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations = []string{"hex"} }},
		{"single-multiple-path", "v2-decimal", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations = []string{"decimal", "hex"} }},
		{"transformed-encoded-scope", "v2-reversed", func(r *TestCaseResult) { r.Detection.Matches[0].SpanScope = "encoded_candidate" }},
		{"transformed-partial-region", "v2-rot13", func(r *TestCaseResult) { r.Detection.Matches[0].StartByte++ }},
		{"composed-no-path", "v2-composed-encoded", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations = nil }},
		{"composed-single-path", "v2-composed-encoded", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations = []string{"base64"} }},
		{"composed-third-layer", "v2-composed-encoded", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations = []string{"base64", "hex", "rot13"} }},
		{"composed-unknown-method", "v2-composed-encoded", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations[1] = "future" }},
		{"composed-raw-method", "v2-composed-encoded", func(r *TestCaseResult) { r.Detection.Matches[0].Transformations[1] = "exact" }},
		{"composed-encoded-wrong-scope", "v2-composed-encoded", func(r *TestCaseResult) { r.Detection.Matches[0].SpanScope = "transformed_region" }},
		{"composed-transformed-wrong-scope", "v2-composed-transformed", func(r *TestCaseResult) { r.Detection.Matches[0].SpanScope = "encoded_candidate" }},
		{"composed-partial-transformed-region", "v2-composed-transformed", func(r *TestCaseResult) { r.Detection.Matches[0].EndByte-- }},
		{"unknown-representation", "v2-exact", func(r *TestCaseResult) { r.Detection.Matches[0].Representation = "future" }},
		{"unknown-detector", "v2-exact", func(r *TestCaseResult) { r.Detection.Version = "synthetic-canary-v999" }},
		{"incomplete-scan", "v2-exact", func(r *TestCaseResult) { r.Detection.ScannedBytes-- }},
		{"observed-without-match", "v2-exact", func(r *TestCaseResult) { r.Detection.Matches = nil }},
		{"unknown-with-match", "v2-exact", func(r *TestCaseResult) {
			r.Detection.State, r.Detection.Reason = "unknown", "scan_budget_exceeded"
			r.Status, r.Reason = canaryStatus("unknown")
		}},
		{"unknown-reason", "v2-exact", func(r *TestCaseResult) {
			r.Detection.State, r.Detection.Reason, r.Detection.Matches = "unknown", "future", nil
			r.Status, r.Reason = canaryStatus("unknown")
		}},
	} {
		t.Run(item.name, func(t *testing.T) {
			source := valid[item.source]
			result := cloneCanaryCase(t, source.result)
			item.edit(&result)
			if validateCanaryCase(run.Suite.Cases[0], result, source.runner) == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}
