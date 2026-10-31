package governance

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/gateway"
)

func TestActiveToolEditDuringModelCallInvalidatesVerdict(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var mode, calls atomic.Int32
	provider := contractProvider(&mode, &calls)
	f, product, _ := activeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
			provider.ServeHTTP(w, r)
		case <-r.Context().Done():
		}
	}), nil)
	input := gateway.ToolInput{Name: "Read", Alias: "read", Endpoint: "https://tool.example/read", Enabled: true,
		TimeoutSeconds: 1, OutputMode: "block", Resources: []gateway.ToolResource{{ID: "guide", Sensitivity: "internal", AllowedApplications: []string{f.app.ID}}}}
	tool, err := f.gateway.Tools.Save("", input)
	if err != nil {
		t.Fatal(err)
	}
	started, err := f.service.Tests.Start(product.ID, "pre_deployment", "manual")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("test did not reach provider")
	}
	input.Revision, input.OutputMode = tool.Revision, "observe"
	if _, err := f.gateway.Tools.Save(tool.ID, input); err != nil {
		t.Fatal(err)
	}
	close(release)
	run := waitTestRun(t, f.service.Tests, started.ID)
	if run.State != "error" || run.ErrorCode != "test_source_changed" || run.Status != "inconclusive" || run.Evaluation != nil {
		t.Fatal("tool configuration change published a stale verdict")
	}
	if string(run.Input.Facts["runtime.tools.revision"].Value) != "1" || len(run.Cases) != 1 || calls.Load() != 1 {
		t.Fatal("snapshot or stopped execution is inconsistent")
	}
	if run.GatewayRevision != f.gateway.Store.Snapshot().Revision || run.PolicyRevision != f.gateway.Policies.Snapshot().Revision {
		t.Fatal("fixture changed unrelated model configuration")
	}
}

func TestActiveComparisonsRequireSameToolEvidenceGeneration(t *testing.T) {
	makeRun := func(value, source string) TestRun {
		facts := map[string]compliance.Fact{}
		if value != "" {
			facts["runtime.tools.revision"] = compliance.Fact{Value: json.RawMessage(value), Source: source}
		}
		return TestRun{RunnerVersion: TestRunnerVersion, Input: compliance.Input{Facts: facts}}
	}
	for _, tc := range []struct {
		name, left, right, source string
		want                      bool
	}{
		{"legacy pair", "", "", "runtime", true},
		{"same tool revision", "1", "1", "runtime", true},
		{"different tool revisions", "1", "2", "runtime", false},
		{"legacy vs new zero", "", "0", "runtime", false},
		{"new zero vs legacy", "0", "", "runtime", false},
		{"null evidence", "null", "null", "runtime", false},
		{"negative evidence", "-1", "-1", "runtime", false},
		{"string evidence", `"1"`, `"1"`, "runtime", false},
		{"declared evidence", "1", "1", "declared", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := comparableTestRuns(makeRun(tc.left, tc.source), makeRun(tc.right, tc.source)); got != tc.want {
				t.Fatal("incorrect cross-run tool evidence comparison", got)
			}
		})
	}
}
