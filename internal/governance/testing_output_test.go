package governance

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"govweave/internal/compliance"
)

func TestOutputPolicyEditDuringActiveModelCallInvalidatesVerdict(t *testing.T) {
	entered, release := make(chan struct{}, 2), make(chan struct{})
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
	started, err := f.service.Tests.Start(product.ID, "pre_deployment", "manual")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("active test did not reach provider")
	}
	in := f.gateway.OutputPolicies.Snapshot().OutputPolicyInput
	in.Mode, in.Categories = "observe", []string{"email"}
	if _, err := f.gateway.OutputPolicies.Save(in, f.gateway.Store.Snapshot()); err != nil {
		t.Fatal(err)
	}
	close(release)
	run := waitTestRun(t, f.service.Tests, started.ID)
	if run.State != "error" || run.ErrorCode != "test_source_changed" || run.Status != "inconclusive" || run.Evaluation != nil {
		t.Fatal("output-policy change published a stale active-test verdict")
	}
	if string(run.Input.Facts["runtime.output_policy_revision"].Value) != "0" || len(run.Cases) != 1 || calls.Load() != 1 {
		t.Fatal("active run did not retain original revision or stop after the changed source")
	}
	if run.GatewayRevision != f.gateway.Store.Snapshot().Revision || run.PolicyRevision != f.gateway.Policies.Snapshot().Revision {
		t.Fatal("fixture unexpectedly changed model/request-policy configuration")
	}
}

func TestOutputPolicyEvidenceMustMatchForActiveComparisons(t *testing.T) {
	makeRun := func(value, source string) TestRun {
		facts := map[string]compliance.Fact{}
		if value != "" {
			facts["runtime.output_policy_revision"] = compliance.Fact{Value: json.RawMessage(value), Source: source}
		}
		return TestRun{RunnerVersion: TestRunnerVersion, Input: compliance.Input{Facts: facts}}
	}
	for _, tc := range []struct {
		name, left, right, source string
		want                      bool
	}{
		{"legacy pair", "", "", "runtime", true},
		{"same zero revision", "0", "0", "runtime", true},
		{"same revision", "7", "7", "runtime", true},
		{"different revisions", "7", "8", "runtime", false},
		{"legacy versus current", "", "0", "runtime", false},
		{"current versus legacy", "0", "", "runtime", false},
		{"null", "null", "null", "runtime", false},
		{"negative", "-1", "-1", "runtime", false},
		{"string", `"7"`, `"7"`, "runtime", false},
		{"fraction", "0.5", "0.5", "runtime", false},
		{"overflow", "18446744073709551616", "18446744073709551616", "runtime", false},
		{"declared evidence", "7", "7", "declared", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := comparableTestRuns(makeRun(tc.left, tc.source), makeRun(tc.right, tc.source)); got != tc.want {
				t.Fatal("incorrect cross-run output-policy evidence comparison", got)
			}
		})
	}
}
