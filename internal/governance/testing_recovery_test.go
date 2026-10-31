package governance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestActiveInterruptedRecoveryAndDurableAdmission(t *testing.T) {
	var mode, calls atomic.Int32
	f, product, _ := activeFixture(t, contractProvider(&mode, &calls), nil)
	run := startTestRun(t, f.service.Tests, product.ID, "pre_deployment")
	f.service.Close()
	run.State, run.Status, run.FinishedAt, run.Evaluation = "running", "pending", "", nil
	run.Cases = []TestCaseResult{}
	data, _ := json.Marshal(run)
	if os.WriteFile(filepath.Join(f.dir, "test-runs", run.ID+".json"), data, 0600) != nil {
		t.Fatal("write running fixture")
	}
	count := calls.Load()
	reopened, err := Open(f.dir, f.gateway, f.evaluator)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.Tests.Get(run.ID)
	if err != nil || recovered.State != "interrupted" || recovered.Status != "inconclusive" || recovered.Evaluation != nil || calls.Load() != count {
		t.Fatal("interrupted test recovered as success or retried", err)
	}
	if _, err := reopened.Tests.Replay(run.ID); err == nil {
		t.Fatal("interrupted run replayed as a verdict")
	}
	reopened.Tests.mu.Lock()
	originalDir := reopened.Tests.dir
	reopened.Tests.dir = filepath.Join(t.TempDir(), "a-file")
	if os.WriteFile(reopened.Tests.dir, []byte("fixture"), 0600) != nil {
		t.Fatal("write failure fixture")
	}
	reopened.Tests.mu.Unlock()
	if _, err := reopened.Tests.Start(product.ID, "operation", "manual"); err == nil {
		t.Fatal("run admitted without durable evidence")
	}
	reopened.Tests.mu.Lock()
	reopened.Tests.dir = originalDir
	reopened.Tests.mu.Unlock()
	if calls.Load() != count {
		t.Fatal("persistence failure called provider")
	}
	if err := f.gateway.Audit.Close(); err != nil {
		t.Fatal(err)
	}
	auditFailure := startTestRun(t, reopened.Tests, product.ID, "operation")
	if auditFailure.Status != "inconclusive" || calls.Load() != count {
		t.Fatal("audit failure called provider or passed")
	}
}

func TestTestTimestampOrderingUsesTime(t *testing.T) {
	if !testStartedBefore("2026-01-01T00:00:00.1Z", "2026-01-01T00:00:00.12Z") {
		t.Fatal("fractional timestamp sorted lexically")
	}
}
