package governance

import (
	"sync/atomic"
	"testing"
)

func TestLifecycleEvidenceInProductReports(t *testing.T) {
	var mode, calls atomic.Int32
	f, product, _ := activeFixture(t, contractProvider(&mode, &calls), nil)
	status := func(id, want string) {
		t.Helper()
		report, err := f.service.Refresh(product.ID)
		if err != nil || report.Evaluation == nil {
			t.Fatal("missing product evaluation", err)
		}
		for _, control := range report.Evaluation.Controls {
			if control.ID == id {
				if control.Status != want {
					t.Fatalf("%s: want %s, got %s", id, want, control.Status)
				}
				return
			}
		}
		t.Fatal("missing control", id)
	}
	status("NIST-OPERATION-TEST", "unknown")
	startTestRun(t, f.service.Tests, product.ID, "pre_deployment")
	status("NIST-PREDEPLOYMENT-TEST", "pass")
	startTestRun(t, f.service.Tests, product.ID, "operation")
	status("NIST-OPERATION-TEST", "pass")
	status("NIST-TEST-RECORD", "pass")
	status("NIST-CONTEXT-REVIEW", "unknown")
	archive, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	mode.Store(1)
	startTestRun(t, f.service.Tests, product.ID, "operation")
	status("NIST-OPERATION-TEST", "fail")
	mode.Store(2)
	startTestRun(t, f.service.Tests, product.ID, "operation")
	status("NIST-OPERATION-TEST", "unknown")
	mode.Store(0)
	startTestRun(t, f.service.Tests, product.ID, "operation")
	status("NIST-OPERATION-TEST", "pass")
	count := calls.Load()
	replay, err := f.service.Archives.Replay(archive.Summary.ID)
	if err != nil || !replay.Matches || count != calls.Load() {
		t.Fatal("snapshot replay changed or called model", err)
	}
}
