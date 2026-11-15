package governance

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"govweave/internal/gateway"
)

func createRemediation(t *testing.T, f fixture, product Product, control string) RemediationView {
	t.Helper()
	report, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	item, err := f.service.Remediations.Create(product.ID, RemediationCreate{ReportID: report.Summary.ID, ControlID: control, Owner: "Synthetic owner", Note: "Investigate configured control"})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func readyRemediation(t *testing.T, m *Remediations, item RemediationView) RemediationView {
	t.Helper()
	in := item.Current.RemediationInput
	in.Status = "ready_for_recheck"
	in.Note = "Applied the intended configuration; verify current evidence"
	updated, err := m.Update(item.ProductID, item.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func TestRemediationLifecycleEvidenceAndRestart(t *testing.T) {
	f := setup(t)
	product, _ := f.service.Save("", f.input())
	m := f.service.Remediations
	item := createRemediation(t, f, product, "CREDENTIAL-EGRESS")
	if _, err := m.Create(product.ID, RemediationCreate{ReportID: item.SourceReportID, ControlID: item.ControlID}); !errors.Is(err, ErrRemediationDuplicate) {
		t.Fatal("duplicate finding accepted")
	}
	if _, err := m.Get("other-product", item.ID); !errors.Is(err, gateway.ErrNotFound) {
		t.Fatal("cross-product access")
	}
	if _, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: 1}); !errors.Is(err, ErrRemediationState) {
		t.Fatal("unprepared verification")
	}
	forged := item.Current.RemediationInput
	forged.Status = "verified"
	if _, err := m.Update(product.ID, item.ID, forged); err == nil {
		t.Fatal("manual verification accepted")
	}
	item = readyRemediation(t, m, item)
	failed, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: item.Current.Revision})
	if err != nil || failed.Current.Status != "in_progress" || failed.Current.Verification.Result != "fail" {
		t.Fatal("failed control closed", err)
	}
	setMode(t, f, "block")
	item = readyRemediation(t, m, failed)
	verified, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: item.Current.Revision})
	if err != nil || verified.Current.Status != "verified" || verified.VerificationState != "current" {
		t.Fatal("current remediation did not verify", err)
	}
	if verified.Current.Verification.ReportID == item.SourceReportID {
		t.Fatal("source report reused as fresh evidence")
	}
	if _, err := m.Update(product.ID, item.ID, item.Current.RemediationInput); !errors.Is(err, gateway.ErrConflict) {
		t.Fatal("stale update accepted")
	}
	reopened, err := openRemediations(f.dir, f.service)
	if err != nil {
		t.Fatal("restart", err)
	}
	got, _ := reopened.Get(product.ID, item.ID)
	if !reflect.DeepEqual(verified, got) {
		t.Fatal("restart changed immutable history")
	}
	got.Events[0].Note = "mutated"
	got.Current.Verification.Result = "mutated"
	again, _ := reopened.Get(product.ID, item.ID)
	if again.Events[0].Note == "mutated" || again.Current.Verification.Result != "pass" {
		t.Fatal("shared mutable record")
	}
	setMode(t, f, "observe")
	stale, _ := m.Get(product.ID, item.ID)
	if stale.Current.Status != "verified" || stale.VerificationState != "stale" {
		t.Fatal("historical verification presented as current")
	}
	in := stale.Current.RemediationInput
	in.Status = "open"
	in.Note = "Reopened after a policy change"
	open, err := m.Update(product.ID, item.ID, in)
	if err != nil || open.Current.Verification != nil || len(open.Events) != len(verified.Events)+1 {
		t.Fatal("reopen lost history", err)
	}
	data, _ := os.ReadFile(m.path)
	info, _ := os.Stat(m.path)
	if info.Mode().Perm() != 0600 || strings.Contains(string(data), f.key) {
		t.Fatal("private record storage")
	}
}

func TestRemediationUnknownNotApplicableAndScopeCannotClose(t *testing.T) {
	f := setup(t)
	in := f.input()
	delete(in.Facts, "transparency.disclosure_verified")
	product, _ := f.service.Save("", in)
	m := f.service.Remediations
	item := readyRemediation(t, m, createRemediation(t, f, product, "AI-DISCLOSURE"))
	unknown, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: item.Current.Revision})
	if err != nil || unknown.Current.Status == "verified" || unknown.Current.Verification.Result != "unknown" {
		t.Fatal("unknown closed", err)
	}
	in.Revision = product.Revision
	fact := in.Facts["product.user_facing"]
	fact.Value = json.RawMessage("false")
	in.Facts["product.user_facing"] = fact
	product, _ = f.service.Save(product.ID, in)
	item = readyRemediation(t, m, unknown)
	na, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: item.Current.Revision})
	if err != nil || na.Current.Status == "verified" || na.Current.Verification.Result != "not_applicable" {
		t.Fatal("not-applicable closed", err)
	}
	other, _, _ := f.gateway.Store.SaveApplication("", gateway.ApplicationInput{Name: "Other scope", AllowedConnections: []string{f.connection.ID}})
	in.Revision = product.Revision
	in.ApplicationIDs = []string{other.ID}
	_, err = f.service.Save(product.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	item = readyRemediation(t, m, na)
	before := len(f.service.Archives.List(product.ID))
	if _, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: item.Current.Revision}); !errors.Is(err, ErrRemediationScope) {
		t.Fatal("changed scope closed", err)
	}
	if len(f.service.Archives.List(product.ID)) != before {
		t.Fatal("invalid scope consumed archive capacity")
	}
}

func TestRemediationConflictsCapacityAndFailedWrites(t *testing.T) {
	f := setup(t)
	product, _ := f.service.Save("", f.input())
	m := f.service.Remediations
	item := createRemediation(t, f, product, "CREDENTIAL-EGRESS")
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in := item.Current.RemediationInput
			in.Status = "in_progress"
			_, err := m.Update(product.ID, item.ID, in)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, gateway.ErrConflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("concurrent updates lost a revision")
	}
	item, _ = m.Get(product.ID, item.ID)
	path := m.path
	m.path = filepath.Join(t.TempDir(), "directory")
	os.Mkdir(m.path, 0700)
	if _, err := m.Update(product.ID, item.ID, item.Current.RemediationInput); !errors.Is(err, gateway.ErrPersistence) {
		t.Fatal("failed write accepted")
	}
	again, _ := m.Get(product.ID, item.ID)
	if !reflect.DeepEqual(item, again) {
		t.Fatal("failed write mutated history")
	}
	m.path = path
	for len(item.Events) < MaxRemediationEvents {
		var err error
		item, err = m.Update(product.ID, item.ID, item.Current.RemediationInput)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Update(product.ID, item.ID, item.Current.RemediationInput); !errors.Is(err, ErrRemediationCapacity) {
		t.Fatal("history limit bypassed")
	}
	data, _ := os.ReadFile(path)
	var state remediationState
	json.Unmarshal(data, &state)
	state.Items[0].Events[0].Status = "verified"
	altered, _ := json.Marshal(state)
	os.WriteFile(path, altered, 0600)
	if _, err := openRemediations(f.dir, f.service); err == nil {
		t.Fatal("corrupt history accepted")
	}
	os.WriteFile(path, data, 0600)
	os.Chmod(path, 0644)
	if _, err := openRemediations(f.dir, f.service); err == nil {
		t.Fatal("public record accepted")
	}
}

func TestRemediationCanBindExplicitFreshModelRetest(t *testing.T) {
	var mode, calls atomic.Int32
	f, product, _ := activeFixture(t, contractProvider(&mode, &calls), nil)
	in := product.ProductInput
	in.PackID = "demo-ai-governance"
	in.PackVersion = "1.0.0"
	product, _ = f.service.Save(product.ID, in)
	m := f.service.Remediations
	item := createRemediation(t, f, product, "CREDENTIAL-EGRESS")
	setMode(t, f, "block")
	old, err := f.service.Tests.Start(product.ID, "pre_deployment", "manual")
	if err != nil {
		t.Fatal(err)
	}
	waitTestRun(t, f.service.Tests, old.ID)
	item = readyRemediation(t, m, item)
	if _, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: item.Current.Revision, TestRunID: old.ID}); !errors.Is(err, ErrRemediationTest) {
		t.Fatal("pre-remediation test accepted")
	}
	mode.Store(1)
	failedStart, err := f.service.Tests.Start(product.ID, "pre_deployment", "manual")
	if err != nil {
		t.Fatal(err)
	}
	failedRun := waitTestRun(t, f.service.Tests, failedStart.ID)
	if failedRun.Status != "failed" {
		t.Fatal("expected failed synthetic retest")
	}
	failed, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: item.Current.Revision, TestRunID: failedRun.ID})
	if err != nil || failed.Current.Status != "in_progress" || failed.Current.Verification.ControlStatus != "pass" || failed.Current.Verification.Result != "fail" {
		t.Fatal("failed retest overruled by passing configuration", err)
	}
	mode.Store(0)
	item = readyRemediation(t, m, failed)
	started, err := f.service.Tests.Start(product.ID, "pre_deployment", "manual")
	if err != nil {
		t.Fatal(err)
	}
	run := waitTestRun(t, f.service.Tests, started.ID)
	if run.Status != "passed" {
		t.Fatal("fixture did not pass", run.Status)
	}
	before := calls.Load()
	verified, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: item.Current.Revision, TestRunID: run.ID})
	if err != nil || verified.Current.Status != "verified" || verified.Current.Verification.TestRunID != run.ID || verified.VerificationState != "current" {
		t.Fatal("model retest not bound", err)
	}
	if calls.Load() != before {
		t.Fatal("verification made an implicit model call")
	}
	if _, err := openRemediations(f.dir, f.service); err != nil {
		t.Fatal("retained test binding invalid", err)
	}
	path := filepath.Join(f.dir, "test-runs", run.ID+".json")
	os.WriteFile(path, []byte(`{}`), 0600)
	view, _ := m.Get(product.ID, item.ID)
	if view.VerificationState != "unavailable" {
		t.Fatal("corrupt test still current")
	}
}

func TestRemediationVerificationExpiresWithEvidence(t *testing.T) {
	f := setup(t)
	in := f.input()
	delete(in.Facts, "transparency.disclosure_verified")
	product, _ := f.service.Save("", in)
	m := f.service.Remediations
	item := createRemediation(t, f, product, "AI-DISCLOSURE")
	in.Revision = product.Revision
	fact := f.input().Facts["transparency.disclosure_verified"]
	deadline := time.Now().Add(time.Second)
	fact.ExpiresAt = deadline.UTC().Format(time.RFC3339Nano)
	in.Facts["transparency.disclosure_verified"] = fact
	f.service.Save(product.ID, in)
	item = readyRemediation(t, m, item)
	verified, err := m.Check(product.ID, item.ID, RemediationCheck{Revision: item.Current.Revision})
	if err != nil || verified.VerificationState != "current" {
		t.Fatal("fresh evidence did not verify", err)
	}
	time.Sleep(time.Until(deadline) + time.Millisecond)
	view, _ := m.Get(product.ID, item.ID)
	if view.VerificationState != "stale" {
		t.Fatal("expired evidence still current")
	}
}
