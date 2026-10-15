package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditRecoveryAndCapacityReservation(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	record := CallRecord{RequestID: "req_test", Operation: "chat.completions", Decision: "allow"}
	if err := a.Begin(record); err != nil {
		t.Fatal(err)
	}
	a.Close()
	a, err = OpenAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if view := a.View(10, ""); len(view.Records) != 1 || view.Records[0].Outcome != "incomplete" {
		t.Fatal("unfinished call misrepresented")
	}
	a.size = AuditMaxBytes - 2*maxAuditEventBytes
	record.RequestID = "req_capacity"
	if err := a.Begin(record); err != nil {
		t.Fatal(err)
	}
	if a.View(1, "").Available {
		t.Fatal("capacity not reserved")
	}
	if err := a.Begin(CallRecord{RequestID: "req_overflow"}); err == nil {
		t.Fatal("capacity overflow allowed")
	}
	record.Outcome = "completed"
	if err := a.Finish(record); err != nil {
		t.Fatal("terminal capacity not reserved", err)
	}
}

func TestAuditRefusesCorruptionAndWriteFailures(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "calls.jsonl"), []byte(`{"schema_version":1,"request_id":"req_a","phase":"started"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if a, err := OpenAudit(dir); err == nil {
		a.Close()
		t.Fatal("partial final line accepted")
	}
	dir = t.TempDir()
	a, err := OpenAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	a.file.Close()
	if err := a.Begin(CallRecord{RequestID: "req_fail"}); err == nil || a.View(1, "").Available {
		t.Fatal("write failure did not stop audit admission")
	}
}
