package gateway

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"govweave/internal/storage"
)

// BenchmarkEvidenceCapture measures the supplementary vault only. Payloads and
// committed call records are prepared before timing; it excludes detectors,
// ordinary audit writes, HTTP/model latency, capture hooks, and policy lookup.
// Run with -benchtime=20x: each case has a separate temporary vault and unique
// request IDs. Bounding this durable benchmark prevents capacity or disk growth
// from becoming the measured behavior. It is not a percentile/load benchmark.
func BenchmarkEvidenceCapture(b *testing.B) {
	for _, size := range []struct {
		name  string
		bytes int
	}{{"8KiB", 8 << 10}, {"near1MiB", (1 << 20) - (1 << 10)}} {
		for _, mode := range []string{"disabled", "metadata", "full"} {
			b.Run(size.name+"/"+mode, func(b *testing.B) {
				if b.N > 20 {
					b.Skip("bounded durable benchmark: use -benchtime=20x")
				}
				dir := b.TempDir()
				vault, err := OpenEvidence(dir)
				if err != nil {
					b.Fatal(err)
				}
				config := vault.Config()
				config.Mode, config.ApplicationIDs = mode, []string{evidenceTestApp}
				config.MaxContentBytes = MaxEvidenceObjectBytes
				config, err = vault.SaveConfig(config, Snapshot{Applications: []Application{{ID: evidenceTestApp}}}, "benchmark")
				if err != nil {
					b.Fatal(err)
				}
				payload := benchmarkEvidencePayload(b, config, size.bytes)
				records := benchmarkEvidenceRecords(b, dir)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					summary, err := vault.Capture(records[i], payload)
					if mode == "disabled" {
						if !errors.Is(err, ErrEvidenceDisabled) {
							b.Fatal("disabled capture unexpectedly persisted", err)
						}
					} else if err != nil || summary.ID != EvidenceID(records[i].RequestID) {
						b.Fatal("capture failed or returned wrong request", err)
					}
				}
				b.StopTimer()
				// Validate retention outside the measured region: a successful
				// fast result must not have silently omitted the larger objects.
				if mode == "disabled" {
					if len(vault.entries) != 0 {
						b.Fatal("disabled capture created records")
					}
					return
				}
				bundle, err := vault.Get(EvidenceID(records[b.N-1].RequestID), evidenceTestApp)
				if err != nil || len(bundle.Objects) != 4 || len(vault.entries) != b.N {
					b.Fatal("capture did not preserve distinct evidence records", err)
				}
				wantBytes, wantState := 0, "metadata_only"
				if mode == "full" {
					wantBytes, wantState = 4*size.bytes, "retained"
				}
				if bundle.RetainedBytes != wantBytes {
					b.Fatal("unexpected retained byte count", bundle.RetainedBytes)
				}
				for _, object := range bundle.Objects {
					if object.Bytes != size.bytes || object.ContentState != wantState {
						b.Fatal("unexpected object coverage", object.Kind, object.ContentState)
					}
				}
			})
		}
	}
}

func benchmarkEvidencePayload(b *testing.B, config EvidenceConfig, size int) EvidencePayload {
	b.Helper()
	jsonBytes := func(prefix, suffix string) []byte {
		data := []byte(prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix)
		if !json.Valid(data) || len(data) != size {
			b.Fatal("invalid synthetic benchmark payload")
		}
		return data
	}
	request := jsonBytes(`{"model":"synthetic-model","messages":[{"role":"user","content":"`, `"}]}`)
	forwarded := jsonBytes(`{"model":"synthetic-provider-model","messages":[{"role":"user","content":"`, `"}]}`)
	original := jsonBytes(`{"choices":[{"index":0,"message":{"role":"assistant","content":"`, `"},"finish_reason":"stop"}]}`)
	released := jsonBytes(`{"choices":[{"index":0,"message":{"role":"assistant","content":"`, `"},"finish_reason":"stop"}]}`)
	payload := EvidencePayload{Config: config, AuditCommitted: true, DeliveryState: "release_prepared", Objects: []EvidenceObjectInput{
		{Kind: "request", MediaType: "application/json", Data: request},
		{Kind: "upstream_request", MediaType: "application/json", Data: forwarded},
		{Kind: "upstream_output", MediaType: "application/json", Data: original},
		{Kind: "released_output", MediaType: "application/json", Data: released},
	}}
	input, output := defaultPolicy(), defaultOutputPolicy()
	inputJSON, err := json.Marshal(input)
	if err != nil {
		b.Fatal(err)
	}
	outputJSON, err := json.Marshal(output)
	if err != nil {
		b.Fatal(err)
	}
	payload.Policies = []EvidencePolicySnapshot{
		{Kind: "input", ID: input.ID, Revision: input.Revision, Snapshot: inputJSON},
		{Kind: "output", ID: output.ID, Revision: output.Revision, Snapshot: outputJSON},
	}
	return payload
}

func benchmarkEvidenceRecords(b *testing.B, dir string) []CallRecord {
	b.Helper()
	audit, err := OpenAudit(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer audit.Close()
	for i := 0; i < b.N; i++ {
		id, err := storage.ID("req_", 16)
		if err != nil {
			b.Fatal(err)
		}
		record := CallRecord{SchemaVersion: 1, RequestID: id, ApplicationID: evidenceTestApp,
			Operation: "chat.completions", StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Decision: "allow", Outcome: "completed", HTTPStatus: 200, UpstreamStatus: 200, UpstreamAttempted: true}
		if err := audit.Begin(record); err != nil {
			b.Fatal(err)
		}
		if err := audit.Finish(record); err != nil {
			b.Fatal(err)
		}
	}
	records := audit.View(b.N, evidenceTestApp).Records
	if len(records) != b.N {
		b.Fatal("missing committed benchmark records")
	}
	return records
}
