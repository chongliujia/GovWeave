package gateway

import (
	"strings"
	"testing"
	"time"
)

// BenchmarkEvidenceStreamFrames compares the local SSE observer with and
// without evidence hooks. It includes framing, JSON parsing, frame metadata,
// bounded retention and incremental HMACs, but excludes network, ordinary
// audit, vault encryption/fsync, model time and policy checks. Results are
// serial CPU/allocation measurements, not first-token latency or a load SLA.
func BenchmarkEvidenceStreamFrames(b *testing.B) {
	prefix, suffix := `data: {"choices":[{"delta":{"content":"`, "\"}}]}\n\n"
	frame := []byte(prefix + strings.Repeat("x", 1024-len(prefix)-len(suffix)) + suffix)
	for _, size := range []struct {
		name   string
		frames int
	}{{"32KiB", 32}, {"1MiB", 1024}} {
		for _, mode := range []string{"disabled", "metadata", "full"} {
			b.Run(size.name+"/"+mode, func(b *testing.B) {
				engine := &Engine{Evidence: &EvidenceStore{fingerprintKey: []byte("synthetic-benchmark-evidence-key")}}
				b.SetBytes(int64(size.frames*len(frame) + len(done)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var call *callEvidence
					if mode != "disabled" {
						call = &callEvidence{applicationID: evidenceTestApp, payload: EvidencePayload{
							Config:  EvidenceConfig{Mode: mode, MaxContentBytes: 64 << 10},
							Objects: []EvidenceObjectInput{{Kind: "upstream_output"}, {Kind: "released_output"}},
						}}
					}
					capture := engine.beginStreamEvidence(call, time.Now())
					observer := streamObserver{}
					if capture != nil {
						observer.accepted = capture.accepted
					}
					for j := 0; j <= size.frames; j++ {
						data := frame
						if j == size.frames {
							data = []byte(done)
						}
						if err := observer.observe(data); err != nil {
							b.Fatal(err)
						}
						ready := observer.take()
						capture.attempt(ready)
						capture.written(len(ready), len(ready))
					}
					capture.finish("completed")
					if capture != nil && (capture.upstream.input.Metadata.FrameCount != size.frames+1 || !capture.released.input.Metadata.DoneSeen) {
						b.Fatal("stream evidence hooks did not observe every fixture frame")
					}
				}
			})
		}
	}
}
