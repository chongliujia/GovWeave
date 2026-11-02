package gateway

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestEvidenceEncryptionOwnsBufferBeforePersistence(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "json"
		if stream {
			name = "sse"
		}
		t.Run(name, func(t *testing.T) {
			s, dir, c := evidenceFixture(t, "full")
			r := evidenceTestRecord(t, evidenceTestApp)
			original := []byte(`{"text":"synthetic immutable content"}`)
			input := EvidenceObjectInput{Kind: "upstream_output", MediaType: "application/json", Data: bytes.Clone(original)}
			if stream {
				r.Streaming = true
				frames := [][]byte{[]byte("data: {\"text\":\"synthetic immutable content\"}\n\n"), []byte("data: [DONE]\n\n")}
				original = bytes.Join(frames, nil)
				input = evidenceStreamFixtureInput(s, c, "upstream_output", frames, []string{"data", "done"})
			}
			source := input.Data
			if stream {
				source = input.Stream.Data
			}
			entered, gate := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var wg sync.WaitGroup
			release := func() { once.Do(func() { close(gate) }) }
			defer func() { release(); wg.Wait() }()
			s.writeEvidence = func(path string, sealed []byte) error {
				close(entered)
				<-gate
				return immutableEvidenceFile(path, sealed)
			}
			done := concurrentCapture(s, r, EvidencePayload{Config: c, Objects: []EvidenceObjectInput{input}, AuditCommitted: true}, &wg)
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("capture did not reach persistence")
			}
			if !bytes.Equal(source, original) {
				t.Fatal("in-place encryption modified caller plaintext")
			}
			// Persistence must own only sealed bytes, independently of the raw
			// source and SSE manifest by the time the filesystem is involved.
			clear(source)
			if stream {
				input.Stream.Metadata.Frames[0].Bytes = 999
			}
			release()
			result := awaitCapture(t, done)
			if result.err != nil {
				t.Fatal(result.err)
			}
			sealed, err := os.ReadFile(filepath.Join(dir, "evidence", result.summary.ID+".sealed"))
			if err != nil || bytes.Contains(sealed, []byte("synthetic immutable content")) {
				t.Fatal("unencrypted persisted content", err)
			}
			reopened, err := OpenEvidence(dir)
			if err != nil {
				t.Fatal(err)
			}
			content, err := reopened.Reveal(result.summary.ID, evidenceTestApp, result.summary.ID+":upstream_output", "raw", "validation", "buffer_test")
			if err != nil || content.Text != string(original) {
				t.Fatal("source mutation changed persisted content", err)
			}
		})
	}
}
