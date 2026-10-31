package gateway

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func evidenceStreamFixtureInput(s *EvidenceStore, c EvidenceConfig, kind string, frames [][]byte, kinds []string) EvidenceObjectInput {
	metadata := EvidenceStream{Version: "sse-evidence-v1", Scope: "validated_frames", EndState: "incomplete_stream", Frames: []EvidenceStreamFrame{}}
	var data []byte
	h := s.newEvidenceFingerprint(evidenceTestApp)
	for i, frame := range frames {
		if i < MaxEvidenceStreamFrames {
			metadata.Frames = append(metadata.Frames, EvidenceStreamFrame{Sequence: i + 1, Offset: len(data), Bytes: len(frame), ElapsedMS: int64(i), Kind: kinds[i]})
		}
		metadata.DoneSeen = metadata.DoneSeen || kinds[i] == "done"
		h.Write(frame)
		data = append(data, frame...)
	}
	metadata.FrameCount = len(frames)
	metadata.FramesTruncated = len(frames) > MaxEvidenceStreamFrames
	if metadata.DoneSeen {
		metadata.EndState = "completed"
	}
	if kind == "released_output" {
		metadata.Scope = "write_attempted_frames"
		metadata.WrittenBytes = len(data)
	}
	input := EvidenceStreamInput{Metadata: metadata, Bytes: len(data), Fingerprint: hex.EncodeToString(h.Sum(nil))}
	if c.Mode == "full" && len(data) <= c.MaxContentBytes {
		input.Data = append([]byte{}, data...)
	}
	return EvidenceObjectInput{Kind: kind, MediaType: "text/event-stream", Stream: &input}
}

func captureEvidenceStream(t *testing.T, s *EvidenceStore, c EvidenceConfig, inputs ...EvidenceObjectInput) EvidenceSummary {
	t.Helper()
	record := evidenceTestRecord(t, evidenceTestApp)
	record.Streaming = true
	summary, err := s.Capture(record, EvidencePayload{Config: c, Objects: inputs, AuditCommitted: true, DeliveryState: "write_completed"})
	if err != nil {
		t.Fatal(err)
	}
	return summary
}

func TestEvidenceStreamExactEncryptedRestartAndManifest(t *testing.T) {
	s, dir, c := evidenceFixture(t, "full")
	frames := [][]byte{[]byte("data: {\"delta\":\"synthetic stream evidence secret\"}\r\n\r\n"), []byte("data: [DONE]\n\n"), []byte(": post-done comment\n\n")}
	kinds := []string{"data", "done", "other"}
	upstream := evidenceStreamFixtureInput(s, c, "upstream_output", frames, kinds)
	released := evidenceStreamFixtureInput(s, c, "released_output", frames, kinds)
	data := bytes.Join(frames, nil)
	if upstream.Stream.Fingerprint != s.fingerprint(evidenceTestApp, data) {
		t.Fatal("incremental fingerprint differs from existing application domain")
	}
	summary := captureEvidenceStream(t, s, c, upstream, released)
	upstream.Stream.Metadata.Frames[0].Bytes = 999
	upstream.Stream.Data[0] = 'X'
	sealed, err := os.ReadFile(filepath.Join(dir, "evidence", summary.ID+".sealed"))
	if err != nil || bytes.Contains(sealed, []byte("synthetic stream evidence secret")) {
		t.Fatal("stream content was not encrypted", err)
	}
	s, err = OpenEvidence(dir)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := s.Get(summary.ID, evidenceTestApp)
	if err != nil || len(bundle.Objects) != 2 || bundle.RetainedBytes != 2*len(data) {
		t.Fatal("stream restart lost evidence", err)
	}
	metadataJSON, _ := json.Marshal(bundle)
	if bytes.Contains(metadataJSON, []byte("synthetic stream evidence secret")) {
		t.Fatal("stream metadata exposed content")
	}
	for _, object := range bundle.Objects {
		if object.Stream == nil || object.Stream.Version != "sse-evidence-v1" || object.Stream.FrameCount != 3 || !object.Stream.DoneSeen || object.Stream.FramesTruncated || object.Bytes != len(data) || object.ContentState != "retained" || object.Stream.Frames[0].Bytes != len(frames[0]) {
			t.Fatal("stream manifest did not survive immutable capture", object)
		}
		if object.Kind == "upstream_output" && object.Stream.WrittenBytes != 0 || object.Kind == "released_output" && object.Stream.WrittenBytes != len(data) {
			t.Fatal("write-return byte semantics lost")
		}
		content, err := s.Reveal(summary.ID, evidenceTestApp, object.ID, "raw", "validation", "stream_test")
		if err != nil || content.Text != string(data) {
			t.Fatal("exact SSE framing was changed", err)
		}
	}
}

func TestEvidenceStreamRetentionModesAndEmptyStages(t *testing.T) {
	for _, mode := range []string{"metadata", "full"} {
		t.Run(mode, func(t *testing.T) {
			s, dir, c := evidenceFixture(t, mode)
			c.MaxContentBytes = 4096
			for _, size := range []int{0, 4096, 4097} {
				var frames [][]byte
				var kinds []string
				if size > 0 {
					frames, kinds = [][]byte{bytes.Repeat([]byte("s"), size)}, []string{"other"}
				}
				input := evidenceStreamFixtureInput(s, c, "upstream_output", frames, kinds)
				summary := captureEvidenceStream(t, s, c, input)
				bundle, err := s.Get(summary.ID, evidenceTestApp)
				if err != nil {
					t.Fatal(err)
				}
				object := bundle.Objects[0]
				want := "retained"
				if mode == "metadata" {
					want = "metadata_only"
				} else if size > c.MaxContentBytes {
					want = "omitted_size"
				}
				if object.ContentState != want || object.Bytes != size || object.Stream.FrameCount != len(frames) {
					t.Fatal("stream retention boundary lost", size, object)
				}
				content, err := s.Reveal(summary.ID, evidenceTestApp, object.ID, "raw", "validation", "stream_test")
				if want == "retained" {
					if err != nil || len(content.Text) != size {
						t.Fatal("retained stream not readable", err)
					}
				} else if !errors.Is(err, ErrEvidenceContentUnavailable) {
					t.Fatal("omitted stream body available", err)
				}
			}
			if _, err := OpenEvidence(dir); err != nil {
				t.Fatal("restart rejected bounded/empty stream", err)
			}
		})
	}
}

func TestEvidenceStreamTruncatedManifestAndLargeObservation(t *testing.T) {
	s, _, c := evidenceFixture(t, "metadata")
	frames, kinds := make([][]byte, 130), make([]string, 130)
	for i := range frames {
		frames[i], kinds[i] = []byte(": ping\n\n"), "other"
	}
	frames[129], kinds[129] = []byte("data: [DONE]\n\n"), "done"
	input := evidenceStreamFixtureInput(s, c, "released_output", frames, kinds)
	summary := captureEvidenceStream(t, s, c, input)
	bundle, err := s.Get(summary.ID, evidenceTestApp)
	if err != nil || len(bundle.Objects[0].Stream.Frames) != MaxEvidenceStreamFrames || !bundle.Objects[0].Stream.FramesTruncated || !bundle.Objects[0].Stream.DoneSeen {
		t.Fatal("bounded manifest lost tail facts", err)
	}
	large := evidenceStreamFixtureInput(s, c, "upstream_output", [][]byte{[]byte(": ping\n\n")}, []string{"other"})
	large.Stream.Bytes, large.Stream.Metadata.Frames[0].Bytes = maxStreamBytes, maxStreamBytes
	// Metadata capture receives the already computed HMAC, without allocating
	// the observed body. Its length can exceed the non-stream JSON limit.
	captureEvidenceStream(t, s, c, large)
	large.Stream.Bytes++
	large.Stream.Metadata.Frames[0].Bytes++
	r := evidenceTestRecord(t, evidenceTestApp)
	r.Streaming = true
	if _, err := s.Capture(r, EvidencePayload{Config: c, Objects: []EvidenceObjectInput{large}}); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatal("stream exceeded observation bound", err)
	}
}

func TestEvidenceStreamMalformedMetadataRejected(t *testing.T) {
	s, _, c := evidenceFixture(t, "full")
	mutations := map[string]func(*EvidenceObjectInput){
		"version":        func(i *EvidenceObjectInput) { i.Stream.Metadata.Version = "future" },
		"scope":          func(i *EvidenceObjectInput) { i.Stream.Metadata.Scope = "write_attempted_frames" },
		"end state":      func(i *EvidenceObjectInput) { i.Stream.Metadata.EndState = "provider secret" },
		"negative count": func(i *EvidenceObjectInput) { i.Stream.Metadata.FrameCount = -1 },
		"count":          func(i *EvidenceObjectInput) { i.Stream.Metadata.FrameCount++ },
		"truncated flag": func(i *EvidenceObjectInput) { i.Stream.Metadata.FramesTruncated = true },
		"too many frames": func(i *EvidenceObjectInput) {
			i.Stream.Metadata.Frames = append(i.Stream.Metadata.Frames, i.Stream.Metadata.Frames[0])
		},
		"sequence":            func(i *EvidenceObjectInput) { i.Stream.Metadata.Frames[0].Sequence = 0 },
		"offset":              func(i *EvidenceObjectInput) { i.Stream.Metadata.Frames[1].Offset++ },
		"frame bytes":         func(i *EvidenceObjectInput) { i.Stream.Metadata.Frames[0].Bytes = 0 },
		"negative elapsed":    func(i *EvidenceObjectInput) { i.Stream.Metadata.Frames[0].ElapsedMS = -1 },
		"elapsed regression":  func(i *EvidenceObjectInput) { i.Stream.Metadata.Frames[0].ElapsedMS = 20 },
		"frame kind":          func(i *EvidenceObjectInput) { i.Stream.Metadata.Frames[0].Kind = "unvalidated" },
		"missing done":        func(i *EvidenceObjectInput) { i.Stream.Metadata.DoneSeen = false },
		"false done":          func(i *EvidenceObjectInput) { i.Stream.Metadata.Frames[1].Kind = "other" },
		"duplicate done":      func(i *EvidenceObjectInput) { i.Stream.Metadata.Frames[0].Kind = "done" },
		"upstream written":    func(i *EvidenceObjectInput) { i.Stream.Metadata.WrittenBytes = 1 },
		"negative written":    func(i *EvidenceObjectInput) { i.Stream.Metadata.WrittenBytes = -1 },
		"bad fingerprint":     func(i *EvidenceObjectInput) { i.Stream.Fingerprint = strings.Repeat("z", 64) },
		"wrong fingerprint":   func(i *EvidenceObjectInput) { i.Stream.Fingerprint = strings.Repeat("0", 64) },
		"body length":         func(i *EvidenceObjectInput) { i.Stream.Data = append(i.Stream.Data, 'x') },
		"missing full body":   func(i *EvidenceObjectInput) { i.Stream.Data = nil },
		"negative bytes":      func(i *EvidenceObjectInput) { i.Stream.Bytes = -1 },
		"extra total bytes":   func(i *EvidenceObjectInput) { i.Stream.Bytes++ },
		"input kind":          func(i *EvidenceObjectInput) { i.Kind = "request" },
		"non SSE media":       func(i *EvidenceObjectInput) { i.MediaType = "application/json" },
		"mixed body":          func(i *EvidenceObjectInput) { i.Data = []byte{} },
		"mixed content state": func(i *EvidenceObjectInput) { i.ContentState = "streaming_not_captured" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			input := evidenceStreamFixtureInput(s, c, "upstream_output", [][]byte{[]byte("data: {}\n\n"), []byte("data: [DONE]\n\n")}, []string{"data", "done"})
			mutate(&input)
			r := evidenceTestRecord(t, evidenceTestApp)
			r.Streaming = true
			if _, err := s.Capture(r, EvidencePayload{Config: c, Objects: []EvidenceObjectInput{input}}); !errors.Is(err, ErrEvidenceInvalid) {
				t.Fatal("malformed stream accepted", err)
			}
		})
	}
	input := evidenceStreamFixtureInput(s, c, "upstream_output", nil, nil)
	if _, err := s.Capture(evidenceTestRecord(t, evidenceTestApp), EvidencePayload{Config: c, Objects: []EvidenceObjectInput{input}}); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatal("stream metadata accepted for nonstream record")
	}
}

func TestEvidenceStreamWriteFailuresEncodingAndLegacyRead(t *testing.T) {
	s, dir, c := evidenceFixture(t, "full")
	r := evidenceTestRecord(t, evidenceTestApp)
	r.Streaming = true
	input := evidenceStreamFixtureInput(s, c, "upstream_output", nil, nil)
	summary, err := s.Capture(r, EvidencePayload{Config: c, Objects: []EvidenceObjectInput{input}, DeliveryState: "stream_incomplete"})
	if err != nil {
		t.Fatal("incomplete stream delivery state rejected", err)
	}
	bundle, err := s.Get(summary.ID, evidenceTestApp)
	if err != nil || bundle.DeliveryState != "stream_incomplete" {
		t.Fatal("incomplete stream delivery state lost", err)
	}
	for _, end := range []string{"incomplete_stream", "invalid_upstream_stream", "upstream_error", "response_too_large", "upstream_timeout", "upstream_unreachable", "client_cancelled", "write_failed", "flush_failed"} {
		input := evidenceStreamFixtureInput(s, c, "released_output", [][]byte{[]byte("data: {}\n\n")}, []string{"data"})
		input.Stream.Metadata.EndState = end
		input.Stream.Metadata.WrittenBytes = 3
		captureEvidenceStream(t, s, c, input)
	}
	input = evidenceStreamFixtureInput(s, c, "released_output", [][]byte{[]byte("data: [DONE]\n\n")}, []string{"done"})
	input.Stream.Metadata.WrittenBytes--
	r = evidenceTestRecord(t, evidenceTestApp)
	r.Streaming = true
	if _, err := s.Capture(r, EvidencePayload{Config: c, Objects: []EvidenceObjectInput{input}}); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatal("completed stream falsely claimed full write")
	}
	input = evidenceStreamFixtureInput(s, c, "upstream_output", [][]byte{{0xff}}, []string{"other"})
	summary = captureEvidenceStream(t, s, c, input)
	bundle, _ = s.Get(summary.ID, evidenceTestApp)
	if bundle.Objects[0].ContentState != "unsupported_encoding" {
		t.Fatal("non UTF-8 stream was converted")
	}
	legacy := captureEvidenceStream(t, s, c, EvidenceObjectInput{Kind: "upstream_output", MediaType: "text/event-stream", ContentState: "streaming_not_captured"})
	s, err = OpenEvidence(dir)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = s.Get(legacy.ID, evidenceTestApp)
	if err != nil || bundle.Objects[0].Stream != nil || bundle.Objects[0].ContentState != "streaming_not_captured" {
		t.Fatal("legacy streaming gap evidence lost", err)
	}
}

func TestEvidenceStreamStorageRejectsContradictions(t *testing.T) {
	s, _, c := evidenceFixture(t, "full")
	c.MaxContentBytes = 4096
	full := evidenceStreamFixtureInput(s, c, "upstream_output", [][]byte{[]byte("data: {}\n\n"), []byte("data: [DONE]\n\n")}, []string{"data", "done"})
	summary := captureEvidenceStream(t, s, c, full)
	stored, _, err := s.read(summary.ID)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*storedEvidence){
		"frame offset":        func(e *storedEvidence) { e.Bundle.Objects[0].Stream.Frames[1].Offset++ },
		"legacy state":        func(e *storedEvidence) { e.Bundle.Objects[0].ContentState = "streaming_not_captured" },
		"metadata retained":   func(e *storedEvidence) { e.Bundle.Mode = "metadata" },
		"retained omitted":    func(e *storedEvidence) { e.Bundle.Objects[0].ContentState = "omitted_size" },
		"body missing":        func(e *storedEvidence) { delete(e.Content, e.Bundle.Objects[0].ID) },
		"nonstream record":    func(e *storedEvidence) { e.Bundle.Record.Streaming = false },
		"bad digest syntax":   func(e *storedEvidence) { e.Bundle.Objects[0].Fingerprint = "raw content" },
		"too many written":    func(e *storedEvidence) { e.Bundle.Objects[0].Stream.WrittenBytes = e.Bundle.Objects[0].Bytes + 1 },
		"incomplete manifest": func(e *storedEvidence) { e.Bundle.Objects[0].Stream.Frames = e.Bundle.Objects[0].Stream.Frames[:1] },
	} {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(stored)
			var copy storedEvidence
			if err := json.Unmarshal(data, &copy); err != nil {
				t.Fatal(err)
			}
			mutate(&copy)
			if validStoredEvidence(summary.ID, copy) {
				t.Fatal("contradictory stored stream accepted")
			}
		})
	}
	for _, mode := range []string{"metadata", "full"} {
		config := c
		config.Mode = mode
		input := evidenceStreamFixtureInput(s, config, "upstream_output", [][]byte{bytes.Repeat([]byte("x"), c.MaxContentBytes+1)}, []string{"other"})
		input.Stream.Data = []byte{}
		r := evidenceTestRecord(t, evidenceTestApp)
		r.Streaming = true
		if _, err := s.Capture(r, EvidencePayload{Config: config, Objects: []EvidenceObjectInput{input}}); !errors.Is(err, ErrEvidenceInvalid) {
			t.Fatal("body accepted after retention was disabled", mode, err)
		}
	}
}
