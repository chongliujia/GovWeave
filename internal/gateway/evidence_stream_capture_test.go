package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

type streamReadFailure struct{ err error }

func (r streamReadFailure) Read([]byte) (int, error) { return 0, r.err }

type streamTimeout struct{}

func (streamTimeout) Error() string   { return "private upstream timeout" }
func (streamTimeout) Timeout() bool   { return true }
func (streamTimeout) Temporary() bool { return false }

type streamCancelReader struct{ cancel context.CancelFunc }

func (r streamCancelReader) Read([]byte) (int, error) {
	r.cancel()
	return 0, context.Canceled
}

type streamGateReader struct {
	gate   <-chan struct{}
	reader io.Reader
}

func (r *streamGateReader) Read(p []byte) (int, error) {
	if r.gate != nil {
		<-r.gate
		r.gate = nil
	}
	return r.reader.Read(p)
}

type streamNotifyWriter struct {
	*httptest.ResponseRecorder
	flushed chan string
}

func (w *streamNotifyWriter) FlushError() error {
	w.ResponseRecorder.Flush()
	select {
	case w.flushed <- w.Header().Get("X-Request-ID"):
	default:
	}
	return nil
}

type evidenceStreamWriter struct {
	*httptest.ResponseRecorder
	short, writeError, flushError bool
}

func (w *evidenceStreamWriter) Write(data []byte) (int, error) {
	if w.short || w.writeError {
		n := len(data) / 2
		_, _ = w.ResponseRecorder.Write(data[:n])
		if w.writeError {
			return n, errors.New("private client write failure")
		}
		return n, nil
	}
	return w.ResponseRecorder.Write(data)
}

func (w *evidenceStreamWriter) FlushError() error {
	if w.flushError {
		return errors.New("private client flush failure")
	}
	w.ResponseRecorder.Flush()
	return nil
}

func runEvidenceStream(t *testing.T, f *integrationFixture, key string, reader io.Reader, writer http.ResponseWriter, ctx context.Context) bool {
	t.Helper()
	f.g.client.Transport = toolRoundTripper(func(*http.Request) (*http.Response, error) {
		f.calls.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(reader)}, nil
	})
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(chatBody(f.connection.Alias, true))).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	aborted := false
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered != http.ErrAbortHandler {
					t.Fatalf("unexpected stream panic: %v", recovered)
				}
				aborted = true
			}
		}()
		f.g.Chat(writer, r)
	}()
	return aborted
}

func TestEvidenceStreamCompleteFragmentedFrames(t *testing.T) {
	f := newIntegrationFixture(t)
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	frames := []string{": heartbeat\r\n\r\n", "data: {\"choices\":\r\ndata: [{\"delta\":{\"content\":\"私人联系人你好\"}}]}\r\n\r\n", "data: [DONE]\r\n\r\n", ": final heartbeat\r\n\r\n"}
	body := strings.Join(frames, "")
	w := httptest.NewRecorder()
	if runEvidenceStream(t, f, f.key, iotest.OneByteReader(strings.NewReader(body)), w, context.Background()) || w.Code != 200 || w.Body.String() != body {
		t.Fatal("fragmented stream bytes or completion changed")
	}
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	if bundle.DeliveryState != "write_completed" {
		t.Fatal("completed stream delivery missing")
	}
	for _, kind := range []string{"upstream_output", "released_output"} {
		object := evidenceObject(t, bundle, kind)
		if object.ContentState != "retained" || object.MediaType != "text/event-stream" || object.Bytes != len(body) || revealRuntimeEvidence(t, f.g, bundle, kind) != body {
			t.Fatal("retained stream differs from exact accepted bytes", kind)
		}
		s := object.Stream
		if s == nil || s.EndState != "completed" || s.FrameCount != len(frames) || !s.DoneSeen || s.FramesTruncated || len(s.Frames) != len(frames) {
			t.Fatal("completed stream metadata missing", kind)
		}
		if kind == "upstream_output" && (s.Scope != "validated_frames" || s.WrittenBytes != 0) || kind == "released_output" && (s.Scope != "write_attempted_frames" || s.WrittenBytes != len(body)) {
			t.Fatal("stream stage scope or write count wrong", kind)
		}
		offset, elapsed := 0, int64(0)
		for i, frame := range s.Frames {
			if frame.Sequence != i+1 || frame.Offset != offset || frame.Bytes != len(frames[i]) || frame.ElapsedMS < elapsed || frame.Kind != []string{"other", "data", "done", "other"}[i] {
				t.Fatal("frame timeline incorrect", kind, frame)
			}
			offset += frame.Bytes
			elapsed = frame.ElapsedMS
		}
	}
	metadata, _ := json.Marshal(bundle)
	if strings.Contains(string(metadata), "私人联系人") {
		t.Fatal("private stream leaked into metadata")
	}
	assertEvidenceDiskPrivate(t, f.dir, "私人联系人", f.key, "provider-credential-private")
}

func TestEvidenceStreamFailurePreservesAcceptedFrames(t *testing.T) {
	private := "invalid-private-envelope"
	for _, tc := range []struct {
		name, tail, endState string
		combine              bool
		wantReleased         string
	}{
		{"early_eof", "", "incomplete_stream", false, event},
		{"unfinished_frame", "data: " + private, "incomplete_stream", false, event},
		{"invalid_same_read", "data: " + private + "\n\n", "invalid_upstream_stream", true, ""},
		{"error_same_read", "data: {\"error\":\"" + private + "\"}\n\n", "upstream_error", true, ""},
		{"error_later_read", "data: {\"error\":\"" + private + "\"}\n\n", "upstream_error", false, event},
		{"duplicate_done", done + done, "invalid_upstream_stream", true, ""},
		{"data_after_done", done + event, "invalid_upstream_stream", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIntegrationFixture(t)
			enableRuntimeEvidence(t, f.g, f.app.ID, "full")
			var reader io.Reader = io.MultiReader(strings.NewReader(event), strings.NewReader(tc.tail))
			if tc.combine {
				reader = strings.NewReader(event + tc.tail)
			}
			w := httptest.NewRecorder()
			if !runEvidenceStream(t, f, f.key, reader, w, context.Background()) {
				t.Fatal("incomplete or invalid stream did not abort")
			}
			bundle := runtimeEvidence(t, f.g, w, f.app.ID)
			wantUpstream := event
			if tc.name == "duplicate_done" || tc.name == "data_after_done" {
				wantUpstream += done
			}
			if bundle.DeliveryState != "stream_incomplete" || bundle.Record.ErrorCode != tc.endState || revealRuntimeEvidence(t, f.g, bundle, "upstream_output") != wantUpstream || revealRuntimeEvidence(t, f.g, bundle, "released_output") != tc.wantReleased || w.Body.String() != tc.wantReleased {
				t.Fatal("stream failure hid accepted frames or invented delivery")
			}
			for _, kind := range []string{"upstream_output", "released_output"} {
				object := evidenceObject(t, bundle, kind)
				if object.Stream == nil || object.Stream.EndState != tc.endState {
					t.Fatal("stream failure metadata missing")
				}
				if strings.Contains(revealRuntimeEvidence(t, f.g, bundle, kind), private) {
					t.Fatal("invalid/error provider text entered evidence")
				}
			}
			assertEvidenceDiskPrivate(t, f.dir, private, "private-answer")
		})
	}
}

func TestEvidenceStreamTransportFailures(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "read_error", "short_write", "write_error", "flush_error"} {
		t.Run(mode, func(t *testing.T) {
			f := newIntegrationFixture(t)
			enableRuntimeEvidence(t, f.g, f.app.ID, "full")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var reader io.Reader = strings.NewReader(event + done)
			w := &evidenceStreamWriter{ResponseRecorder: httptest.NewRecorder()}
			wantState, wantOutcome := "", "cancelled"
			switch mode {
			case "timeout":
				reader, wantState, wantOutcome = io.MultiReader(strings.NewReader(event), streamReadFailure{streamTimeout{}}), "upstream_timeout", "failed"
			case "cancel":
				reader, wantState = io.MultiReader(strings.NewReader(event), streamCancelReader{cancel}), "client_cancelled"
			case "read_error":
				reader, wantState, wantOutcome = io.MultiReader(strings.NewReader(event), streamReadFailure{errors.New("private upstream read error")}), "upstream_unreachable", "failed"
			case "short_write":
				w.short, wantState = true, "write_failed"
			case "write_error":
				w.writeError, wantState = true, "write_failed"
			case "flush_error":
				w.flushError, wantState = true, "flush_failed"
			}
			runEvidenceStream(t, f, f.key, reader, w, ctx)
			bundle := runtimeEvidence(t, f.g, w.ResponseRecorder, f.app.ID)
			wantDelivery := "stream_incomplete"
			if wantState == "write_failed" || wantState == "flush_failed" {
				wantDelivery = "write_failed"
			}
			if bundle.Record.Outcome != wantOutcome || bundle.DeliveryState != wantDelivery {
				t.Fatal("transport failure claimed completed delivery")
			}
			for _, kind := range []string{"upstream_output", "released_output"} {
				if evidenceObject(t, bundle, kind).Stream.EndState != wantState {
					t.Fatal("wrong stream end state", kind)
				}
			}
			s := evidenceObject(t, bundle, "released_output").Stream
			if s.WrittenBytes != w.Body.Len() {
				t.Fatal("write evidence is not the exact Write return count")
			}
			if w.short || w.writeError {
				if s.WrittenBytes >= evidenceObject(t, bundle, "released_output").Bytes || revealRuntimeEvidence(t, f.g, bundle, "released_output") != event+done {
					t.Fatal("short write lost the attempted body or overclaimed writes")
				}
			}
			assertEvidenceDiskPrivate(t, f.dir, "private upstream", "private client", "private-answer")
		})
	}
}

func TestEvidenceStreamBoundedContentAndManifest(t *testing.T) {
	for _, mode := range []string{"full", "metadata"} {
		t.Run(mode, func(t *testing.T) {
			f := newIntegrationFixture(t)
			config := enableRuntimeEvidence(t, f.g, f.app.ID, mode)
			config.MaxContentBytes = 4096
			if _, err := f.g.Evidence.SaveConfig(config, f.g.Store.Snapshot(), "runtime_test"); err != nil {
				t.Fatal(err)
			}
			body := strings.Repeat(event, MaxEvidenceStreamFrames+20) + done
			w := httptest.NewRecorder()
			if runEvidenceStream(t, f, f.key, strings.NewReader(body), w, context.Background()) || w.Body.String() != body {
				t.Fatal("evidence limits changed streaming delivery")
			}
			bundle := runtimeEvidence(t, f.g, w, f.app.ID)
			for _, kind := range []string{"upstream_output", "released_output"} {
				object := evidenceObject(t, bundle, kind)
				wantState := "omitted_size"
				if mode == "metadata" {
					wantState = "metadata_only"
				}
				if object.ContentState != wantState || object.Bytes != len(body) || object.Fingerprint != f.g.Evidence.fingerprint(f.app.ID, []byte(body)) || !object.Stream.FramesTruncated || len(object.Stream.Frames) != MaxEvidenceStreamFrames || object.Stream.FrameCount != MaxEvidenceStreamFrames+21 || !object.Stream.DoneSeen {
					t.Fatal("bounded stream capture lost total counts or fingerprint", kind)
				}
				if _, err := f.g.Evidence.Reveal(bundle.ID, f.app.ID, object.ID, "raw", "validation", "runtime_test"); !errors.Is(err, ErrEvidenceContentUnavailable) {
					t.Fatal("overcap/metadata stream retained a partial body", err)
				}
			}
		})
	}
}

func TestEvidenceStreamNoCaptureOutsideExplicitScope(t *testing.T) {
	for _, mode := range []string{"disabled", "outside_scope"} {
		t.Run(mode, func(t *testing.T) {
			f := newIntegrationFixture(t)
			if mode == "outside_scope" {
				other, _, err := f.g.Store.SaveApplication("", ApplicationInput{Name: "Other scope", AllowedConnections: []string{f.connection.ID}})
				if err != nil {
					t.Fatal(err)
				}
				enableRuntimeEvidence(t, f.g, other.ID, "full")
			}
			w := httptest.NewRecorder()
			if runEvidenceStream(t, f, f.key, strings.NewReader(event+done), w, context.Background()) || w.Body.String() != event+done {
				t.Fatal("disabled capture changed stream")
			}
			if _, err := f.g.Evidence.Get(EvidenceID(w.Header().Get("X-Request-ID")), f.app.ID); !errors.Is(err, ErrEvidenceNotFound) {
				t.Fatal("captured unselected application", err)
			}
		})
	}
}

func TestEvidenceStreamFlushesBeforeTerminalCaptureAndPinsConfig(t *testing.T) {
	f := newIntegrationFixture(t)
	config := enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	config.MaxContentBytes = 4096
	var err error
	config, err = f.g.Evidence.SaveConfig(config, f.g.Store.Snapshot(), "runtime_test")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	w := &streamNotifyWriter{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan string, 1)}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runEvidenceStream(t, f, f.key, io.MultiReader(strings.NewReader(event), &streamGateReader{gate: release, reader: strings.NewReader(done)}), w, context.Background())
	}()
	var requestID string
	select {
	case requestID = <-w.flushed:
	case <-time.After(3 * time.Second):
		t.Fatal("full evidence capture buffered the stream until completion")
	}
	if _, err := f.g.Evidence.Get(EvidenceID(requestID), f.app.ID); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatal("stream evidence published before terminal audit", err)
	}
	updated := config
	updated.Mode, updated.MaxContentBytes = "disabled", MaxEvidenceObjectBytes
	if _, err := f.g.Evidence.SaveConfig(updated, f.g.Store.Snapshot(), "runtime_test"); err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not complete")
	}
	bundle := runtimeEvidence(t, f.g, w.ResponseRecorder, f.app.ID)
	if bundle.CaptureRevision != config.Revision || bundle.Mode != "full" || bundle.MaxContentBytes != 4096 || revealRuntimeEvidence(t, f.g, bundle, "upstream_output") != event+done {
		t.Fatal("in-flight streaming capture configuration was reinterpreted")
	}
}

func TestEvidenceStreamUnsupportedUTF8NeverRetainsBody(t *testing.T) {
	f := newIntegrationFixture(t)
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	body := "data: {\"value\":\"" + string([]byte{0xff}) + "\"}\n\n" + done
	w := httptest.NewRecorder()
	if runEvidenceStream(t, f, f.key, strings.NewReader(body), w, context.Background()) || w.Body.String() != body {
		t.Fatal("capture changed existing SSE parser behavior")
	}
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	for _, kind := range []string{"upstream_output", "released_output"} {
		object := evidenceObject(t, bundle, kind)
		if object.ContentState != "unsupported_encoding" || object.Bytes != len(body) || object.Stream.EndState != "completed" || object.Fingerprint != f.g.Evidence.fingerprint(f.app.ID, []byte(body)) {
			t.Fatal("unsupported stream encoding lost explicit state")
		}
		if _, err := f.g.Evidence.Reveal(bundle.ID, f.app.ID, object.ID, "raw", "validation", "runtime_test"); !errors.Is(err, ErrEvidenceContentUnavailable) {
			t.Fatal("unsupported stream encoding released body")
		}
	}
}
