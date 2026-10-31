package gateway

import (
	"encoding/hex"
	"hash"
	"time"
)

// A stage holds at most the configured content limit and the first bounded
// frame manifest. Hashing/counting continues after the body is discarded.
// Neither frames nor content are persisted until the ordinary audit commits.
type evidenceStreamStage struct {
	input EvidenceStreamInput
	hash  hash.Hash
	limit int
}

type pendingEvidenceFrame struct {
	bytes int
	kind  string
}

type callStreamEvidence struct {
	call         *callEvidence
	start        time.Time
	upstream     evidenceStreamStage
	released     evidenceStreamStage
	pending      []pendingEvidenceFrame
	pendingCount int
	pendingDone  bool
}

func (g *Engine) beginStreamEvidence(call *callEvidence, start time.Time) *callStreamEvidence {
	if call == nil || call.finished {
		return nil
	}
	stage := func(scope string) evidenceStreamStage {
		value := evidenceStreamStage{hash: g.Evidence.newEvidenceFingerprint(call.applicationID), limit: call.payload.Config.MaxContentBytes,
			input: EvidenceStreamInput{Metadata: EvidenceStream{Version: "sse-evidence-v1", Scope: scope, Frames: []EvidenceStreamFrame{}}}}
		if call.payload.Config.Mode == "full" {
			value.input.Data = []byte{}
		}
		return value
	}
	return &callStreamEvidence{call: call, start: start, upstream: stage("validated_frames"), released: stage("write_attempted_frames")}
}

func (s *evidenceStreamStage) append(data []byte) {
	s.input.Bytes += len(data)
	_, _ = s.hash.Write(data)
	if s.input.Data == nil {
		return
	}
	if s.input.Bytes > s.limit {
		// Never expose a retained prefix as if it were the complete stage.
		clear(s.input.Data)
		s.input.Data = nil
		return
	}
	s.input.Data = append(s.input.Data, data...)
}

func (c *callStreamEvidence) accepted(data []byte, kind string) {
	s := &c.upstream
	metadata := &s.input.Metadata
	metadata.FrameCount++
	if len(metadata.Frames) < MaxEvidenceStreamFrames {
		metadata.Frames = append(metadata.Frames, EvidenceStreamFrame{Sequence: metadata.FrameCount, Offset: s.input.Bytes,
			Bytes: len(data), ElapsedMS: time.Since(c.start).Milliseconds(), Kind: kind})
	}
	metadata.DoneSeen = metadata.DoneSeen || kind == "done"
	s.append(data)
	c.pendingCount++
	c.pendingDone = c.pendingDone || kind == "done"
	// Only the portion that could still enter the released manifest is held.
	if len(c.released.input.Metadata.Frames)+len(c.pending) < MaxEvidenceStreamFrames {
		c.pending = append(c.pending, pendingEvidenceFrame{len(data), kind})
	}
}

func (c *callStreamEvidence) attempt(data []byte) {
	if c == nil {
		return
	}
	s := &c.released
	metadata := &s.input.Metadata
	offset, elapsed := s.input.Bytes, time.Since(c.start).Milliseconds()
	for i, frame := range c.pending {
		metadata.Frames = append(metadata.Frames, EvidenceStreamFrame{Sequence: metadata.FrameCount + i + 1, Offset: offset,
			Bytes: frame.bytes, ElapsedMS: elapsed, Kind: frame.kind})
		offset += frame.bytes
	}
	metadata.FrameCount += c.pendingCount
	metadata.DoneSeen = metadata.DoneSeen || c.pendingDone
	s.append(data)
	c.pending, c.pendingCount, c.pendingDone = c.pending[:0], 0, false
}

func (c *callStreamEvidence) written(n, attempted int) {
	if c == nil {
		return
	}
	// A conforming ResponseWriter returns 0 <= n <= len(p). If an adapter
	// violates that contract the stream fails; do not invent extra bytes.
	if n < 0 {
		n = 0
	}
	if n > attempted {
		n = attempted
	}
	c.released.input.Metadata.WrittenBytes += n
}

func (c *callStreamEvidence) finish(endState string) {
	if c == nil {
		return
	}
	for kind, stage := range map[string]*evidenceStreamStage{"upstream_output": &c.upstream, "released_output": &c.released} {
		stage.input.Metadata.EndState = endState
		stage.input.Metadata.FramesTruncated = stage.input.Metadata.FrameCount > len(stage.input.Metadata.Frames)
		stage.input.Fingerprint = hex.EncodeToString(stage.hash.Sum(nil))
		for i := range c.call.payload.Objects {
			object := &c.call.payload.Objects[i]
			if object.Kind == kind {
				object.MediaType, object.ContentState, object.Data = "text/event-stream", "", nil
				object.Stream = &stage.input
			}
		}
	}
}
