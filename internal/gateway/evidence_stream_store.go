package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"unicode/utf8"
)

func validEvidenceStream(stream *EvidenceStream, kind string, total int, fingerprint string, streaming bool) bool {
	if stream == nil || !streaming || stream.Version != "sse-evidence-v1" || total < 0 || total > maxStreamBytes ||
		stream.FrameCount < 0 || stream.FrameCount > total || stream.WrittenBytes < 0 || stream.WrittenBytes > total ||
		!slices.Contains([]string{"completed", "incomplete_stream", "invalid_upstream_stream", "upstream_error", "response_too_large", "upstream_timeout", "upstream_unreachable", "client_cancelled", "write_failed", "flush_failed"}, stream.EndState) {
		return false
	}
	if kind == "upstream_output" {
		if stream.Scope != "validated_frames" || stream.WrittenBytes != 0 {
			return false
		}
	} else if kind == "released_output" {
		if stream.Scope != "write_attempted_frames" || stream.EndState == "completed" && stream.WrittenBytes != total {
			return false
		}
	} else {
		return false
	}
	digest, err := hex.DecodeString(fingerprint)
	if err != nil || len(digest) != sha256.Size || strings.ToLower(fingerprint) != fingerprint {
		return false
	}
	if len(stream.Frames) != min(stream.FrameCount, MaxEvidenceStreamFrames) || stream.FramesTruncated != (stream.FrameCount > MaxEvidenceStreamFrames) {
		return false
	}
	offset, elapsed, done := 0, int64(0), false
	for i, frame := range stream.Frames {
		if frame.Sequence != i+1 || frame.Offset != offset || frame.Bytes <= 0 || frame.Bytes > total-offset || frame.ElapsedMS < elapsed ||
			!slices.Contains([]string{"data", "done", "other"}, frame.Kind) || done && frame.Kind != "other" {
			return false
		}
		offset += frame.Bytes
		elapsed = frame.ElapsedMS
		done = done || frame.Kind == "done"
	}
	if done && !stream.DoneSeen || !stream.FramesTruncated && (offset != total || done != stream.DoneSeen) ||
		stream.FramesTruncated && total-offset < stream.FrameCount-len(stream.Frames) || stream.EndState == "completed" && !stream.DoneSeen {
		return false
	}
	return true
}

func cloneEvidenceStream(stream EvidenceStream) *EvidenceStream {
	stream.Frames = append([]EvidenceStreamFrame{}, stream.Frames...)
	return &stream
}

// Stream stages arrive with an incremental HMAC and a body held only while it
// fits the frozen retention cap. Crossing the cap discards the entire body;
// metadata never describes a retained prefix as the complete stage.
func (s *EvidenceStore) streamEvidenceObject(id string, record CallRecord, input EvidenceObjectInput, config EvidenceConfig) (EvidenceObject, []byte, error) {
	stream := input.Stream
	if stream == nil || input.Data != nil || input.ContentState != "" || input.MediaType != "text/event-stream" ||
		!validEvidenceStream(&stream.Metadata, input.Kind, stream.Bytes, stream.Fingerprint, record.Streaming) {
		return EvidenceObject{}, nil, ErrEvidenceInvalid
	}
	object := EvidenceObject{ID: id + ":" + input.Kind, Kind: input.Kind, MediaType: input.MediaType, Bytes: stream.Bytes,
		Fingerprint: stream.Fingerprint, Stream: cloneEvidenceStream(stream.Metadata)}
	if config.Mode == "metadata" {
		if stream.Data != nil {
			return EvidenceObject{}, nil, ErrEvidenceInvalid
		}
		object.ContentState = "metadata_only"
		return object, nil, nil
	}
	if stream.Bytes > config.MaxContentBytes {
		if stream.Data != nil {
			return EvidenceObject{}, nil, ErrEvidenceInvalid
		}
		object.ContentState = "omitted_size"
		return object, nil, nil
	}
	if stream.Data == nil || len(stream.Data) != stream.Bytes || s.fingerprint(record.ApplicationID, stream.Data) != stream.Fingerprint {
		return EvidenceObject{}, nil, ErrEvidenceInvalid
	}
	if !utf8.Valid(stream.Data) {
		object.ContentState = "unsupported_encoding"
		return object, nil, nil
	}
	object.ContentState = "retained"
	return object, bytes.Clone(stream.Data), nil
}

func validStoredEvidenceStream(object EvidenceObject, bundle EvidenceBundle) bool {
	if object.MediaType != "text/event-stream" || !validEvidenceStream(object.Stream, object.Kind, object.Bytes, object.Fingerprint, bundle.Record.Streaming) {
		return false
	}
	if bundle.Mode == "metadata" {
		return object.ContentState == "metadata_only"
	}
	if object.Bytes > bundle.MaxContentBytes {
		return object.ContentState == "omitted_size"
	}
	return object.ContentState == "retained" || object.ContentState == "unsupported_encoding" && object.Bytes > 0
}
