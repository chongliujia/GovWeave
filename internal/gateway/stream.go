package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Observe SSE framing without changing the bytes sent to clients. Only the
// current bounded event is held in memory and it is never written to audit.
type streamObserver struct {
	line, event, pending, ready []byte
	Done, Failed                bool
	accepted                    func([]byte, string)
}

func (s *streamObserver) observe(data []byte) error {
	for _, c := range data {
		s.pending = append(s.pending, c)
		if len(s.pending) > 1<<20 {
			return errors.New("stream_event_too_large")
		}
		if c != '\n' {
			s.line = append(s.line, c)
			if len(s.line)+len(s.event) > 1<<20 {
				return errors.New("stream_event_too_large")
			}
			continue
		}
		line := bytes.TrimSuffix(s.line, []byte{'\r'})
		if len(line) == 0 {
			value := bytes.TrimSpace(s.event)
			kind := "other"
			if bytes.Equal(value, []byte("[DONE]")) {
				if s.Done {
					return errors.New("invalid_upstream_stream")
				}
				s.Done = true
				kind = "done"
			} else if len(value) > 0 {
				var envelope map[string]json.RawMessage
				if s.Done || json.Unmarshal(value, &envelope) != nil || envelope == nil {
					return errors.New("invalid_upstream_stream")
				}
				if payload, ok := envelope["error"]; ok && string(payload) != "null" {
					s.Failed = true
					return errors.New("upstream_error")
				}
				kind = "data"
			}
			if s.accepted != nil {
				// The callback must consume these borrowed bytes synchronously.
				// Invalid and provider-error frames never reach this point.
				s.accepted(s.pending, kind)
			}
			s.ready = append(s.ready, s.pending...)
			s.pending = s.pending[:0]
			s.event = s.event[:0]
		} else if bytes.HasPrefix(line, []byte("data:")) {
			value := line[5:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
			s.event = append(s.event, value...)
			s.event = append(s.event, '\n')
		}
		s.line = s.line[:0]
	}
	return nil
}

func (s *streamObserver) take() []byte { data := s.ready; s.ready = nil; return data }
