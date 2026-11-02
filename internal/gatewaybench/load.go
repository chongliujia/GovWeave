package gatewaybench

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const inputText = "Synthetic gateway benchmark input. "

type fixture struct {
	url     string
	server  *http.Server
	body    []byte
	frames  [][]byte
	calls   atomic.Int64
	invalid atomic.Int64
}

func requestBody(model string, stream bool) []byte {
	data, _ := json.Marshal(map[string]any{"model": model, "messages": []map[string]string{{"role": "user", "content": strings.Repeat(inputText, 16)}}, "stream": stream})
	return data
}

func startFixture(cell Cell, key string, delay int) (*fixture, error) {
	f := &fixture{}
	content := strings.Repeat("a", cell.OutputBytes)
	if cell.Protocol == "json" {
		f.body, _ = json.Marshal(map[string]any{"id": "synthetic-benchmark", "object": "chat.completion", "model": "fixture", "choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop"}}})
	} else {
		for i := 0; i < 16; i++ {
			chunk := content[i*len(content)/16 : (i+1)*len(content)/16]
			data, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]string{"content": chunk}, "finish_reason": nil}}})
			f.frames = append(f.frames, append(append([]byte("data: "), data...), '\n', '\n'))
		}
		f.frames = append(f.frames, []byte("data: [DONE]\n\n"))
		f.body = bytes.Join(f.frames, nil)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		var body struct {
			Model    string                           `json:"model"`
			Stream   bool                             `json:"stream"`
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(data) > 4096 || json.Unmarshal(data, &body) != nil || r.Method != "POST" || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer "+key || r.Header.Get("X-GovWeave-Trace-ID") != "" || body.Model != "fixture" || body.Stream != (cell.Protocol == "sse") || len(body.Messages) != 1 || body.Messages[0].Role != "user" || body.Messages[0].Content != strings.Repeat(inputText, 16) {
			f.invalid.Add(1)
			http.Error(w, "invalid synthetic request", 400)
			return
		}
		if delay > 0 {
			select {
			case <-time.After(time.Duration(delay) * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		if cell.Protocol == "json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(f.body)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, frame := range f.frames {
			if _, err := w.Write(frame); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
		}
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f.url = "http://" + l.Addr().String()
	f.server = &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go f.server.Serve(l)
	return f, nil
}

func benchmarkClient(concurrency int) *http.Client {
	return &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, MaxIdleConns: concurrency, MaxIdleConnsPerHost: concurrency, MaxConnsPerHost: concurrency, DisableCompression: true, IdleConnTimeout: 30 * time.Second}}
}

func oneRequest(ctx context.Context, client *http.Client, endpoint, key string, body, expected []byte, traced bool, index int) (sample Sample) {
	sample.Index = index
	start := time.Now()
	defer func() {
		if sample.ElapsedMS == 0 {
			sample.ElapsedMS = float64(time.Since(start)) / float64(time.Millisecond)
		}
	}()
	r, err := http.NewRequestWithContext(ctx, "POST", endpoint+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		sample.Error = "request_invalid"
		return
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	if traced {
		r.Header.Set("X-GovWeave-Trace-ID", "1234567890abcdef1234567890abcdef")
	}
	response, err := client.Do(r)
	if err != nil {
		sample.Error = "transport_error"
		return
	}
	defer response.Body.Close()
	sample.Status = response.StatusCode
	first := make([]byte, 1)
	n, err := io.ReadFull(response.Body, first)
	if n > 0 {
		sample.FirstBodyMS = float64(time.Since(start)) / float64(time.Millisecond)
	}
	if err != nil {
		sample.Error = "body_read"
		return
	}
	remaining, err := io.ReadAll(io.LimitReader(response.Body, int64(len(expected))+1))
	sample.ElapsedMS = float64(time.Since(start)) / float64(time.Millisecond)
	sample.Bytes = n + len(remaining)
	if err != nil {
		sample.Error = "body_read"
	} else if sample.Status != 200 {
		sample.Error = "http_status"
	} else if !bytes.Equal(append(first, remaining...), expected) {
		sample.Error = "body_mismatch"
	}
	return
}

func runLoad(ctx context.Context, client *http.Client, endpoint, key string, body, expected []byte, traced bool, count, concurrency int) ([]Sample, time.Duration) {
	samples := make([]Sample, count)
	var next atomic.Int64
	var wg sync.WaitGroup
	startGate := make(chan struct{})
	for i := 0; i < min(count, concurrency); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			for {
				index := int(next.Add(1) - 1)
				if index >= count {
					return
				}
				samples[index] = oneRequest(ctx, client, endpoint, key, body, expected, traced, index)
			}
		}()
	}
	start := time.Now()
	close(startGate)
	wg.Wait()
	return samples, time.Since(start)
}

func summarizeResult(r *Result) {
	r.Succeeded, r.Failed = 0, 0
	all, success, first := []float64{}, []float64{}, []float64{}
	r.Errors = map[string]int{}
	for _, s := range r.Samples {
		all = append(all, s.ElapsedMS)
		if s.Error != "" {
			r.Failed++
			r.Errors[s.Error]++
		} else {
			r.Succeeded++
			success = append(success, s.ElapsedMS)
			first = append(first, s.FirstBodyMS)
		}
	}
	r.AllLatency, r.SuccessLatency, r.FirstBodyLatency = distribution(all), distribution(success), distribution(first)
	r.SucceededPerSec = float64(r.Succeeded) / (r.ElapsedMS / 1000)
}
