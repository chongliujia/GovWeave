package gatewaybench

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testOptions() Options {
	return Options{Requests: 12, Warmup: 2, Rounds: 2, Concurrency: []int{1, 8}, Sizes: []int{1024}, Protocols: []string{"json", "sse"}, GoMaxProcs: 2, Seed: 42}
}

func TestPlanAndBounds(t *testing.T) {
	o := testOptions()
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	plan := Plan(o)
	if len(plan) != 32 || !reflect.DeepEqual(plan, Plan(o)) {
		t.Fatal("plan must be complete and reproducible")
	}
	seen := map[Cell]bool{}
	for _, c := range plan {
		if seen[c] {
			t.Fatal("duplicate cell")
		}
		seen[c] = true
	}
	o.Seed++
	if reflect.DeepEqual(plan, Plan(o)) {
		t.Fatal("seed did not affect order")
	}
	for _, change := range []func(*Options){
		func(o *Options) { o.Requests = 513 }, func(o *Options) { o.Warmup = 0 },
		func(o *Options) { o.Rounds = 0 }, func(o *Options) { o.DelayMS = 101 },
		func(o *Options) { o.GoMaxProcs = 0 }, func(o *Options) { o.Concurrency = []int{1, 1} },
		func(o *Options) { o.Sizes = []int{65536} }, func(o *Options) { o.Protocols = []string{"json", "json"} },
		func(o *Options) { o.Rounds = 5; o.Sizes = []int{128, 1024, 4096, 8192} },
	} {
		invalid := testOptions()
		change(&invalid)
		if invalid.Validate() == nil {
			t.Fatalf("accepted invalid bounds: %+v", invalid)
		}
	}
}

func TestDistributionAndFailureDenominators(t *testing.T) {
	if distribution(nil) != nil {
		t.Fatal("empty data must be unavailable")
	}
	values := []float64{100, 1, 2, 3}
	d := distribution(values)
	if d.P50MS != 2 || d.P95MS != 100 || d.P99MS != 100 || !d.P99IsMax || d.MeanMS != 26.5 || values[0] != 100 {
		t.Fatalf("bad quantiles: %+v", d)
	}
	many := make([]float64, 100)
	for i := range many {
		many[i] = float64(i + 1)
	}
	if p := distribution(many); p.P99MS != 99 || p.P99IsMax {
		t.Fatal("incorrect nearest rank")
	}
	r := Result{ElapsedMS: 1000, Samples: []Sample{{ElapsedMS: 1, FirstBodyMS: .5}, {ElapsedMS: 500, Error: "transport_error"}}}
	summarizeResult(&r)
	if r.Succeeded != 1 || r.Failed != 1 || r.SucceededPerSec != 1 || r.AllLatency.Count != 2 || r.SuccessLatency.Count != 1 || r.AllLatency.P95MS != 500 || r.Errors["transport_error"] != 1 {
		t.Fatal("failure was hidden")
	}
}

func TestComparisonRequiresValidMatchedCells(t *testing.T) {
	direct := Result{Cell: Cell{Round: 1, Concurrency: 1, OutputBytes: 1024, Protocol: "json", Mode: "direct"}, Samples: []Sample{{ElapsedMS: 5, FirstBodyMS: 3}}, ElapsedMS: 5, ProviderCalls: 1, ProviderCountMatches: true}
	summarizeResult(&direct)
	gateway := direct
	gateway.Mode, gateway.Samples = "full", []Sample{{ElapsedMS: 4, FirstBodyMS: 2}}
	gateway.Verification, gateway.Resources = &Verification{Passed: true}, &ResourceWindow{}
	summarizeResult(&gateway)
	cs := comparisons([]Result{gateway, direct})
	if len(cs) != 1 || !cs[0].Comparable || *cs[0].P99DeltaMS != -1 {
		t.Fatal("negative distribution difference lost")
	}
	for _, change := range []func(*Result){
		func(r *Result) { r.Failed = 1 }, func(r *Result) { r.WarmupFailed = 1 },
		func(r *Result) { r.ProviderCountMatches = false }, func(r *Result) { r.ProviderInvalid = 1 },
		func(r *Result) { r.Verification = &Verification{} }, func(r *Result) { r.Resources = nil },
	} {
		bad := gateway
		change(&bad)
		c := comparisons([]Result{bad, direct})[0]
		if c.Comparable || c.P99DeltaMS != nil {
			t.Fatal("invalid cell got a comparison")
		}
	}
	direct.Round = 2
	if len(comparisons([]Result{gateway, direct})) != 0 {
		t.Fatal("unmatched rounds compared")
	}
}

func TestFixtureProtocolsAndCredentials(t *testing.T) {
	for _, protocol := range []string{"json", "sse"} {
		t.Run(protocol, func(t *testing.T) {
			f, err := startFixture(Cell{Protocol: protocol, OutputBytes: 32768}, "synthetic-test", 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.server.Close()
			client := benchmarkClient(4)
			defer client.CloseIdleConnections()
			body := requestBody("fixture", protocol == "sse")
			samples, elapsed := runLoad(context.Background(), client, f.url, "synthetic-test", body, f.body, false, 8, 4)
			for i, s := range samples {
				if s.Error != "" || s.Status != 200 || s.Bytes != len(f.body) || s.Index != i || s.FirstBodyMS <= 0 || s.ElapsedMS < s.FirstBodyMS {
					t.Fatalf("incomplete successful response: %+v", s)
				}
			}
			if elapsed <= 0 || f.calls.Load() != 8 || f.invalid.Load() != 0 {
				t.Fatal("bad provider counts")
			}
			bad := oneRequest(context.Background(), client, f.url, "wrong", body, f.body, false, 0)
			if bad.Error != "http_status" || bad.Status != 400 || f.invalid.Load() != 1 {
				t.Fatal("invalid provider request accepted")
			}
		})
	}
}

func TestClientFailuresAreNotSuccessfulTimings(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		handler    http.HandlerFunc
	}{
		{"status", "http_status", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "synthetic", 503) }},
		{"mismatch", "body_mismatch", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("wrong response")) }},
		{"truncated", "body_read", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			w.Write([]byte("x"))
		}},
		{"timeout", "transport_error", func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); <-r.Context().Done() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(tc.handler)
			defer s.Close()
			client := benchmarkClient(1)
			defer client.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			v := oneRequest(ctx, client, s.URL, "synthetic", []byte("{}"), []byte("expected"), false, 0)
			if v.Error != tc.want || v.ElapsedMS <= 0 {
				t.Fatalf("bad failure accounting: %+v", v)
			}
			r := Result{Samples: []Sample{v}, ElapsedMS: v.ElapsedMS}
			summarizeResult(&r)
			if r.SuccessLatency != nil || r.FirstBodyLatency != nil || r.Failed != 1 {
				t.Fatal("failure included as success")
			}
		})
	}
}

func TestFailedRunCheckpoint(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checkpoints := []Report{}
	r, err := Run(ctx, executable, root, "", testOptions(), func(r Report) error { checkpoints = append(checkpoints, r); return nil })
	if err != nil || r.State != "failed" || r.Failure != "interrupted" || r.FailedCell == nil || len(r.Results) != 0 || len(checkpoints) != 2 {
		t.Fatalf("failure checkpoint absent: %s, %v", r.State, err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(dir, r); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved Report
	if json.Unmarshal(data, &saved) != nil || saved.State != "failed" {
		t.Fatal("invalid checkpoint")
	}
	for _, name := range []string{"report.json", "report.md"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("report permissions")
		}
	}
	if err := Worker(strings.NewReader(`{"provider_url":"https://remote.example/v1"}`), &strings.Builder{}); err == nil {
		t.Fatal("invalid worker setup accepted")
	}
}
