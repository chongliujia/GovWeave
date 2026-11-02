package gatewaybench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"govweave/internal/storage"
)

type Report struct {
	SchemaVersion int               `json:"schema_version"`
	Benchmark     string            `json:"benchmark"`
	CreatedAt     string            `json:"created_at"`
	State         string            `json:"state"`
	Failure       string            `json:"failure,omitempty"`
	FailedCell    *Cell             `json:"failed_cell,omitempty"`
	GoVersion     string            `json:"go_version"`
	OS            string            `json:"os"`
	Architecture  string            `json:"architecture"`
	LogicalCPUs   int               `json:"logical_cpus"`
	BinarySHA256  string            `json:"benchmark_binary_sha256"`
	BuildSettings map[string]string `json:"build_settings"`
	SourceSHA256  map[string]string `json:"source_sha256"`
	Options       Options           `json:"options"`
	PlannedCells  int               `json:"planned_cells"`
	Results       []Result          `json:"results"`
	Comparisons   []Comparison      `json:"comparisons"`
	Limitations   []string          `json:"limitations"`
}

var limitations = []string{
	"Synthetic loopback HTTP/1.1 inside one host or container; no real model, TLS, WAN, multiple instances, tenant contention or production SLA. Container isolation, backing storage and resource quotas require separately recorded deployment metadata.",
	"The worker embeds the actual server.New router, gateway and file stores. It is a benchmark executable, not the shipped cmd/govweave binary; setup and lifecycle orchestration differ.",
	"Fixed-concurrency closed-loop clients, not an independent arrival rate: saturation queues and coordinated omission are not characterized. Throughput is achieved harness throughput, not maximum service capacity.",
	"Warmups are excluded from latency and interval resource deltas, but included in store size, verification counts and process-lifetime peak RSS. No forced GC; GOGC=100, GOMEMLIMIT=off.",
	"Credential request checking is observe mode with both rules; output protection is disabled so SSE is admitted. No semantic-model detection, tool execution, active assessments or registered product workloads.",
	"SSE has 16 data frames plus DONE, flushed without token pacing. First body byte is client-observed, not model time-to-first-token. All response bytes must match the fixture.",
	"Each gateway cell has a new child and private directory. Parent load generation and provider CPU/heap are excluded from worker metrics but still compete for the same physical resources.",
	"Client completion may precede final audit/capture writes. The drained acknowledgement waits for handlers; read-back verification and shutdown are outside the resource window. OS file-sync semantics do not prove power-loss durability.",
	"Process CPU is getrusage interval CPU; RSS is the process-lifetime high-water mark, not an interval peak. Heap values are endpoints. Runtime GC CPU estimates are not directly comparable to OS CPU; do not divide them to claim GC percent.",
	"Nearest-rank percentiles describe the finite samples. Small samples can make P99 the maximum. Differences of direct and gateway percentiles are distribution differences, not paired per-request overhead; negative values remain visible.",
	"Seeded order randomizes workloads and mode order within each matched round; sequential runs and machine/storage noise still confound comparisons. Repeated calls are not independent customer workloads.",
	"Reports contain only metadata and counters. Temporary synthetic credentials, plaintext payloads and encrypted instance data are removed after child shutdown; generated reports are not source fixtures.",
	"The executable hash identifies the running binary. Source hashes describe files on disk at run start, not proof of their correspondence to that binary; build immediately before running. Build settings retain available VCS identity and dirty state.",
	"Per-request latency runs from client request construction through body read (or failure); byte comparison is outside that timer. Batch throughput includes client validation. Resource snapshots and control acknowledgements add small measurement overhead.",
	"Optional profiling is diagnostic only, begins after warmup and stops after the ending resource sample. CPU, contention, trace and allocs are separate modes; instrumentation changes timings and disables direct percentile comparisons. Profile stacks/runtime events contain paths and symbols, not payload dumps; artifact files are private and bounded.",
	"GC stopping and total pause histograms retain runtime bucket precision; totals are lower/upper bounds, not exact durations. Stopping is included in total, not additional. Adjacent MemStats and histogram snapshots need not cover precisely identical events. Allocation profiles use default runtime sampling and may lag up to two GC cycles; compare after with before as a sampling diagnostic, not exact byte accounting.",
}

type child struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *json.Decoder
	waited bool
}

func (c *child) close() {
	_ = c.input.Close()
	if !c.waited {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
	}
}

func (c *child) reply(ctx context.Context, state string) (workerReply, error) {
	channel := make(chan struct {
		value workerReply
		err   error
	}, 1)
	go func() {
		var v workerReply
		err := c.output.Decode(&v)
		channel <- struct {
			value workerReply
			err   error
		}{v, err}
	}()
	select {
	case r := <-channel:
		if r.err != nil || r.value.State != state {
			return workerReply{}, errors.New("benchmark worker protocol failed")
		}
		return r.value, nil
	case <-ctx.Done():
		return workerReply{}, errors.New("benchmark worker deadline reached")
	}
}

func startChild(ctx context.Context, executable string, setup workerConfig) (*child, workerReply, error) {
	cmd := exec.CommandContext(ctx, executable, "--worker")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "TMPDIR=" + os.TempDir(), "GOGC=100", "GOMEMLIMIT=off", "GOMAXPROCS=" + fmt.Sprint(setup.GoMaxProcs)}
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, workerReply{}, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, workerReply{}, err
	}
	if err = cmd.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, workerReply{}, err
	}
	c := &child{cmd: cmd, input: input, output: json.NewDecoder(io.LimitReader(output, 64<<10))}
	if err = json.NewEncoder(input).Encode(setup); err != nil {
		c.close()
		return nil, workerReply{}, err
	}
	ready, err := c.reply(ctx, "ready")
	if err != nil || !localProvider(ready.URL+"/v1") || !strings.HasPrefix(ready.Key, "gw_app_") {
		c.close()
		return nil, workerReply{}, errors.New("benchmark worker did not initialize")
	}
	return c, ready, nil
}

func runCell(ctx context.Context, executable, artifactRoot string, index int, cell Cell, o Options) (Result, error) {
	result := Result{Cell: cell}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	providerKey, err := storage.ID("synthetic_", 16)
	if err != nil {
		return result, err
	}
	f, err := startFixture(cell, providerKey, o.DelayMS)
	if err != nil {
		return result, err
	}
	defer f.server.Close()
	endpoint, key, model := f.url, providerKey, "fixture"
	var worker *child
	var profileDir string
	if cell.Mode != "direct" {
		dir, err := os.MkdirTemp("", "govweave-load-")
		if err != nil {
			return result, err
		}
		defer os.RemoveAll(dir)
		if o.Profile != "" {
			profileDir = filepath.Join(artifactRoot, "profiles", fmt.Sprintf("cell-%03d", index))
			if err := os.MkdirAll(filepath.Dir(profileDir), 0700); err != nil {
				return result, err
			}
			if err := os.Mkdir(profileDir, 0700); err != nil {
				return result, err
			}
		}
		var ready workerReply
		worker, ready, err = startChild(ctx, executable, workerConfig{Directory: dir, ProviderURL: f.url + "/v1", ProviderKey: providerKey, Mode: cell.Mode, GoMaxProcs: o.GoMaxProcs, Profile: o.Profile, ProfileDir: profileDir})
		if err != nil {
			return result, err
		}
		defer worker.close()
		endpoint, key, model = ready.URL, ready.Key, "bench"
	}
	client := benchmarkClient(cell.Concurrency)
	defer client.CloseIdleConnections()
	body := requestBody(model, cell.Protocol == "sse")
	warmup, _ := runLoad(ctx, client, endpoint, key, body, f.body, worker != nil, o.Warmup, cell.Concurrency)
	for _, s := range warmup {
		if s.Error != "" {
			result.WarmupFailed++
		}
	}
	if worker != nil {
		if err := json.NewEncoder(worker.input).Encode(control{Operation: "begin"}); err != nil {
			return result, err
		}
		if _, err := worker.reply(ctx, "measuring"); err != nil {
			return result, err
		}
	}
	start := time.Now()
	samples, elapsed := runLoad(ctx, client, endpoint, key, body, f.body, worker != nil, o.Requests, cell.Concurrency)
	result.Samples, result.ElapsedMS = samples, float64(elapsed)/float64(time.Millisecond)
	summarizeResult(&result)
	if worker != nil {
		if err := json.NewEncoder(worker.input).Encode(control{"finish", o.Requests + o.Warmup}); err != nil {
			return result, err
		}
		end, err := worker.reply(ctx, "drained")
		if err != nil {
			return result, err
		}
		result.DurableWindowMS = float64(time.Since(start)) / float64(time.Millisecond)
		result.Resources, result.DrainMS = end.Resources, end.DrainMS
		verified, err := worker.reply(ctx, "verified")
		if err != nil {
			return result, err
		}
		result.Verification = verified.Verification
		if result.Verification != nil && result.Verification.Passed {
			result.DurablePerSec = float64(result.Succeeded) / (result.DurableWindowMS / 1000)
		}
		waitErr := worker.cmd.Wait()
		worker.waited = true
		if waitErr != nil {
			return result, errors.New("benchmark worker failed to stop")
		}
		if o.Profile != "" {
			result.Profiles, err = profileArtifacts(artifactRoot, profileDir, o.Profile)
			if err != nil {
				return result, err
			}
		}
	}
	result.ProviderCalls, result.ProviderInvalid = f.calls.Load(), f.invalid.Load()
	result.ProviderCountMatches = result.ProviderCalls == int64(o.Requests+o.Warmup)
	return result, nil
}

func Run(ctx context.Context, executable, sourceRoot, artifactRoot string, o Options, progress func(Report) error) (Report, error) {
	report := Report{SchemaVersion: 1, Benchmark: "gateway-load-v1", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), State: "running", GoVersion: runtime.Version(), OS: runtime.GOOS, Architecture: runtime.GOARCH, LogicalCPUs: runtime.NumCPU(), Options: o, Results: []Result{}, Comparisons: []Comparison{}, Limitations: limitations}
	report.BuildSettings = map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			// Do not retain arbitrary compiler/linker arguments or environment.
			if s.Key == "vcs.revision" || s.Key == "vcs.time" || s.Key == "vcs.modified" || s.Key == "GOOS" || s.Key == "GOARCH" || s.Key == "CGO_ENABLED" || s.Key == "-race" || s.Key == "-trimpath" {
				report.BuildSettings[s.Key] = s.Value
			}
		}
	}
	if err := o.Validate(); err != nil {
		return report, err
	}
	if o.Profile != "" {
		info, err := os.Lstat(artifactRoot)
		if err != nil || !filepath.IsAbs(artifactRoot) || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return report, errors.New("private absolute artifact directory required")
		}
	}
	if _, _, _, err := processResources(); err != nil {
		return report, err
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		return report, err
	}
	digest := sha256.Sum256(data)
	report.BinarySHA256 = hex.EncodeToString(digest[:])
	report.SourceSHA256, err = sourceHashes(sourceRoot)
	if err != nil {
		return report, err
	}
	plan := Plan(o)
	report.PlannedCells = len(plan)
	if progress != nil {
		if err := progress(report); err != nil {
			return report, err
		}
	}
	for index, cell := range plan {
		if ctx.Err() != nil {
			report.State, report.Failure = "failed", "interrupted"
			report.FailedCell = &cell
			break
		}
		result, err := runCell(ctx, executable, artifactRoot, index, cell, o)
		if err != nil {
			report.State, report.Failure = "failed", "cell_execution_failed"
			if ctx.Err() != nil {
				report.Failure = "interrupted"
			}
			report.FailedCell = &cell
			break
		}
		report.Results = append(report.Results, result)
		report.Comparisons = comparisons(report.Results)
		if progress != nil {
			if err := progress(report); err != nil {
				return report, err
			}
		}
	}
	if report.State == "running" {
		report.State = "completed"
		for _, r := range report.Results {
			if !comparable(r) {
				report.State = "completed_with_errors"
			}
		}
	}
	if progress != nil {
		if err := progress(report); err != nil {
			return report, err
		}
	}
	return report, nil
}

func sourceHashes(root string) (map[string]string, error) {
	result := map[string]string{}
	add := func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(rel)] = hex.EncodeToString(digest[:])
		return nil
	}
	if err := add(filepath.Join(root, "go.mod")); err != nil {
		return nil, err
	}
	for _, dir := range []string{"cmd/gateway-bench", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".go") || strings.Contains(filepath.ToSlash(path), "/server/web/") {
				return add(path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
