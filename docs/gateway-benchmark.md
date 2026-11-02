# Synthetic gateway load benchmark

**English** | [简体中文](zh-CN/gateway-benchmark.md)

GovWeave continues to use Go. Before considering a language change, measure the actual forwarding and evidence path. `gateway-bench` provides a bounded local experiment with a direct-provider baseline, JSON/SSE traffic, encrypted evidence modes and separate gateway process resource counters. It does not determine production capacity or prove a Go/Rust performance difference.

## Run

From the checkout, on macOS or Linux with permission to create loopback listeners and child processes:

```bash
make benchmark-gateway
```

The target builds a normal binary without the race detector, then runs 144 cells: three rounds × three concurrency levels (`1,8,32`) × two output text sizes (`1024,16384` bytes) × JSON/SSE × four modes. Each cell has 16 warmups and 128 measured requests. No model API key or external service is required. All provider requests use a synthetic loopback server.

A shorter reproducible matrix:

```bash
make benchmark-gateway GATEWAY_BENCH_ARGS='-requests 128 -warmup 16 -rounds 2 -concurrency 1,8 -sizes 1024,16384 -protocols json,sse'
```

JSON and English Markdown reports are written to a new private directory under `dist/gateway-benchmark/`. Use `-out /absolute/path/to/new-directory` to choose it; an existing directory is rejected. Build immediately before each experiment and avoid concurrent builds/tests or other heavy workloads. To execute a previously built binary from elsewhere, pass `-source-root /path/to/GovWeave`.

| Option | Default | Bounds |
| --- | --- | --- |
| `-requests` | 128 | 1–512 measured attempts per cell |
| `-warmup` | 16 | 1–64 attempts per cell |
| `-rounds` | 3 | 1–5 |
| `-concurrency` | `1,8,32` | Distinct integers, each 1–128 |
| `-sizes` | `1024,16384` | Distinct output text sizes, each 128–32768 bytes |
| `-protocols` | `json,sse` | `json`, `sse`, or both |
| `-provider-delay-ms` | 0 | 0–100 ms before output, not token pacing |
| `-gomaxprocs` | min(4, logical CPUs) | 1–128, gateway child only |
| `-seed` | 20261031 | Signed integer controlling workload/mode order |
| `-profile` | disabled | `cpu`, `contention`, `trace` or `allocs`; at most 8 cells |

At most 256 cells are allowed. Each cell has a 90-second deadline; individual client requests time out after eight seconds. Concurrency above the gateway's 64-request admission limit can produce denials; errors remain visible. The size/call limits keep each fresh capture store within the current object, record and byte budgets; this is not a retention-exhaustion test.

## Linux / Docker comparison

```bash
make benchmark-gateway-docker GATEWAY_BENCH_ARGS='-requests 128 -warmup 16 -rounds 2 -concurrency 8 -sizes 16384 -protocols json,sse -gomaxprocs 4'
```

The build defaults to `GO_VERSION` from the production `Dockerfile`. The first build needs a cached or downloadable official Go image; compilation uses `GOPROXY=off` and `GOTOOLCHAIN=local`. `Dockerfile.benchmark` is a separate developer image and does not change the production image. Set `GATEWAY_BENCH_GO_VERSION` and `GATEWAY_BENCH_IMAGE` explicitly for another comparison toolchain/image.

The runner fixes four CPUs, 1 GiB memory with no additional swap, 256 PIDs, a non-root user, a read-only root filesystem and `--network none`. Traffic stays on container loopback with no published ports. Provider, clients and gateway children share this quota; parent `GOMAXPROCS=4` is fixed, while the benchmark records the gateway child setting. Evidence uses a fresh Docker `local` disk volume per run and source hashes come from the image. No host source, credentials or Docker socket is mounted, and tmpfs is not used to simulate persistence.

Run an already-built trusted image, or select a diagnostic:

```bash
python3 scripts/benchmark-gateway-docker.py --image govweave-gateway-bench:local --out dist/gateway-benchmark/linux-diagnostic -- -requests 128 -warmup 16 -rounds 1 -concurrency 8 -sizes 16384 -protocols json -profile trace
```

The outer private directory retains `docker-environment.json` (actual image ID, engine/kernel, isolation settings, exit state, other running container count and cleanup results), `container.log`, and `result/report.json` / `report.md`. The run pins the inspected immutable local image ID. `--out` must be new. The benchmark's own `-out`, `-source-root` and worker entry point are controlled by the runner and cannot be overridden. The benchmark execution deadline defaults to 1,800 seconds, followed by bounded cleanup; `--timeout` accepts 1–21,600 seconds. Go's per-cell deadlines still apply.

Completion and handled interruption stop this container, copy complete/partial checkpoints, then remove this run's UUID-named container and volume. Failed cleanup is recorded and causes a failure exit. A forced process kill or unavailable Docker daemon can still leave resources. The runner neither stops other workloads nor performs a global prune. Docker Desktop's Linux VM, virtual disk and host background load affect results; it is not bare-metal Linux, and differences from macOS cannot all be attributed to Go or one syscall.

Optional Docker acceptance after building the image:

```bash
make build-gateway-bench-docker
python3 tests/gateway-bench-docker-test.py
```

Acceptance covers actual isolation settings, JSON/SSE evidence readback, private artifacts, rejected path overrides, and interrupted/deadline checkpoint/resource cleanup. Set the `GATEWAY_BENCH_IMAGE` environment variable to test another built image.

## What runs

Each matched workload/round contains four independently executed cells, with seeded random order:

| Mode | Path |
| --- | --- |
| `direct` | Client → synthetic provider |
| `disabled` | Client → gateway with ordinary audit enabled, content evidence disabled → provider |
| `metadata` | Same gateway, metadata evidence capture enabled |
| `full` | Same gateway, encrypted content evidence enabled |

Each gateway cell starts a fresh private instance in a separate process. It uses the actual `server.New` router, application authentication, connection/model grant, gateway forwarding, audit and evidence stores. The executable is a developer harness, **not the shipped `cmd/govweave` binary**: configuration and lifecycle setup differ. It adds no production diagnostics endpoint or runtime flag.

The application has one connection and a request credential policy in `observe` mode with `private_key` and `api_key` rules. A fixed harmless user message is sent, with repeated ASCII output of the selected size. All gateway requests declare the same synthetic trace ID; upstream requests must not receive that header. Output protection is disabled because protected streaming is currently rejected. There are no registered products, installed rule packs, tool executions, semantic-model checks or active assessments in this workload.

The provider verifies request routing, synthetic authentication, model mapping and content. JSON returns one completion. SSE flushes 16 data frames and `[DONE]` without token pacing. The client checks status and exact response bytes, including the complete SSE terminator. Output size means text bytes; the JSON/SSE envelope is additional and `response_bytes` records its actual size.

The worker inherits only a small environment allowlist, with `GOGC=100`, `GOMEMLIMIT=off` and the selected `GOMAXPROCS`. It receives synthetic credentials over private pipes. Parent provider/client CPU and heap do not appear in child counters, although both processes still compete for the same machine. Normal completion, failure and handled interruption stop children and remove their temporary instance data. A forced process kill or machine crash can leave temporary directories; no secure-erasure claim is made.

## Measurement and evidence boundaries

1. Run warmups and wait for their gateway handlers to finish.
2. Snapshot gateway resource counters without forcing GC.
3. Start fixed-concurrency clients and retain each measured attempt's status, error category, response byte count, first body byte time and completion time.
4. After clients finish, wait for gateway handlers, including final audit/capture writes, then take the ending resource snapshot and send a drained acknowledgement.
5. Outside the timed window, shut down HTTP and read back audit records and encrypted evidence. Check paired start/finish records, successful terminal status, exact capture counts, content retention state, and completed SSE manifests. Remove instance data after child exit.

`client_batch_elapsed_ms` ends when client workers finish. `client_start_to_drained_ack_ms` includes the acknowledgement; `verified_successes_per_durable_second` is populated only after the subsequent verification passes. These are distinct from the child resource interval. `gateway_drain_ms` measures only the wait after the finish command, so it is **not** total persistence time. Read-back verification establishes recoverable files at that point, not survival of power loss or the complete disaster-recovery lifecycle.

Per-request latency begins at request construction and ends after body read, or on failure. Byte comparison is outside that timer; client batch throughput includes validation work. Both the direct and gateway paths use the same client. First body byte is a client observation, not model time-to-first-token. The closed-loop client sends its next request after completing the previous one: it does not model independent arrival rates, long queues or coordinated omission under production saturation.

`gateway_resources` contains process user/system CPU deltas, average CPU cores, endpoint heap sizes, allocations, GC count, GC pause delta and Go GC CPU estimates. Peak RSS is a **process-lifetime high-water mark**, including setup and warmup; it is not a timed-window peak. Resource snapshots and control messages add small measurement overhead. Go's estimated GC CPU counters are explicitly not comparable with OS CPU; do not divide them by process CPU to claim a GC percentage. See the official [runtime metric definitions](https://pkg.go.dev/runtime/metrics).

## Read the report

The [JSON schema](../schemas/gateway-benchmark.schema.json) describes `gateway-load-v1`. JSON is canonical; Markdown is a human-readable view. Each completed cell checkpoints both files. A crash between the two replacements may leave older Markdown. A handled interruption records `state: failed` and `failed_cell`, preserving previously completed cells. The unfinished cell is excluded from `results`, not counted as successful. Abrupt termination can leave the last checkpoint with `state: running`.

- `all_attempt_latency` includes failures; `success_latency` and `success_first_body_latency` include only successful attempts. Empty distributions are `null`. Failures and warmup failures are separate counters.
- Percentiles use nearest rank. `p99_is_max_rank` identifies small samples where P99 is the maximum. Repeating a synthetic input does not create independent customer workloads or a confidence interval.
- `comparisons` subtract matching direct percentiles from gateway percentiles in the same round, protocol, size and concurrency. These are distribution differences, not paired request overhead. Negative differences are retained. Any failed client, provider or durability check suppresses the comparison.
- Binary SHA-256 identifies the executable. Source hashes identify on-disk Go sources, embedded assets and `go.mod` at run start; they do not prove correspondence with the executable. Available VCS/build settings are recorded, including dirty state. No arbitrary compiler arguments or environment values are reported.
- Exit 0 means all cells completed and functional/count checks passed; it is not a latency SLO. Exit 2 means invalid options or completed cells with errors. Exit 1 means initialization, execution, interruption or report-writing failure.

Compare like-for-like workloads across rounds. Use end-to-end latency, CPU, GC, allocations and persistence observations to choose a targeted profiling experiment. A high latency with low CPU does not on its own identify disk, locking or scheduling as the cause. This harness does not measure WAN/TLS, multi-instance behavior, long-running memory growth, real inference or broader policy evaluation. A language rewrite needs additional evidence beyond this local baseline.

`gc_stopping` and `gc_total_pause` retain timed-window deltas of runtime GC pause histograms. Stopping is the wait from deciding to pause until all processors stop; it is a subset of total pause, so do not add them. Reports retain nonzero buckets, event counts and cumulative lower/upper duration bounds in milliseconds (exclusive upper bounds), rather than inventing exact durations. Infinite upper bounds are `null`; unavailable deltas are omitted. Events are not GC cycles. MemStats and histogram snapshots are adjacent rather than atomic and need not match exactly.

## Verify the harness

### Optional diagnostics

Collect one type of profile at a time in an isolated synthetic run:

```bash
make benchmark-gateway GATEWAY_BENCH_ARGS='-requests 128 -warmup 16 -rounds 1 -concurrency 8 -sizes 16384 -protocols json -profile contention'
```

Replace `contention` with `cpu`, `trace` or `allocs` for CPU sampling, execution traces or allocation snapshots. Each diagnostic matrix is limited to eight cells. Gateway child profiles begin after warmup and stop after the ending resource sample/acknowledgement; serialization is outside the measured resource window. Contention mode collects all block/mutex events (`SetBlockProfileRate(1)` and `SetMutexProfileFraction(1)`); it deliberately adds overhead. CPU uses the runtime's default sampling. Runtime traces include GC, scheduling and blocking events. `allocs` saves cumulative allocation profiles before and after measurement at the default runtime sampling rate without forcing GC; samples may lag by up to two GC cycles, and the difference can include initial profile serialization overhead. These modes are **diagnostic, not performance baselines**; direct percentile comparisons are suppressed, while functional/audit/evidence checks still apply.

Reports list relative paths, lengths and SHA-256 digests for private files under `profiles/cell-NNN/`. Each file is capped at 32 MiB; exceeding a cap fails that cell. CPU emits `cpu.pprof`, contention emits `block.pprof` and `mutex.pprof`, trace emits `runtime.trace`, and allocs emits `allocs-before.pprof` and `allocs-after.pprof`. Incomplete writes use `.partial` names and are not listed as completed artifacts. Profile directories are private, reject existing content and are retained with the report; temporary gateway instance data is still removed. Stacks and runtime events can contain source paths and symbols, but no request payload dumping or custom content labels are added. When tracing is explicitly active, critical audit/evidence file and directory sync calls emit the fixed `govweave.file_sync` region; caller stacks distinguish sources without path or content labels. Sync retains the existing `os.File.Sync` semantics. There is no production profiling endpoint.

Use the exact artifact paths shown in the report:

```bash
go tool pprof -top /path/to/cpu.pprof
go tool pprof -top -cum /path/to/block.pprof
go tool pprof -top -cum /path/to/mutex.pprof
go tool trace /path/to/runtime.trace
go tool pprof -top -alloc_space -base /path/to/allocs-before.pprof /path/to/allocs-after.pprof
```

Block/mutex values sum waiting time across goroutines; overlapping waits can exceed elapsed time. Mutex profiles attribute contention to the holder's unlock stack, while block profiles show blocked callers. They cannot be added to CPU or wall time as independent percentages. Short CPU runs may have few samples. GC pauses can include runtime coordination costs; these files alone do not justify attributing all pause time to object scanning. Follow the official [Go diagnostic guidance](https://go.dev/doc/diagnostics) and [profile semantics](https://pkg.go.dev/runtime/pprof).

The targeted improvements separate configuration reads from vault writes and move independent immutable-file persistence outside the index lock, with at most two concurrent writers. Each capture reserves its ID, count and sealed bytes under the lock before waiting for a writer slot; successful file/directory synchronization is still required before index publication. Uncertain failed writes keep conservative reservations until restart. New configurations become visible only after authorized access logging and config persistence succeed; already-started requests retain their frozen settings. Tests cover independent progress, the writer bound, hidden in-flight files, duplicate IDs, count/byte limits, failed writes and restart recovery. Audit gates, encryption and privileged-content access checks retain their existing semantics. See [risk evidence](risk-evidence.md). Write batching or asynchronous persistence would require separate durability/admission design and validation.


Evidence encoding uses an owned buffer and in-place encryption to avoid copying complete payloads and allocating a separate ciphertext buffer. Raw JSON/SSE is borrowed only during synchronous serialization; file I/O receives independent sealed bytes. Caller buffers are neither modified nor retained in the index. The nonce/ciphertext/tag format remains compatible with existing files. Tests cover unchanged inputs, source mutation before disk writes without changing retained content, and restart reads.

### Local investigation (2026-11-02)

Two alternating before/after pairs on Go 1.25.2, macOS arm64, concurrency 8 and 16 KiB output reduced full-evidence allocation by about 30% for JSON and 21%–22% for SSE. All 4,096 measured requests across 32 cells succeeded; including warmup, 3,456 successful gateway audits and 2,304 captures were verified. Tail latency and durable throughput changed in both directions, so stable improvement is not established. Evidence-disabled controls also varied substantially.

In separate diagnostics, pause histograms placed most GC pause duration in stopping coordination. Sixteen of 20 GC pauses in the full-evidence trace included preemption stacks at `internal/poll.(*FD).Fsync`. Together with inspection of the installed Go Darwin `F_FULLFSYNC` call path, this supports a sync/runtime coordination hypothesis, not independent causal proof. Trace regions also include scheduling/GC waits and are not pure disk-service time.

Raw reports, regressions, source/binary hashes and timestamp analysis are retained in the ignored `dist/gateway-benchmark/2026-11-02-allocation-ab/` directory and adjacent diagnostic directories. At that point the Docker daemon was not running; neither Linux nor another Go version had been tested. The local toolchain also differs from the Dockerfile Go 1.26.9 pin. Repeat in the intended deployment environment before selecting a further persistence optimization.

### Linux follow-up (2026-11-02)

The follow-up ran two alternating A/B pairs per toolchain on Docker Desktop Linux/arm64: Go 1.25.2 and deployment-pinned 1.26.9. All 8,192 measured requests across 64 normal cells succeeded; including warmup, 6,912 successful gateway audits and 4,608 captures were read back. Eight separate diagnostic trace cells also completed.

Full-evidence after-change Go 1.25.2 Linux cells accumulated about 1.94–2.19 ms of GC pauses, rather than the earlier macOS 219–315 ms. Both Linux traces showed all 512 sync regions entering syscall state at Fsync; the macOS trace showed zero. This strengthens the local sync/runtime coordination explanation, but virtual disks, CPU quotas and background workloads also differ: it is not a single-factor causal experiment.

The four full-evidence A/B comparisons on Go 1.26.9 reduced allocations by about 22%–41%, P95 by 11%–53% (after-change P95 around 18 ms), and improved durable throughput by 10%–29%. Older-toolchain SSE comparisons still regressed, including one large outlier. All controls and negative results are retained under `dist/gateway-benchmark/2026-11-02-linux-investigation/`. The full Go 1.26.9 Linux race suite and Docker isolation/readback/cleanup acceptance passed. Seventeen other containers were running; these measurements are not production capacity or an SLA.

### Tests

```bash
make build-gateway-bench
go test -race ./internal/gatewaybench
python3 tests/gateway-bench-test.py
```

Go tests cover matrix bounds/order, failure denominators, quantiles, invalid comparisons, full JSON/SSE reads, bad responses/timeouts, failure checkpoints histogram bounds/snapshot isolation and bounded profile publication. The standard-library Python acceptance runs the actual executable through 16 normal cells, four contention cells and four allocs cells, checks audit/capture/resource counters, private reports/profile hashes and diagnostic comparison suppression, rejects overwrites and verifies interrupted-child cleanup. The benchmark itself should use a normal build without race instrumentation.
