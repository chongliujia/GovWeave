package gatewaybench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"govweave/internal/storage"
)

// WriteReport checkpoints a metadata-only report in a caller-created private
// directory. JSON is canonical; a crash between replacements may leave an older
// Markdown view. Source identities and individual timings remain in JSON.
func WriteReport(dir string, report Report) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("report directory must be private")
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := storage.AtomicWrite(filepath.Join(dir, "report.json"), append(data, '\n')); err != nil {
		return err
	}
	return storage.AtomicWrite(filepath.Join(dir, "report.md"), []byte(markdown(report)))
}

func markdown(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Synthetic gateway load benchmark\n\nState: **%s**. Completed cells: %d/%d. Created: %s.\n\n", report.State, len(report.Results), report.PlannedCells, report.CreatedAt)
	if report.Failure != "" {
		fmt.Fprintf(&b, "Failure: `%s`. The interrupted cell is identified in JSON and is excluded from completed results.\n\n", report.Failure)
	}
	fmt.Fprintf(&b, "Environment: %s, %s/%s, %d logical CPUs; gateway GOMAXPROCS=%d, GOGC=100, GOMEMLIMIT=off.\n\n", report.GoVersion, report.OS, report.Architecture, report.LogicalCPUs, report.Options.GoMaxProcs)
	fmt.Fprintf(&b, "Per cell: %d measured requests, %d warmups. Rounds: %d. Synthetic provider delay: %d ms. Seed: %d.\n\n", report.Options.Requests, report.Options.Warmup, report.Options.Rounds, report.Options.DelayMS, report.Options.Seed)
	if report.Options.Profile != "" {
		fmt.Fprintf(&b, "**Diagnostic profiling: %s. Timings include instrumentation overhead; direct percentile differences are disabled.**\n\n", report.Options.Profile)
	}
	fmt.Fprintf(&b, "Binary SHA-256: `%s`. Source hashes, raw per-attempt timings, build settings and all counters are in [report.json](report.json).\n\n", report.BinarySHA256)
	b.WriteString("## Completed cells\n\nLatency is successful-response completion in milliseconds. RPS is successful responses divided by the client batch interval. CPU is gateway user + system CPU in milliseconds; RSS is the process-lifetime high-water mark in MiB. Direct rows have no gateway process. A `yes` check requires zero client/warmup failures, exact provider call counts, and (for gateway rows) successful audit/capture read-back. It is not a latency acceptance threshold.\n\n")
	b.WriteString("| Index | Round | Protocol | Text bytes | Concurrency | Mode | Success / attempts | P95 ms | P99 ms | Client RPS | CPU ms | GC pause ms | RSS MiB | Checks |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for i, r := range report.Results {
		p95, p99, cpu, gc, rss := "—", "—", "—", "—", "—"
		if r.SuccessLatency != nil {
			p95, p99 = fmt.Sprintf("%.3f", r.SuccessLatency.P95MS), fmt.Sprintf("%.3f", r.SuccessLatency.P99MS)
		}
		if r.Resources != nil {
			cpu, gc, rss = fmt.Sprintf("%.3f", r.Resources.UserCPUMS+r.Resources.SystemCPUMS), fmt.Sprintf("%.3f", r.Resources.GCPauseMS), fmt.Sprintf("%.2f", float64(r.Resources.PeakRSS)/(1<<20))
		}
		check := "no"
		if comparable(r) {
			check = "yes"
		}
		fmt.Fprintf(&b, "| %d | %d | %s | %d | %d | %s | %d / %d | %s | %s | %.1f | %s | %s | %s | %s |\n", i, r.Round, r.Protocol, r.OutputBytes, r.Concurrency, r.Mode, r.Succeeded, len(r.Samples), p95, p99, r.SucceededPerSec, cpu, gc, rss, check)
	}
	b.WriteString("\n## GC pause phases\n\nCumulative bounds from runtime histogram buckets, in milliseconds. Stopping waits for all processors to stop and is a subset of total pause; do not add them. Upper bounds are exclusive. Counts are pause events, not GC cycles. MemStats and histogram snapshots are adjacent, not atomic.\n\n| Index | Mode | Stopping events | Stopping bounds ms | Total pause events | Total pause bounds ms |\n| --- | --- | --- | --- | --- | --- |\n")
	for i, r := range report.Results {
		if r.Resources == nil || r.Resources.GCStopping == nil || r.Resources.GCTotalPause == nil {
			continue
		}
		s, total := r.Resources.GCStopping, r.Resources.GCTotalPause
		fmt.Fprintf(&b, "| %d | %s | %d | %s | %d | %s |\n", i, r.Mode, s.Count, pauseBounds(s), total.Count, pauseBounds(total))
	}
	b.WriteString("\n## Matched direct comparisons\n\nGateway percentile minus direct percentile for the same round, protocol, size and concurrency. These are distribution differences, not paired request overhead. Negative values are retained. Any failed check suppresses differences. No averaging across unlike workloads.\n\n| Gateway index | Direct index | P50 difference ms | P95 difference ms | P99 difference ms | First body P95 difference ms |\n| --- | --- | --- | --- | --- | --- |\n")
	value := func(v *float64) string {
		if v == nil {
			return "unavailable"
		}
		return fmt.Sprintf("%+.3f", *v)
	}
	for _, c := range report.Comparisons {
		fmt.Fprintf(&b, "| %d | %d | %s | %s | %s | %s |\n", c.GatewayIndex, c.DirectIndex, value(c.P50DeltaMS), value(c.P95DeltaMS), value(c.P99DeltaMS), value(c.FirstP95MS))
	}
	if report.Options.Profile != "" {
		b.WriteString("\n## Diagnostic artifacts\n\nProfiles cover only gateway children after warmup, including the small ending snapshot/acknowledgement boundary. Mutex/block samples accumulate goroutine waiting time and cannot be added to wall time or CPU. Interrupted cells may leave unlisted partial files.\n\n")
		for i, r := range report.Results {
			for _, p := range r.Profiles {
				fmt.Fprintf(&b, "- Cell %d (%s): [%s](%s), %d bytes, SHA-256 `%s`\n", i, r.Mode, p.Kind, p.Path, p.Bytes, p.SHA256)
			}
		}
	}
	b.WriteString("\n## Interpretation limits\n\n")
	for _, limit := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", limit)
	}
	return b.String()
}

func pauseBounds(h *PauseHistogram) string {
	if h.TotalUpperMS == nil {
		return fmt.Sprintf("%.3f–unbounded", h.TotalLowerMS)
	}
	return fmt.Sprintf("%.3f–%.3f", h.TotalLowerMS, *h.TotalUpperMS)
}
