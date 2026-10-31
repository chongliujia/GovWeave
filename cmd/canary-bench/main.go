// canary-bench measures local detector cost and quality on frozen synthetic cases.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"govweave/internal/leakageeval"
)

func readCorpus(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > leakageeval.MaxCorpusBytes {
		return nil, errors.New("corpus must be a regular file of at most 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, leakageeval.MaxCorpusBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > leakageeval.MaxCorpusBytes {
		return nil, errors.New("corpus exceeds 1 MiB")
	}
	return data, nil
}

func executableDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	const maxBinaryBytes = 128 << 20
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBinaryBytes {
		return "", errors.New("cannot identify benchmark executable within 128 MiB limit")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maxBinaryBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxBinaryBytes {
		return "", errors.New("benchmark executable exceeds 128 MiB")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func saveReport(parent string, report any) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	if len(data) > 16<<20 {
		return "", errors.New("benchmark report exceeds 16 MiB")
	}
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(parent, "bench-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "report.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := f.Write(append(data, '\n'))
	closeErr := f.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return filepath.Abs(path)
}

func printReport(report leakageeval.BenchmarkReport) {
	fmt.Printf("Corpus %s (%s): %d unique cases; state=%s\n", report.CorpusID, report.CorpusVersion, report.Stages[0].Score.Cases, report.State)
	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "Stage\tWorkers\tTP\tFP\tFN\tUnknown\tCalls\tP50 us\tP95 us\tP99 us\tMax us")
	for _, stage := range report.Stages {
		for _, load := range report.Loads {
			for _, slice := range load.Slices {
				if slice.StageID != stage.Stage.ID || slice.Axis != "all" {
					continue
				}
				s, cost := stage.Score, slice.Latency
				fmt.Fprintf(table, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\t%.3f\n", stage.Stage.ID, load.Workers, s.TruePositives, s.FalsePositives, s.FalseNegatives, s.Unknown, cost.Calls, float64(cost.P50NS)/1000, float64(cost.P95NS)/1000, float64(cost.P99NS)/1000, float64(cost.MaxNS)/1000)
			}
		}
	}
	table.Flush()
	for _, stage := range report.Stages {
		if delta := stage.Transition; delta != nil {
			fmt.Printf("%s -> %s: added TP=%d lost TP=%d added FP=%d resolved FP=%d became unknown=%d resolved unknown=%d\n", delta.FromStage, stage.Stage.ID, len(delta.AddedTruePositiveIDs), len(delta.LostTruePositiveIDs), len(delta.AddedFalsePositiveIDs), len(delta.ResolvedFalsePositiveIDs), len(delta.BecameUnknownIDs), len(delta.ResolvedUnknownIDs))
		}
	}
	for _, load := range report.Loads {
		fmt.Printf("Workers=%d: %d measured mixed-stage calls, batch %.3fs, harness-inclusive %.1f calls/s\n", load.Workers, load.Calls, float64(load.BatchElapsedNS)/1e9, load.HarnessCallsPerSecond)
	}
	fmt.Println("Local warm detector-call timing excludes queue wait, network, audit and model work; it is not a production realtime SLA.")
	fmt.Println("Quality counts unique synthetic cases once; repeated timings do not increase quality sample size. Unknown positives are already counted in FN.")
}

func run() error {
	defaults := leakageeval.DefaultBenchmarkOptions()
	corpus := flag.String("corpus", "tests/testdata/canary-validation-v1.json", "frozen labelled synthetic corpus")
	output := flag.String("output-dir", "", "parent directory for a new private report (default dist/canary-benchmark or dist/canary-routing)")
	routing := flag.Bool("routing", false, "compare frozen offline routing policies through the detector registry")
	repetitions := flag.Int("repetitions", defaults.Repetitions, "timed repetitions per case/stage in each round (1..2000)")
	warmup := flag.Int("warmup", defaults.WarmupPasses, "untimed warmup passes per round (0..20)")
	trials := flag.Int("trials", defaults.Trials, "trials with alternating worker-mode order (1..5)")
	workers := flag.String("workers", "1,2", "distinct worker modes selected from 1 and 2")
	seed := flag.Int64("seed", defaults.Seed, "sample/stage shuffle seed")
	timeout := flag.Duration("timeout", 60*time.Second, "benchmark timeout, at most 5m; incomplete reports exit nonzero")
	flag.Parse()
	if flag.NArg() != 0 || *timeout <= 0 || *timeout > 5*time.Minute {
		return errors.New("unexpected arguments or timeout outside (0, 5m]")
	}
	if *output == "" {
		*output = "dist/canary-benchmark"
		if *routing {
			*output = "dist/canary-routing"
		}
	}
	options := leakageeval.BenchmarkOptions{Repetitions: *repetitions, WarmupPasses: *warmup, Trials: *trials, Seed: *seed}
	for _, value := range strings.Split(*workers, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return errors.New("invalid worker modes; use 1,2")
		}
		options.Workers = append(options.Workers, n)
	}
	data, err := readCorpus(*corpus)
	if err != nil {
		return err
	}
	digest, err := executableDigest()
	if err != nil {
		return err
	}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signals, *timeout)
	defer cancel()
	if *routing {
		return runRouting(ctx, data, options, digest, *output)
	}
	report, benchmarkErr := leakageeval.Benchmark(ctx, data, options)
	if report.BenchmarkVersion == "" {
		return benchmarkErr
	}
	report.ExecutableSHA256 = digest
	path, err := saveReport(*output, report)
	if err != nil {
		return err
	}
	printReport(report)
	fmt.Println("Report:", path)
	if benchmarkErr != nil {
		return fmt.Errorf("incomplete measurement saved: %w", benchmarkErr)
	}
	for _, stage := range report.Stages {
		if stage.Score.BoundaryErrors != 0 {
			return errors.New("stage did not abstain on ineligible labelled cases; inspect report")
		}
	}
	return nil
}

func runRouting(ctx context.Context, data []byte, options leakageeval.BenchmarkOptions, digest, output string) error {
	report, benchmarkErr := leakageeval.BenchmarkRouting(ctx, data, options)
	if report.BenchmarkVersion == "" {
		return benchmarkErr
	}
	report.ExecutableSHA256 = digest
	path, err := saveReport(output, report)
	if err != nil {
		return err
	}
	fmt.Printf("Routing corpus %s (%s): %d unique cases; state=%s\n", report.CorpusID, report.CorpusVersion, report.Policies[0].Score.Cases, report.State)
	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "Policy\tWorkers\tTP\tFP\tFN\tUnknown\tDeep eval/unique\tTimed calls\tP50 us\tP95 us\tP99 us\tMax us")
	for _, quality := range report.Policies {
		for _, load := range report.Loads {
			for _, slice := range load.Slices {
				if slice.PolicyID != quality.Policy.ID || slice.Axis != "all" {
					continue
				}
				s, cost := quality.Score, slice.Latency
				fmt.Fprintf(table, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\t%.3f\n", quality.Policy.ID, load.Workers, s.TruePositives, s.FalsePositives, s.FalseNegatives, s.Unknown, quality.DeepEvaluations, cost.Calls, float64(cost.P50NS)/1000, float64(cost.P95NS)/1000, float64(cost.P99NS)/1000, float64(cost.MaxNS)/1000)
			}
		}
	}
	table.Flush()
	for _, quality := range report.Policies {
		fmt.Printf("%s: unique-case decision coverage=%s, routes=%v\n", quality.Policy.ID, percent(quality.Score.DecisionCoverage), quality.Routes)
	}
	fmt.Println("Gate-skipped deep checks remain unknown. The full-depth reference is a comparator, not ground truth; compare labelled scores and transitions in the report.")
	fmt.Println("Pipeline timing includes registry checks, hashes/copies, fast checks, gates and deep checks; it excludes queue wait, network, audit and models. Offline replay executes the reference too.")
	fmt.Println("Report:", path)
	if benchmarkErr != nil {
		return fmt.Errorf("incomplete routing measurement saved: %w", benchmarkErr)
	}
	for _, quality := range report.Policies {
		if quality.Score.BoundaryErrors != 0 {
			return errors.New("routing policy did not abstain on ineligible labelled cases; inspect report")
		}
	}
	return nil
}

func percent(value *float64) string {
	if value == nil {
		return "undefined"
	}
	return fmt.Sprintf("%.2f%%", 100**value)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "canary-bench:", err)
		os.Exit(1)
	}
}
