// gateway-bench runs bounded, synthetic local HTTP experiments without model keys.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"govweave/internal/gatewaybench"
)

func integers(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	if len(parts) > 64 {
		return nil, fmt.Errorf("too many matrix values")
	}
	values := make([]int, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("invalid matrix value")
		}
		values[i] = n
	}
	return values, nil
}

func run() int {
	if len(os.Args) == 2 && os.Args[1] == "--worker" {
		if gatewaybench.Worker(os.Stdin, os.Stdout) != nil {
			return 1
		}
		return 0
	}
	var o gatewaybench.Options
	flag.IntVar(&o.Requests, "requests", 128, "measured requests per cell (1..512)")
	flag.IntVar(&o.Warmup, "warmup", 16, "warmup requests per cell (1..64)")
	flag.IntVar(&o.Rounds, "rounds", 3, "matched rounds (1..5)")
	concurrency := flag.String("concurrency", "1,8,32", "distinct concurrent clients (1..128)")
	sizes := flag.String("sizes", "1024,16384", "distinct output text sizes in bytes (128..32768)")
	protocols := flag.String("protocols", "json,sse", "json,sse or one of these")
	flag.IntVar(&o.DelayMS, "provider-delay-ms", 0, "synthetic provider delay before output (0..100)")
	flag.IntVar(&o.GoMaxProcs, "gomaxprocs", min(4, runtime.NumCPU()), "gateway process GOMAXPROCS (1..128)")
	flag.Int64Var(&o.Seed, "seed", 20261031, "workload order seed")
	flag.StringVar(&o.Profile, "profile", "", "diagnostic mode: cpu, contention, trace or allocs (at most 8 cells; timings include profiling overhead)")
	out := flag.String("out", "", "new private report directory (default dist/gateway-benchmark/<UTC timestamp>)")
	root := flag.String("source-root", ".", "source checkout for file identity hashes")
	flag.Parse()
	var err error
	o.Concurrency, err = integers(*concurrency)
	if err == nil {
		o.Sizes, err = integers(*sizes)
	}
	o.Protocols = strings.Split(*protocols, ",")
	if err == nil {
		err = o.Validate()
	}
	if err != nil || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Invalid benchmark options; use -help for bounds (at most 256 cells).")
		return 2
	}
	if *out == "" {
		*out = filepath.Join("dist", "gateway-benchmark", time.Now().UTC().Format("20060102T150405.000000000Z"))
	}
	dir, err := filepath.Abs(*out)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(dir), 0700)
	}
	if err == nil {
		err = os.Mkdir(dir, 0700)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot create report directory; it must not already exist.")
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot identify benchmark executable.")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	last := -1
	report, err := gatewaybench.Run(ctx, executable, *root, dir, o, func(r gatewaybench.Report) error {
		if err := gatewaybench.WriteReport(dir, r); err != nil {
			return err
		}
		if len(r.Results) != last {
			last = len(r.Results)
			fmt.Printf("Completed %d/%d cells\n", last, r.PlannedCells)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Benchmark initialization or report write failed; verify source-root, platform and directory access.")
		return 1
	}
	fmt.Printf("State: %s\nReport: %s\n", report.State, filepath.Join(dir, "report.md"))
	if report.State == "failed" {
		fmt.Fprintln(os.Stderr, "Benchmark stopped:", report.Failure)
		return 1
	}
	if report.State != "completed" {
		return 2
	}
	return 0
}

func main() { os.Exit(run()) }
