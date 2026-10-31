// sensitive-eval scores frozen authored fixtures and measures local detector calls.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"govweave/internal/sensitiveeval"
)

func ratio(value *float64) string {
	if value == nil {
		return "undefined"
	}
	return fmt.Sprintf("%.2f%%", *value*100)
}

func save(parent string, report sensitiveeval.Report) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil || len(data) > 8<<20 {
		return "", errors.New("could not encode bounded report")
	}
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", errors.New("could not create output directory")
	}
	dir, err := os.MkdirTemp(parent, "eval-")
	if err != nil {
		return "", errors.New("could not create private report directory")
	}
	path := filepath.Join(dir, "report.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", errors.New("could not create private report")
	}
	_, writeErr := file.Write(append(data, '\n'))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return "", errors.New("could not persist report")
	}
	return filepath.Abs(path)
}

func run() error {
	version := flag.String("detector", "sensitive-text-v1", "immutable detector version: sensitive-text-v1, sensitive-text-v2 or sensitive-text-v3")
	corpusPath := flag.String("corpus", "tests/testdata/sensitive-validation-v1.json", "frozen synthetic corpus")
	output := flag.String("output", "dist/sensitive-validation", "parent directory for a new private report")
	repetitions := flag.Int("repetitions", 100, "timing repetitions per case (1–1000; total work capped at 100000 calls)")
	warmups := flag.Int("warmups", 2, "warmup repetitions per case (0–10)")
	seed := flag.Int64("seed", 20261028, "reproducible timing-order shuffle seed")
	timeout := flag.Duration("timeout", 30*time.Second, "maximum cooperative measurement duration (positive, at most 60s)")
	flag.Parse()
	if flag.NArg() != 0 || *timeout <= 0 || *timeout > time.Minute {
		return errors.New("invalid arguments or timeout")
	}
	file, err := os.Open(*corpusPath)
	if err != nil {
		return errors.New("could not open corpus")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > sensitiveeval.MaxCorpusBytes {
		return errors.New("corpus must be a regular file at most 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, sensitiveeval.MaxCorpusBytes+1))
	if err != nil {
		return errors.New("could not read bounded corpus")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report, measureErr := sensitiveeval.Evaluate(ctx, data, sensitiveeval.Options{DetectorVersion: *version, Repetitions: *repetitions, Warmups: *warmups, Seed: *seed})
	if report.SchemaVersion == 0 {
		return measureErr
	}
	path, err := save(*output, report)
	if err != nil {
		return err
	}
	fmt.Printf("Measurement %s: %d/%d cases, %d invalid inputs, %d boundary errors\n", report.State, len(report.Cases), report.ExpectedCases, report.InvalidCases, report.BoundaryErrors)
	for _, category := range []string{"credential", "email", "phone"} {
		score := report.Categories[category]
		fmt.Printf("%s: TP=%d FP=%d FN=%d TN=%d unknown=%d precision=%s recall=%s coverage=%s\n",
			category, score.TruePositives, score.FalsePositives, score.FalseNegatives, score.TrueNegatives, score.Unknown,
			ratio(score.Precision), ratio(score.Recall), ratio(score.DecisionCoverage))
	}
	if report.Timing.P99NS != nil {
		fmt.Printf("Local detector calls: %d/%d; P50=%.3f us P95=%.3f us P99=%.3f us\n", report.Timing.CompletedCalls, report.Timing.ExpectedCalls,
			float64(*report.Timing.P50NS)/1000, float64(*report.Timing.P95NS)/1000, float64(*report.Timing.P99NS)/1000)
	}
	fmt.Println("Synthetic category-presence baseline only; not production accuracy or end-to-end latency.")
	fmt.Println("Report:", path)
	if measureErr != nil {
		return errors.New("measurement incomplete; inspect retained report")
	}
	if report.BoundaryErrors != 0 {
		return errors.New("invalid input was treated as evaluable; inspect retained report")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sensitive-eval:", err)
		os.Exit(1)
	}
}
