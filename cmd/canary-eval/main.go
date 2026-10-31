// canary-eval measures a bounded detector against authored, labelled fixtures.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"govweave/internal/leakage"
	"govweave/internal/leakageeval"
)

func percent(value *float64) string {
	if value == nil {
		return "undefined"
	}
	return fmt.Sprintf("%.2f%%", 100**value)
}

func run() error {
	corpus := flag.String("corpus", "tests/testdata/canary-validation-v1.json", "frozen labelled synthetic corpus")
	output := flag.String("output-dir", "dist/canary-validation", "parent directory for a new private measurement report")
	version := flag.String("detector", leakage.Version, "versioned detector; v2 reports include the unchanged v1 on the same cases")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	f, err := os.Open(*corpus)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > leakageeval.MaxCorpusBytes {
		return errors.New("corpus must be a regular file of at most 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, leakageeval.MaxCorpusBytes+1))
	if err != nil {
		return err
	}
	report, err := leakageeval.EvaluateVersion(data, *version)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*output, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(*output, "eval-")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "report.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(report)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	if closeErr != nil {
		return closeErr
	}
	s := report.Aggregate.Detector
	b := report.Aggregate.LiteralBaseline
	fmt.Printf("Synthetic cases: %d; complete marker exposures: %d; negatives: %d\n", s.Cases, s.Positives, s.Negatives)
	fmt.Printf("Detector %s: TP=%d FP=%d FN=%d TN=%d unknown=%d\n", report.DetectorVersion, s.TruePositives, s.FalsePositives, s.FalseNegatives, s.TrueNegatives, s.Unknown)
	fmt.Printf("Precision=%s Recall=%s FPR=%s Labelled-input decision coverage=%s\n", percent(s.Precision), percent(s.Recall), percent(s.FalsePositiveRate), percent(s.DecisionCoverage))
	if previous := report.Aggregate.PreviousDetector; previous != nil {
		fmt.Printf("Previous %s: recall=%s FPR=%s unknown=%d labelled-input coverage=%s\n", report.PreviousDetectorVersion, percent(previous.Recall), percent(previous.FalsePositiveRate), previous.Unknown, percent(previous.DecisionCoverage))
	}
	fmt.Printf("Literal baseline recall=%s; unresolved exposure cases=%v\n", percent(b.Recall), report.FalseNegativeIDs)
	fmt.Println("Authored synthetic corpus only; real-model effectiveness is unvalidated.")
	absolute, _ := filepath.Abs(path)
	fmt.Println("Report:", absolute)
	if s.BoundaryErrors != 0 {
		return errors.New("detector did not abstain on ineligible inputs; inspect report")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "canary-eval:", err)
		os.Exit(1)
	}
}
