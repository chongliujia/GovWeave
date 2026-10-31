package main

import (
	"os"
	"path/filepath"
	"testing"

	"govweave/internal/sensitiveeval"
)

func TestReportsArePrivateAndNeverOverwrite(t *testing.T) {
	parent := t.TempDir()
	report := sensitiveeval.Report{SchemaVersion: 1, State: "incomplete"}
	first, err := save(parent, report)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := save(parent, report)
	if err != nil || first == second {
		t.Fatal("fresh report directory not created", err)
	}
	current, _ := os.ReadFile(first)
	if string(current) != string(original) {
		t.Fatal("existing measurement overwritten")
	}
	for _, path := range []string{first, second} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("report is not private")
		}
		info, err = os.Stat(filepath.Dir(path))
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("report directory is not private")
		}
	}
}
