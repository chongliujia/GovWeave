package gatewaybench

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileLimitsAndPublication(t *testing.T) {
	o := testOptions()
	o.Profile = "contention"
	if o.Validate() == nil {
		t.Fatal("large diagnostic matrix accepted")
	}
	o.Rounds, o.Concurrency, o.Protocols = 1, []int{1}, []string{"json"}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "profiles")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := startProfiles("contention", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer p.abort()
	if err := p.finish(); err != nil {
		t.Fatal(err)
	}
	artifacts, err := profileArtifacts(root, dir, "contention")
	if err != nil || len(artifacts) != 2 {
		t.Fatal("profiles unavailable", err)
	}
	for _, artifact := range artifacts {
		f, err := os.Open(filepath.Join(root, artifact.Path))
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		data, err := io.ReadAll(gz)
		gz.Close()
		f.Close()
		if err != nil || len(data) == 0 || len(artifact.SHA256) != 64 {
			t.Fatal("invalid profile serialization")
		}
	}
	if _, err := startProfiles("contention", dir); err == nil {
		t.Fatal("existing artifacts would be overwritten")
	}
	f, err := os.CreateTemp(root, "limit")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := &profileWriter{file: f, bytes: profileLimit - 1}
	if n, err := w.Write([]byte{1, 2}); n != 0 || err == nil {
		t.Fatal("profile limit exceeded")
	}
	if n, err := w.Write([]byte{1}); n != 0 || err == nil {
		t.Fatal("profile failure was not sticky")
	}
}

func TestDiagnosticComparisonSuppressed(t *testing.T) {
	direct := Result{Cell: Cell{Mode: "direct"}, Samples: []Sample{{ElapsedMS: 1, FirstBodyMS: .5}}, ElapsedMS: 1, ProviderCountMatches: true}
	summarizeResult(&direct)
	gateway := direct
	gateway.Mode, gateway.Resources, gateway.Verification = "full", &ResourceWindow{}, &Verification{Passed: true}
	gateway.Profiles = []ProfileArtifact{{Kind: "cpu.pprof"}}
	if !comparable(gateway) {
		t.Fatal("profiling must not alter functional verification")
	}
	c := comparisons([]Result{direct, gateway})[0]
	if c.Comparable || c.P95DeltaMS != nil {
		t.Fatal("instrumented/direct timings compared")
	}
}
