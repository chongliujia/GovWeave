package gatewaybench

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
)

const profileLimit = 32 << 20

type ProfileArtifact struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func profileNames(mode string) []string {
	switch mode {
	case "cpu":
		return []string{"cpu.pprof"}
	case "contention":
		return []string{"block.pprof", "mutex.pprof"}
	case "trace":
		return []string{"runtime.trace"}
	case "allocs":
		return []string{"allocs-before.pprof", "allocs-after.pprof"}
	}
	return nil
}

type profileWriter struct {
	file  *os.File
	bytes int64
	err   error
}

func (w *profileWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if int64(len(data)) > profileLimit-w.bytes {
		w.err = errors.New("profile exceeds size budget")
		return 0, w.err
	}
	n, err := w.file.Write(data)
	w.bytes += int64(n)
	w.err = err
	return n, err
}

type profiles struct {
	mode         string
	dir          string
	writers      map[string]*profileWriter
	active       bool
	oldMutexRate int
}

func startProfiles(mode, dir string) (*profiles, error) {
	p := &profiles{mode: mode, dir: dir, writers: map[string]*profileWriter{}}
	if mode == "" && dir == "" {
		return p, nil
	}
	if len(profileNames(mode)) == 0 {
		return nil, errors.New("invalid profiling mode")
	}
	info, err := os.Lstat(dir)
	if err != nil || !filepath.IsAbs(dir) || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private profile directory required")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		return nil, errors.New("profile directory must be empty")
	}
	for _, name := range profileNames(mode) {
		f, err := os.OpenFile(filepath.Join(dir, name+".partial"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			p.abort()
			return nil, err
		}
		p.writers[name] = &profileWriter{file: f}
	}
	switch mode {
	case "cpu":
		err = pprof.StartCPUProfile(p.writers["cpu.pprof"])
	case "trace":
		err = trace.Start(p.writers["runtime.trace"])
	case "allocs":
		err = pprof.Lookup("allocs").WriteTo(p.writers["allocs-before.pprof"], 0)
	case "contention":
		runtime.SetBlockProfileRate(1)
		p.oldMutexRate = runtime.SetMutexProfileFraction(1)
	}
	if err != nil {
		p.abort()
		return nil, err
	}
	p.active = true
	return p, nil
}

func (p *profiles) stop() {
	if !p.active {
		return
	}
	switch p.mode {
	case "cpu":
		pprof.StopCPUProfile()
	case "trace":
		trace.Stop()
	case "contention":
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(p.oldMutexRate)
	}
	p.active = false
}

func (p *profiles) abort() {
	p.stop()
	for _, w := range p.writers {
		if w.file != nil {
			w.file.Close()
			w.file = nil
		}
	}
}

func (p *profiles) finish() error {
	p.stop()
	defer p.abort()
	if p.mode == "contention" {
		for _, name := range []string{"block", "mutex"} {
			if err := pprof.Lookup(name).WriteTo(p.writers[name+".pprof"], 0); err != nil {
				return err
			}
		}
	}
	if p.mode == "allocs" {
		if err := pprof.Lookup("allocs").WriteTo(p.writers["allocs-after.pprof"], 0); err != nil {
			return err
		}
	}
	for _, name := range profileNames(p.mode) {
		w := p.writers[name]
		if w.err != nil {
			return w.err
		}
		if err := w.file.Sync(); err != nil {
			return err
		}
		if err := w.file.Close(); err != nil {
			return err
		}
		w.file = nil
		if err := os.Rename(filepath.Join(p.dir, name+".partial"), filepath.Join(p.dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func profileArtifacts(root, dir, mode string) ([]ProfileArtifact, error) {
	result := []ProfileArtifact{}
	for _, name := range profileNames(mode) {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > profileLimit {
			return nil, errors.New("invalid profile artifact")
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, profileLimit+1))
		f.Close()
		if err != nil || n != info.Size() {
			return nil, errors.New("profile artifact read failed")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		result = append(result, ProfileArtifact{Kind: name, Path: filepath.ToSlash(rel), Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	return result, nil
}
