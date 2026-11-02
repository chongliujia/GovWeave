package gatewaybench

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"govweave/internal/auth"
	"govweave/internal/compliance"
	"govweave/internal/config"
	"govweave/internal/gateway"
	"govweave/internal/governance"
	"govweave/internal/instance"
	"govweave/internal/server"
)

type workerConfig struct {
	Directory   string `json:"directory"`
	ProviderURL string `json:"provider_url"`
	ProviderKey string `json:"provider_key"`
	Mode        string `json:"mode"`
	GoMaxProcs  int    `json:"gomaxprocs"`
	Profile     string `json:"profile,omitempty"`
	ProfileDir  string `json:"profile_directory,omitempty"`
}

type control struct {
	Operation string `json:"operation"`
	Expected  int    `json:"expected_calls"`
}

type workerReply struct {
	State        string          `json:"state"`
	URL          string          `json:"url,omitempty"`
	Key          string          `json:"key,omitempty"`
	Resources    *ResourceWindow `json:"resources,omitempty"`
	Verification *Verification   `json:"verification,omitempty"`
	DrainMS      float64         `json:"drain_ms,omitempty"`
}

func readMessage(scanner *bufio.Scanner, value any) error {
	if !scanner.Scan() {
		return errors.New("benchmark control input ended")
	}
	return config.DecodeStrict(strings.NewReader(scanner.Text()), value)
}

func localProvider(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "" && u.Path == "/v1" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// Worker exposes metrics only over its inherited pipes. No diagnostics routes
// or production server flags are added. All measured requests use server.New.
func Worker(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var setup workerConfig
	if readMessage(scanner, &setup) != nil || !localProvider(setup.ProviderURL) || setup.ProviderKey == "" || len(setup.ProviderKey) > 128 || setup.GoMaxProcs < 1 || setup.GoMaxProcs > 128 || setup.Mode != "disabled" && setup.Mode != "metadata" && setup.Mode != "full" {
		return errors.New("invalid benchmark worker configuration")
	}
	info, err := os.Lstat(setup.Directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || !filepath.IsAbs(setup.Directory) {
		return errors.New("private benchmark directory required")
	}
	runtime.GOMAXPROCS(setup.GoMaxProcs)
	lock, err := instance.LockDataDir(setup.Directory)
	if err != nil {
		return err
	}
	defer lock.Close()
	store, err := instance.Open(config.Deployment{SchemaVersion: 1, DataDir: setup.Directory, ListenAddr: "127.0.0.1:0", Sources: map[string]string{}})
	if err != nil {
		return err
	}
	admin, err := auth.Open(setup.Directory, "")
	if err != nil {
		return err
	}
	if err := admin.Setup("synthetic isolated benchmark administrator"); err != nil {
		return err
	}
	engine, err := gateway.Open(setup.Directory)
	if err != nil {
		return err
	}
	defer engine.Close()
	evaluator, err := compliance.Open(filepath.Join(setup.Directory, "rule-packs"))
	if err != nil {
		return err
	}
	products, err := governance.Open(setup.Directory, engine, evaluator)
	if err != nil {
		return err
	}
	defer products.Close()
	connection, err := engine.Store.SaveConnection("", gateway.ConnectionInput{Name: "Synthetic benchmark provider", BaseURL: setup.ProviderURL, Model: "fixture", Alias: "bench", APIKey: &setup.ProviderKey, Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: 5})
	if err != nil {
		return err
	}
	app, key, err := engine.Store.SaveApplication("", gateway.ApplicationInput{Revision: engine.Store.Snapshot().Revision, Name: "Synthetic benchmark application", AllowedConnections: []string{connection.ID}})
	if err != nil {
		return err
	}
	_, err = engine.Policies.Save(gateway.PolicyInput{Mode: "observe", Rules: []string{"private_key", "api_key"}, ApplicationIDs: []string{app.ID}, ConnectionIDs: []string{}}, engine.Store.Snapshot())
	if err != nil {
		return err
	}
	capture := engine.Evidence.Config()
	capture.Mode, capture.ApplicationIDs = setup.Mode, []string{app.ID}
	if _, err = engine.Evidence.SaveConfig(capture, engine.Store.Snapshot(), "benchmark"); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	var active sync.WaitGroup
	actual := server.New(store, admin, engine, evaluator, products)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Done()
		actual.ServeHTTP(w, r)
	})
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(io.Discard, "", 0)}
	defer httpServer.Close()
	go httpServer.Serve(listener)
	encoder := json.NewEncoder(output)
	if err := encoder.Encode(workerReply{State: "ready", URL: "http://" + listener.Addr().String(), Key: key}); err != nil {
		return err
	}
	drain := func() error {
		done := make(chan struct{})
		go func() { active.Wait(); close(done) }()
		select {
		case <-done:
			return nil
		case <-time.After(12 * time.Second):
			return errors.New("benchmark drain timed out")
		}
	}
	var command control
	if readMessage(scanner, &command) != nil || command.Operation != "begin" || drain() != nil {
		return errors.New("benchmark warmup did not drain")
	}
	profiles, err := startProfiles(setup.Profile, setup.ProfileDir)
	if err != nil {
		return err
	}
	defer profiles.abort()
	before, err := sampleResources()
	if err != nil {
		return err
	}
	if err := encoder.Encode(workerReply{State: "measuring"}); err != nil {
		return err
	}
	if readMessage(scanner, &command) != nil || command.Operation != "finish" || command.Expected < 2 || command.Expected > 576 {
		return errors.New("invalid benchmark finish")
	}
	drainStart := time.Now()
	if err := drain(); err != nil {
		return err
	}
	drainMS := float64(time.Since(drainStart)) / float64(time.Millisecond)
	after, err := sampleResources()
	if err != nil {
		return err
	}
	window := resourcesBetween(before, after)
	// Send timing before untimed shutdown and read-back verification. The parent
	// timestamps this acknowledgement separately from client response completion.
	if err := encoder.Encode(workerReply{State: "drained", Resources: &window, DrainMS: drainMS}); err != nil {
		return err
	}
	if err := profiles.finish(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		return err
	}
	verification, err := verifyWorker(setup.Directory, engine, app.ID, setup.Mode, command.Expected)
	if err != nil {
		return err
	}
	return encoder.Encode(workerReply{State: "verified", Verification: &verification})
}

func verifyWorker(dir string, g *gateway.Engine, app, mode string, expected int) (Verification, error) {
	v := Verification{ExpectedCalls: expected}
	f, err := os.Open(filepath.Join(dir, "calls.jsonl"))
	if err != nil {
		return v, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return v, err
	}
	v.AuditBytes = info.Size()
	if info.Size() > 16<<20 {
		return v, errors.New("benchmark audit exceeds verification limit")
	}
	scan := bufio.NewScanner(io.LimitReader(f, 16<<20))
	scan.Buffer(make([]byte, 4096), 64<<10)
	seen := map[string]bool{}
	started := map[string]bool{}
	for scan.Scan() {
		var r gateway.CallRecord
		if json.Unmarshal(scan.Bytes(), &r) != nil {
			return v, errors.New("invalid benchmark audit")
		}
		if r.ApplicationID != app || r.Operation != "chat.completions" {
			continue
		}
		if r.Phase == "started" {
			if started[r.RequestID] {
				return v, errors.New("duplicate benchmark start record")
			}
			started[r.RequestID] = true
			v.StartedAuditCalls++
			continue
		}
		if r.Phase != "finished" {
			return v, errors.New("unexpected benchmark audit phase")
		}
		if seen[r.RequestID] {
			return v, errors.New("duplicate benchmark terminal record")
		}
		seen[r.RequestID] = true
		v.FinishedAuditCalls++
		if started[r.RequestID] && r.Outcome == "completed" && r.HTTPStatus == 200 && r.UpstreamAttempted && r.Trace != nil && r.ContentPolicy != nil && r.ContentPolicy.Mode == "observe" {
			v.SuccessfulAudits++
		}
		if mode == "disabled" {
			continue
		}
		b, err := g.Evidence.Get(gateway.EvidenceID(r.RequestID), app)
		valid := err == nil && b.AuditCommitted && b.Mode == mode && b.DeliveryState == "write_completed" && len(b.Objects) == 4
		for _, object := range b.Objects {
			valid = valid && (mode == "metadata" && object.ContentState == "metadata_only" || mode == "full" && object.ContentState == "retained")
			if object.Stream != nil {
				valid = valid && object.Stream.EndState == "completed" && object.Stream.DoneSeen
			}
		}
		if valid {
			v.VerifiedCaptures++
		}
	}
	if err := scan.Err(); err != nil {
		return v, err
	}
	files, err := os.ReadDir(filepath.Join(dir, "evidence"))
	if err != nil {
		return v, err
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".sealed") {
			info, err := file.Info()
			if err != nil {
				return v, err
			}
			v.EvidenceFiles++
			v.EvidenceBytes += info.Size()
		}
	}
	want := expected
	if mode == "disabled" {
		want = 0
	}
	v.Passed = v.StartedAuditCalls == expected && v.FinishedAuditCalls == expected && v.SuccessfulAudits == expected && v.EvidenceFiles == want && v.VerifiedCaptures == want
	return v, nil
}
