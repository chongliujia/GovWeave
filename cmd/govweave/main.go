package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"govweave/internal/auth"
	"govweave/internal/compliance"
	"govweave/internal/config"
	"govweave/internal/gateway"
	"govweave/internal/governance"
	"govweave/internal/instance"
	"govweave/internal/server"
)

func main() {
	path := flag.String("config", "", "deployment JSON file (optional)")
	check := flag.Bool("check-config", false, "validate deployment configuration and exit without creating files")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println(server.Version)
		return
	}
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments")
	}
	d, err := config.Load(*path, os.LookupEnv)
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	if *check {
		fmt.Println("Deployment configuration is valid.")
		return
	}
	// Bind first, so accidentally starting a second instance on the same port
	// cannot modify the running instance's files.
	listener, err := net.Listen("tcp", d.ListenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	lock, err := instance.LockDataDir(d.DataDir)
	if err != nil {
		log.Fatalf("lock instance: %v", err)
	}
	defer lock.Close()
	store, err := instance.Open(d)
	if err != nil {
		log.Fatalf("open instance: %v", err)
	}
	administrator, err := auth.Open(d.DataDir, d.AdminTokenFile)
	if err != nil {
		log.Fatalf("load admin credential: %v", err)
	}
	engine, err := gateway.Open(d.DataDir)
	if err != nil {
		log.Fatalf("open gateway: %v", err)
	}
	defer engine.Close()
	evaluator, err := compliance.Open(filepath.Join(d.DataDir, "rule-packs"))
	if err != nil {
		log.Fatalf("load compliance rule packs: %v", err)
	}
	products, err := governance.Open(d.DataDir, engine, evaluator)
	if err != nil {
		log.Fatalf("load product registry: %v", err)
	}
	defer products.Close()
	httpServer := &http.Server{Handler: server.New(store, administrator, engine, evaluator, products), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdown); err != nil {
			_ = httpServer.Close()
		}
	}()
	log.Printf("GovWeave %s listening on %s", server.Version, listener.Addr())
	if administrator.SetupRequired() {
		log.Print("Open the console to set the initial administrator password before exposing this instance to other users.")
	}
	if public := store.View().PublicURL; public != "" {
		log.Printf("Configured console URL: %s", public)
	}
	log.Print("Console and Chat Completions gateway are available. Configure a model connection and application key before calling. MCP is not implemented.")
	if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Printf("server error: %v", err)
		stop()
	}
	stop()
	<-finished
}
