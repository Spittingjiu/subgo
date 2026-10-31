package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/Spittingjiu/subgo/internal/config"
	"github.com/Spittingjiu/subgo/internal/server"
)

func main() {
	cfg := config.Load()
	log.Printf("subgo listening on %s", cfg.Addr)
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.Run() }()
	select {
	case <-ctx.Done():
		if err := srv.Close(); err != nil {
			log.Printf("subgo shutdown failed: %v", err)
		}
		if err := <-done; err != nil {
			log.Printf("subgo listener failed: %v", err)
		}
	case err := <-done:
		if closeErr := srv.Close(); closeErr != nil {
			log.Printf("subgo shutdown failed: %v", closeErr)
		}
		if err != nil {
			log.Printf("subgo listener failed: %v", err)
		}
	}
}
