package main

import (
	"log"

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
	defer srv.Close()
	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}
