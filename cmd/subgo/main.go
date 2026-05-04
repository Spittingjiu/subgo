package main

import (
	"log"

	"github.com/Spittingjiu/subgo/internal/config"
	"github.com/Spittingjiu/subgo/internal/server"
)

func main() {
	cfg := config.Load()
	log.Printf("subgo listening on %s", cfg.Addr)
	if err := server.New(cfg).Run(); err != nil {
		log.Fatal(err)
	}
}
