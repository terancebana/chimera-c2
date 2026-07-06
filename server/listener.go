package main

import (
	"log"
	"net/http"
)

func startListener(addr, certFile, keyFile string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleC2)

	log.Printf("[c2] listening on %s", addr)
	if err := http.ListenAndServeTLS(addr, certFile, keyFile, mux); err != nil {
		log.Fatalf("[c2] %v", err)
	}
}

func handleC2(w http.ResponseWriter, r *http.Request) {
	agentID := r.Header.Get("X-Agent-ID")

	switch r.Method {
	case "POST":
		mu.Lock()
		_, known := agents[agentID]
		mu.Unlock()
		if known {
			handleResult(w, r, agentID)
		} else {
			handleHandshake(w, r, agentID)
		}
	case "GET":
		handleTaskPoll(w, r, agentID)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
