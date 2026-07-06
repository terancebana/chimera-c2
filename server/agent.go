package main

import (
	"fmt"
	"sync"
	"time"
)

var mu sync.Mutex
var agents = make(map[string]*Agent)

func agentExists(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, ok := agents[id]
	return ok
}

func registerAgent(id string) *Agent {
	mu.Lock()
	defer mu.Unlock()
	a := &Agent{
		ID:        id,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	agents[id] = a
	dbRegisterAgent(id)
	return a
}

func heartbeatAgent(id string) {
	mu.Lock()
	defer mu.Unlock()
	if a, ok := agents[id]; ok {
		a.LastSeen = time.Now()
	}
	dbHeartbeatAgent(id)
}

func setSessionKey(id string, key []byte) {
	mu.Lock()
	defer mu.Unlock()
	if a, ok := agents[id]; ok {
		a.SessionKey = key
	}
	dbSetSessionKey(id, key)
}

func listAgents() []Agent {
	return dbListAgents()
}

func formatAgents() string {
	list := listAgents()
	if len(list) == 0 {
		return "No agents connected."
	}
	out := fmt.Sprintf("%-18s %-20s %-20s\n", "AGENT", "FIRST SEEN", "LAST SEEN")
	out += "--------------------------------------------------------------\n"
	for _, a := range list {
		out += fmt.Sprintf("%-18s %-20s %-20s\n",
			a.ID,
			a.FirstSeen.Format("2006-01-02 15:04:05"),
			a.LastSeen.Format("2006-01-02 15:04:05"),
		)
	}
	return out
}
