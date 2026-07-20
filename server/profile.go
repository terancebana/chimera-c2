package main

import (
	"encoding/json"
	"os"
)

type Profile struct {
	UserAgents []string         `json:"user_agents"`
	Headers    map[string]string `json:"headers"`
	Paths      map[string]string `json:"paths"`
	Sleep      struct {
		MinSeconds int `json:"min_seconds"`
		MaxSeconds int `json:"max_seconds"`
	} `json:"sleep"`
	MaxBodyKB int `json:"max_body_kb"`
}

var PROFILE Profile

func loadProfile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &PROFILE); err != nil {
		return err
	}
	if len(PROFILE.UserAgents) == 0 {
		PROFILE.UserAgents = []string{"Mozilla/5.0"}
	}
	if PROFILE.Paths == nil {
		PROFILE.Paths = map[string]string{
			"handshake": "/api/v1/auth",
			"beacon":    "/api/v1/sync",
			"result":    "/api/v1/telemetry",
		}
	}
	if PROFILE.Sleep.MaxSeconds < PROFILE.Sleep.MinSeconds {
		PROFILE.Sleep.MaxSeconds = PROFILE.Sleep.MinSeconds
	}
	if PROFILE.MaxBodyKB <= 0 {
		PROFILE.MaxBodyKB = 256
	}
	return nil
}
