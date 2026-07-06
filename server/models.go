package main

import "time"

type Task struct {
	Type        string `json:"type"`
	Command     string `json:"command"`
	Path        string `json:"path"`
	FileData    string `json:"file_data"`
	Destination string `json:"destination"`
	PublicKey   string `json:"public_key,omitempty"`
}

type Result struct {
	Type     string   `json:"type"`
	Data     string   `json:"data"`
	Filename string   `json:"filename,omitempty"`
	Keylogs  string   `json:"keylogs,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

type HandshakeResponse struct {
	Status    string `json:"status"`
	PublicKey string `json:"public_key"`
}

type Agent struct {
	ID         string    `json:"id"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	SessionKey []byte    `json:"-"`
}
