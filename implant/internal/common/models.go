package common

type Task struct {
	Type        string `json:"type"`
	Command     string `json:"command"`
	Path        string `json:"path"`
	FileData    string `json:"file_data"`
	Destination string `json:"destination"`
	PublicKey   string `json:"public_key,omitempty"`
}

type HandshakeResponse struct {
	Status    string `json:"status"`
	PublicKey string `json:"public_key"`
}
