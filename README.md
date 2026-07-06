# Chimera C2 - Implant

A Windows implant written in Go, designed as an educational research project for studying offensive security techniques and C2 communication protocols.

## Features

- **ECDH-P256 + HKDF key exchange** for session key derivation
- **AES-256-GCM** authenticated encryption for all C2 traffic
- **TLS with certificate pinning** to prevent MITM interception
- **Per-build unique keys** injected via linker flags
- **In-memory error queue** — operational health tracking without extra network noise
- **Chrome credential harvesting** via DPAPI (`CryptUnprotectData`)
- **Event-driven keylogger** using `SetWindowsHookEx` with window title tracking
- **Screenshot capture** for multi-monitor setups
- **Self-install** with process migration, hidden file attributes, and dual persistence (registry `Run` key + scheduled task)
- **Jittered beacon timing** with unique per-agent IDs

## Build

```bash
./build.sh
```

The build script:
1. Generates a random 32-byte static key per build
2. Generates a self-signed TLS certificate (if one does not exist)
3. Computes the SHA-256 certificate pin
4. Cross-compiles for Windows with stripped debug symbols

Output: `implant.exe`

The generated `server.crt` and `server.key` are used on the C2 server side to serve HTTPS with the pinned certificate.

## Architecture

```
main()
 ├── installSelf()           # Copy to %APPDATA%, set hidden, migrate process
 ├── checkForMutex()         # Single-instance enforcement
 ├── installRegistryPersistence()  # HKCU\..\Run with dedup check
 ├── installScheduledTask()  # schtasks with dedup check
 ├── performHandshake()      # ECDH key exchange over AES-GCM (static key)
 └── for { beacon() }        # Main C2 loop with jitter
      ├── GET task from C2
      ├── drain keylogs into result
      └── POST result + keylogs back
```

## Task Types

| Type | Description |
|------|-------------|
| `exec` | Execute a shell command, return output |
| `cd` | Change working directory |
| `upload` | Write b64-decoded file data to disk |
| `download` | Read file from disk, return b64-encoded |
| `screenshot` | Capture primary display, return PNG |
| `harvest` | Extract Chrome master key + Login Data |
| `uninstall` | Remove persistence and terminate |

## Disclaimer

This software is provided for **educational and authorized security research purposes only**. Use of this software against systems without explicit written permission from the system owner is illegal and may violate applicable laws including but not limited to the Computer Fraud and Abuse Act (CFAA) and similar legislation in other jurisdictions.

The author assumes no liability for any misuse, damage, or legal consequences resulting from the use of this software. By using this software, you acknowledge that you are solely responsible for ensuring compliance with all applicable laws and regulations.
