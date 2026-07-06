# Roadmap

## Crypto

- [x] Swap AES-CBC for AES-GCM (adds authentication, prevents ciphertext malleability)
- [x] Validate PKCS7 padding instead of relying on recover() panic catch (obsoleted by GCM — no padding needed)
- [x] Stop silently discarding encrypt/decrypt/marshal errors (silent skip on failure, server timeout at 15s)
- [x] In-memory error queue — queue failures, piggyback on next successful beacon result

## Key Material

- [x] Replace hardcoded static key with something derived or at minimum not plaintext-recoverable (linker-injected hex key + init())

## Agent Identity

- [x] Increase generateAgentID() from 4 bytes to 8 bytes (reduce collision risk)

## OPSEC

- [x] Replace GetAsyncKeyState polling loop with SetWindowsHookEx (event-driven, lower CPU)
- [x] Deduplicate persistence installs (don't re-write registry/task every startup)

## Network

- [x] Batch keylogs into the beacon response instead of a separate POST request
- [x] Add TLS with certificate pinning to C2 communication

---

## Server (v1)

- [x] Resolver endpoint — HTTP server returning C2 address
- [x] C2 listener — HTTPS with cert pinning, 3 routes (handshake/tasks/results)
- [x] Protocol layer — ECDH + HKDF session keys, GCM encrypt/decrypt
- [x] Agent registry — track agent ID, first seen, last seen, session key
- [x] Task queue — per-agent pending tasks (exec, upload, download, screenshot, harvest, uninstall)
- [x] Result store — save text output, keylogs, file data to disk
- [x] Database — SQLite (agents, tasks, results tables)
- [x] Operator CLI — interactive shell with list/exec/upload/download/screenshot/harvest/keylog/result/uninstall commands
