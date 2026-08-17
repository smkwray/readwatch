//go:build windows

package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"readwatch/internal/protocol"
)

// TestDumpLiveState reads the running service's state over the owner's pipe and
// prints it. It exists because a status line truncates, and diagnosing a folder
// refusal from a truncated message is guesswork. Gated: it needs a running
// service and says nothing about correctness.
//
//	READWATCH_DUMP_STATE=1 go test ./cmd/readwatch/ -run DumpLiveState -v
func TestDumpLiveState(t *testing.T) {
	if os.Getenv("READWATCH_DUMP_STATE") != "1" {
		t.Skip("set READWATCH_DUMP_STATE=1 with ReadWatch running")
	}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("current user SID: %v", err)
	}
	got := make(chan protocol.State, 4)
	client, err := ConnectIPC(sid, protocol.RoleViewer, 5*time.Second,
		func(s protocol.State) {
			select {
			case got <- s:
			default:
			}
		}, nil, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	select {
	case s := <-got:
		b, _ := json.MarshalIndent(s, "", "  ")
		t.Logf("state:\n%s", b)
		for _, f := range s.Folders {
			t.Logf("FOLDER %-40s state=%v detail=%q", f.Path, f.State, f.Detail)
		}
		t.Logf("MECHANISM %q overridden=%v reason=%q", s.Mechanism, s.MechanismOverridden, s.MechanismReason)
	case <-time.After(8 * time.Second):
		t.Fatal("no state arrived in 8s")
	}
}
