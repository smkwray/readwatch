package protocol

import (
	"readwatch/internal/model"
	"readwatch/internal/settings"
)

const Version = 1

const (
	TypeHello    = "hello"
	TypeCommand  = "command"
	TypeResponse = "response"
	TypeState    = "state"
	TypeEvent    = "event"
)

const (
	CmdGetState = "get_state"
	CmdApply    = "apply"
	CmdStart    = "start"
	CmdStop     = "stop"
	CmdOpenLog  = "open_log"
	CmdCleanup  = "cleanup"
)

type Message struct {
	Version int                    `json:"version,omitempty"`
	Type    string                 `json:"type"`
	ID      uint64                 `json:"id,omitempty"`
	Command string                 `json:"command,omitempty"`
	Config  *settings.PublicConfig `json:"config,omitempty"`
	State   *State                 `json:"state,omitempty"`
	Event   *model.Event           `json:"event,omitempty"`
	OK      bool                   `json:"ok,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

type State struct {
	Running      bool                  `json:"running"`
	Config       settings.PublicConfig `json:"config"`
	LastError    string                `json:"last_error,omitempty"`
	LogDropped   uint64                `json:"log_dropped,omitempty"`
	LiveDropped  uint64                `json:"live_dropped,omitempty"`
	Suppressed   uint64                `json:"suppressed,omitempty"`
	ServiceReady bool                  `json:"service_ready"`
}
