package protocol

import (
	"readwatch/internal/model"
	"readwatch/internal/settings"
)

// Version 2 made Hello mandatory and gave it a role, so the service can tell a
// viewer session (whose presence is the reason the service exists) from a
// maintenance connection (which must not keep it alive). Both ends ship in one
// binary, so there is no mixed-version case to support: a mismatch is a stale
// process and the connection is closed.
const Version = 2

// ClientRole is a lifetime signal, not a security identity. The pipe ACL and
// the owner-SID check are what decide who may connect at all; this only decides
// whether the connection holds the service open.
type ClientRole string

const (
	RoleViewer      ClientRole = "viewer"
	RoleMaintenance ClientRole = "maintenance"
)

func (r ClientRole) valid() bool {
	return r == RoleViewer || r == RoleMaintenance
}

// ValidRole reports whether a role arrived intact over the wire.
func ValidRole(r ClientRole) bool { return r.valid() }

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
	Role    ClientRole             `json:"role,omitempty"`
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
