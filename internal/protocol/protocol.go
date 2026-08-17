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
	// CmdRefresh re-binds the configuration the service already holds. It exists
	// because a folder can become reachable without the configuration changing -
	// a drive is plugged in - and only a connected owner's token may open it.
	CmdRefresh = "refresh"
)

type Message struct {
	Version int                    `json:"version,omitempty"`
	Type    string                 `json:"type"`
	Role    ClientRole             `json:"role,omitempty"`
	ID      uint64                 `json:"id,omitempty"`
	Command string                 `json:"command,omitempty"`
	Config  *settings.PublicConfig `json:"config,omitempty"`
	// Authorise marks a command as the owner deciding what each configured path
	// means, which only the Settings dialog's Save is. Every other sender of an
	// apply - the right-click process exclusion, the start-at-sign-in rollback -
	// is changing something else and leaves the folder identities alone, so a
	// folder that has been substituted stays refused instead of being approved by
	// a click that was about something entirely different.
	Authorise bool         `json:"authorise,omitempty"`
	State     *State       `json:"state,omitempty"`
	Event     *model.Event `json:"event,omitempty"`
	OK        bool         `json:"ok,omitempty"`
	Error     string       `json:"error,omitempty"`
}

// FolderState is what the last binding attempt found at a configured path. A
// configured folder is never silently dropped, so every one of them has a state
// and the counts always add up to what the owner asked for.
type FolderState string

const (
	// FolderAvailable was opened under the owner's token. It carries the audit
	// rule whenever monitoring is on.
	FolderAvailable FolderState = "available"
	// FolderWaiting is not reachable right now and is expected to come back on
	// its own: a drive that is not plugged in, an empty card reader, a folder not
	// yet created. Not a fault, and never a reason to stop watching the others.
	FolderWaiting FolderState = "waiting"
	// FolderRefused is reachable but ReadWatch will not watch it, and nothing
	// will change that on its own: a junction, a permission the owner does not
	// have, a volume that cannot carry an audit rule, or a path that now refers
	// to a different folder than the one that was authorised.
	FolderRefused FolderState = "refused"
)

type FolderStatus struct {
	Path   string      `json:"path"`
	State  FolderState `json:"state"`
	Detail string      `json:"detail,omitempty"`
}

type State struct {
	Running      bool                  `json:"running"`
	Config       settings.PublicConfig `json:"config"`
	LastError    string                `json:"last_error,omitempty"`
	LogDropped   uint64                `json:"log_dropped,omitempty"`
	LiveDropped  uint64                `json:"live_dropped,omitempty"`
	Suppressed   uint64                `json:"suppressed,omitempty"`
	ServiceReady bool                  `json:"service_ready"`
	// Folders is the per-folder outcome of the last binding attempt, in the order
	// the owner configured them.
	Folders []FolderStatus `json:"folders,omitempty"`
	// PendingRules names folders whose audit rule ReadWatch still owns but cannot
	// reach, because the disk holding them is not in the machine. It is the one
	// case where stopping cannot leave nothing behind, so it is reported rather
	// than quietly forgotten.
	PendingRules []string `json:"pending_rules,omitempty"`
}

// Counts summarises the folder states for the status line.
func (s State) Counts() (available, waiting, refused int) {
	for _, f := range s.Folders {
		switch f.State {
		case FolderAvailable:
			available++
		case FolderWaiting:
			waiting++
		case FolderRefused:
			refused++
		}
	}
	return available, waiting, refused
}

// FirstRefused returns the first folder ReadWatch will not watch, which is the
// only folder state that asks the owner to do something.
func (s State) FirstRefused() (FolderStatus, bool) {
	for _, f := range s.Folders {
		if f.State == FolderRefused {
			return f, true
		}
	}
	return FolderStatus{}, false
}
