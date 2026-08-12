package model

import "time"

// Event is one exercised file read reported by Windows Security event 4663.
type Event struct {
	Time        time.Time `json:"time"`
	RecordID    uint64    `json:"record_id,omitempty"`
	Path        string    `json:"path"`
	ProcessPath string    `json:"process_path"`
	Process     string    `json:"process"`
	PID         uint32    `json:"pid"`
	User        string    `json:"user"`
	UserSID     string    `json:"user_sid,omitempty"`
	LogonID     string    `json:"logon_id,omitempty"`
	HandleID    string    `json:"handle_id,omitempty"`
	AccessMask  uint32    `json:"access_mask"`
	Directory   bool      `json:"directory,omitempty"`
}
