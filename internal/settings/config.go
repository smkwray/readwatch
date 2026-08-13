package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const Version = 2

// Phases of a privileged mutation. The record is written before the change and
// updated after it is verified, so a crash in between is recognisable: a
// "prepared" record means the change may or may not have happened and the
// object must be examined, an "applied" one means it did.
const (
	PhasePrepared = "prepared"
	PhaseApplied  = "applied"
)

// ObjectIdentity is what survives a rename and what a substituted folder cannot
// forge: the volume, the file identifier within it, and the creation time.
// File identifiers are reused after deletion, which is why the creation time is
// part of the tuple and why a match alone never authorises a write.
type ObjectIdentity struct {
	VolumeGUID   string   `json:"volume_guid"`
	VolumeSerial uint64   `json:"volume_serial"`
	FileSystem   string   `json:"file_system"`
	FileID128    [16]byte `json:"file_id_128"`
	FileIndex64  uint64   `json:"file_index_64,omitempty"`
	CreationTime uint64   `json:"creation_time"`
}

func (id ObjectIdentity) Zero() bool {
	return id.VolumeGUID == "" && id.FileID128 == [16]byte{} && id.FileIndex64 == 0
}

// Key identifies a snapshot by the object it describes rather than by a path
// that can be pointed somewhere else.
func (id ObjectIdentity) Key() string {
	return fmt.Sprintf("%s|%x|%d", strings.ToLower(id.VolumeGUID), id.FileID128, id.CreationTime)
}

func (id ObjectIdentity) Equal(other ObjectIdentity) bool {
	return strings.EqualFold(id.VolumeGUID, other.VolumeGUID) &&
		id.VolumeSerial == other.VolumeSerial &&
		id.FileID128 == other.FileID128 &&
		id.FileIndex64 == other.FileIndex64 &&
		id.CreationTime == other.CreationTime
}

// ObjectBinding remembers which object a configured path meant when the owner
// last authorised it. Path is a locator for display and diagnostics; Identity
// is the part that decides.
type ObjectBinding struct {
	Path     string         `json:"path"`
	Identity ObjectIdentity `json:"identity"`
}

// AuditSnapshot lets ReadWatch undo only a SACL state it can prove it created.
// If another tool changes the SACL after ReadWatch applies its rule, ReadWatch
// leaves that folder untouched rather than overwriting the external change.
type AuditSnapshot struct {
	Path     string         `json:"path"`
	Identity ObjectIdentity `json:"identity"`
	Original string         `json:"original_sddl"`
	Applied  string         `json:"applied_sddl"`
	Phase    string         `json:"phase"`
}

// AuditPolicySnapshot is the machine-wide policy change, journalled the same way
// as a folder's SACL so a crash between the change and the record is visible.
type AuditPolicySnapshot struct {
	Original uint32 `json:"original"`
	Applied  uint32 `json:"applied"`
	Phase    string `json:"phase"`
}

// Config is persisted in a SYSTEM/admin-only ProgramData directory. Since
// version 2 it is also the recovery journal: every privileged change is written
// here before it is made, so a crash leaves a record of what to undo.
type Config struct {
	Version            int                      `json:"version"`
	OwnerSID           string                   `json:"owner_sid"`
	OwnerName          string                   `json:"owner_name,omitempty"`
	Enabled            bool                     `json:"enabled"`
	StartAtLogin       bool                     `json:"start_at_login"`
	OpenAtLogin        bool                     `json:"open_at_login"`
	IncludeDirectories bool                     `json:"include_directory_listings"`
	LogPath            string                   `json:"log_path"`
	LogFormat          string                   `json:"log_format"`
	MaxRows            int                      `json:"max_rows"`
	Folders            []string                 `json:"folders"`
	ExcludedProcesses  []string                 `json:"excluded_processes"`
	FolderBindings     map[string]ObjectBinding `json:"folder_bindings,omitempty"`
	LogBinding         *ObjectBinding           `json:"log_binding,omitempty"`
	Snapshots          map[string]AuditSnapshot `json:"audit_snapshots,omitempty"`
	AuditPolicy        *AuditPolicySnapshot     `json:"audit_policy,omitempty"`

	// Version-1 policy fields, read only so the migration gate can refuse to
	// upgrade a configuration that still owns machine state it cannot identify.
	LegacyPolicyOwned    bool   `json:"audit_policy_owned,omitempty"`
	LegacyPolicyOriginal uint32 `json:"audit_policy_original,omitempty"`
	LegacyPolicyApplied  uint32 `json:"audit_policy_applied,omitempty"`
}

// ErrUnsafeV1Upgrade means the previous version left audit state behind that
// carries no identity, so there is no safe way to find those objects again. The
// old version has to be started and stopped cleanly first.
var ErrUnsafeV1Upgrade = errors.New("the installed ReadWatch still owns audit rules or an audit-policy change from version 1; start it, stop monitoring, then upgrade")

// MigrateFromV1 converts a clean version-1 configuration. It refuses a dirty
// one rather than inventing identities for objects the old version changed:
// a version-1 snapshot names a path, and a path is exactly what cannot be
// trusted to still mean the same object.
func (c *Config) MigrateFromV1() error {
	if c.Version >= 2 {
		return nil
	}
	if len(c.Snapshots) > 0 || c.LegacyPolicyOwned {
		return ErrUnsafeV1Upgrade
	}
	c.Version = Version
	c.FolderBindings = make(map[string]ObjectBinding)
	c.LogBinding = nil
	c.Snapshots = make(map[string]AuditSnapshot)
	c.AuditPolicy = nil
	return nil
}

// PublicConfig is the subset sent over IPC to the non-elevated UI.
type PublicConfig struct {
	Enabled            bool     `json:"enabled"`
	StartAtLogin       bool     `json:"start_at_login"`
	OpenAtLogin        bool     `json:"open_at_login"`
	IncludeDirectories bool     `json:"include_directory_listings"`
	LogPath            string   `json:"log_path"`
	LogFormat          string   `json:"log_format"`
	MaxRows            int      `json:"max_rows"`
	Folders            []string `json:"folders"`
	ExcludedProcesses  []string `json:"excluded_processes"`
}

// Excludes reports whether a reader matches the suppression list.
//
// An entry containing a path separator is matched against the full image path;
// anything else is matched against the image name. Image-name matching is what
// people expect and what the right-click action produces, but it is trivially
// spoofable - any binary can be called explorer.exe - and noticing unexpected
// readers is this tool's whole purpose. So the full-path form is offered as the
// stronger option, and suppressed events are counted rather than discarded
// silently so a hidden reader is always visible as a number.
func Excludes(list []string, imagePath, imageName string) bool {
	if len(list) == 0 {
		return false
	}
	path := strings.ToLower(strings.TrimSpace(imagePath))
	name := strings.ToLower(strings.TrimSpace(imageName))
	if name == "" && path != "" {
		name = strings.ToLower(filepath.Base(path))
	}
	for _, raw := range list {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		if strings.ContainsAny(entry, `\/`) {
			if path != "" && filepath.Clean(entry) == filepath.Clean(path) {
				return true
			}
			continue
		}
		if entry == name {
			return true
		}
	}
	return false
}

func Default(logPath, ownerSID, ownerName string) Config {
	return Config{
		Version:   Version,
		OwnerSID:  ownerSID,
		OwnerName: ownerName,
		LogPath:   logPath,
		LogFormat: "text",
		MaxRows:   1000,
		Folders:   []string{},
		// No processes are excluded out of the box. Which readers are noise is a
		// property of the machine, not of the tool, so the list starts empty and
		// is filled by right-clicking the readers you actually see.
		ExcludedProcesses: []string{},
		Snapshots:         make(map[string]AuditSnapshot),
		FolderBindings:    make(map[string]ObjectBinding),
		OpenAtLogin:       false,
	}
}

func Load(path, defaultLogPath, ownerSID, ownerName string) (Config, error) {
	cfg := Default(defaultLogPath, ownerSID, ownerName)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Default(defaultLogPath, ownerSID, ownerName), err
	}
	if cfg.OwnerSID == "" {
		cfg.OwnerSID = ownerSID
	}
	if cfg.OwnerName == "" {
		cfg.OwnerName = ownerName
	}
	cfg.Normalize()
	return cfg, nil
}

func (c Config) Public() PublicConfig {
	folders := append([]string(nil), c.Folders...)
	excluded := append([]string(nil), c.ExcludedProcesses...)
	return PublicConfig{
		ExcludedProcesses:  excluded,
		Enabled:            c.Enabled,
		StartAtLogin:       c.StartAtLogin,
		OpenAtLogin:        c.OpenAtLogin,
		IncludeDirectories: c.IncludeDirectories,
		LogPath:            c.LogPath,
		LogFormat:          c.LogFormat,
		MaxRows:            c.MaxRows,
		Folders:            folders,
	}
}

func (c *Config) ApplyPublic(p PublicConfig) {
	c.StartAtLogin = p.StartAtLogin
	c.OpenAtLogin = p.OpenAtLogin
	c.IncludeDirectories = p.IncludeDirectories
	c.LogPath = p.LogPath
	c.LogFormat = p.LogFormat
	c.MaxRows = p.MaxRows
	c.Folders = append(c.Folders[:0], p.Folders...)
	c.ExcludedProcesses = append(c.ExcludedProcesses[:0], p.ExcludedProcesses...)
	c.Normalize()
}

func (c *Config) Normalize() {
	c.Version = Version
	c.OwnerSID = strings.TrimSpace(c.OwnerSID)
	c.OwnerName = strings.TrimSpace(c.OwnerName)
	c.LogPath = filepath.Clean(strings.TrimSpace(c.LogPath))
	if c.LogFormat != "text" && c.LogFormat != "jsonl" && c.LogFormat != "csv" {
		c.LogFormat = "text"
	}
	if c.MaxRows < 200 || c.MaxRows > 5000 {
		c.MaxRows = 1000
	}
	if c.Snapshots == nil {
		c.Snapshots = make(map[string]AuditSnapshot)
	}
	if c.FolderBindings == nil {
		c.FolderBindings = make(map[string]ObjectBinding)
	}

	seen := make(map[string]string)
	for _, raw := range c.Folders {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		key := strings.ToLower(p)
		seen[key] = p
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	c.Folders = c.Folders[:0]
	for _, k := range keys {
		c.Folders = append(c.Folders, seen[k])
	}

	// Case-insensitive dedupe, original spelling kept for display. An empty list
	// means "show me everything" and stays empty.
	exSeen := make(map[string]string)
	exOrder := make([]string, 0, len(c.ExcludedProcesses))
	for _, raw := range c.ExcludedProcesses {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		key := strings.ToLower(e)
		if _, dup := exSeen[key]; dup {
			continue
		}
		exSeen[key] = e
		exOrder = append(exOrder, key)
	}
	sort.Strings(exOrder)
	c.ExcludedProcesses = c.ExcludedProcesses[:0]
	for _, k := range exOrder {
		c.ExcludedProcesses = append(c.ExcludedProcesses, exSeen[k])
	}
}

// Save commits the configuration durably. This file is the recovery journal for
// every privileged change ReadWatch makes, so the previous good copy must
// survive any failure here: the old delete-then-rename fallback could destroy it
// and leave nothing to recover from. Write a fresh file beside it, flush it to
// disk, then replace in one step - os.Rename is MoveFileEx with
// MOVEFILE_REPLACE_EXISTING on Windows, which replaces atomically within a
// volume without unlinking the destination first.
func Save(path string, cfg Config) error {
	cfg.Normalize()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	// O_EXCL so a stale or hostile temp file is never written through.
	tmp := filepath.Join(dir, fmt.Sprintf("%s.%d.tmp", filepath.Base(path), os.Getpid()))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = os.Remove(tmp)
		if f, err = os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err != nil {
			return fmt.Errorf("create configuration temporary file: %w", err)
		}
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write configuration: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("flush configuration: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close configuration: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace configuration: %w", err)
	}
	return nil
}
