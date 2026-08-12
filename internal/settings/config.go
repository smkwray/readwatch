package settings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const Version = 1

// AuditSnapshot lets ReadWatch undo only a SACL state it can prove it created.
// If another tool changes the SACL after ReadWatch applies its rule, ReadWatch
// leaves that folder untouched rather than overwriting the external change.
type AuditSnapshot struct {
	Path     string `json:"path"`
	Original string `json:"original_sddl"`
	Applied  string `json:"applied_sddl"`
}

// Config is persisted in a SYSTEM/admin-only ProgramData directory.
type Config struct {
	Version             int                      `json:"version"`
	OwnerSID            string                   `json:"owner_sid"`
	OwnerName           string                   `json:"owner_name,omitempty"`
	Enabled             bool                     `json:"enabled"`
	StartAtLogin        bool                     `json:"start_at_login"`
	OpenAtLogin         bool                     `json:"open_at_login"`
	IncludeDirectories  bool                     `json:"include_directory_listings"`
	LogPath             string                   `json:"log_path"`
	LogFormat           string                   `json:"log_format"`
	MaxRows             int                      `json:"max_rows"`
	Folders             []string                 `json:"folders"`
	ExcludedProcesses   []string                 `json:"excluded_processes"`
	Snapshots           map[string]AuditSnapshot `json:"audit_snapshots,omitempty"`
	AuditPolicyOwned    bool                     `json:"audit_policy_owned,omitempty"`
	AuditPolicyOriginal uint32                   `json:"audit_policy_original,omitempty"`
	AuditPolicyApplied  uint32                   `json:"audit_policy_applied,omitempty"`
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
	if !c.AuditPolicyOwned {
		c.AuditPolicyOriginal = 0
		c.AuditPolicyApplied = 0
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

func Save(path string, cfg Config) error {
	cfg.Normalize()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(path)
		return os.Rename(tmp, path)
	}
	return nil
}
