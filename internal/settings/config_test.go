package settings

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalizeBoundsFormatAndDeduplicatesFolders(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "Alpha")
	b := filepath.Join(base, "Beta")
	cfg := Config{
		LogPath:   filepath.Join(base, "..", filepath.Base(base), "ReadWatch.log"),
		LogFormat: "xml",
		MaxRows:   42,
		Folders:   []string{"  " + b + "  ", a, a, filepath.Join(base, "alpha")},
	}
	cfg.Normalize()
	if cfg.Version != Version {
		t.Fatalf("version = %d, want %d", cfg.Version, Version)
	}
	if cfg.LogFormat != "text" {
		t.Fatalf("format = %q, want text", cfg.LogFormat)
	}
	if cfg.MaxRows != 1000 {
		t.Fatalf("max rows = %d, want 1000", cfg.MaxRows)
	}
	want := []string{filepath.Join(base, "alpha"), b}
	if !reflect.DeepEqual(cfg.Folders, want) {
		t.Fatalf("folders = %#v, want %#v", cfg.Folders, want)
	}
	if cfg.Snapshots == nil {
		t.Fatal("snapshots map was not initialized")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := Default(filepath.Join(dir, "ReadWatch.log"), "S-1-5-21-test", `DESKTOP\\User`)
	cfg.Enabled = true
	cfg.StartAtLogin = true
	cfg.OpenAtLogin = true
	cfg.LogFormat = "jsonl"
	cfg.MaxRows = 2500
	cfg.Folders = []string{filepath.Join(dir, "Docs")}
	cfg.Snapshots["docs"] = AuditSnapshot{Path: cfg.Folders[0], Original: "S:", Applied: "S:(AU;SA;0x1;;;WD)"}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path, filepath.Join(dir, "fallback.log"), cfg.OwnerSID, cfg.OwnerName)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, cfg) {
		t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", got, cfg)
	}
}

func TestPublicConfigCannotChangeOwnerOrEnabledState(t *testing.T) {
	cfg := Default("ReadWatch.log", "owner-sid", "owner-name")
	cfg.Enabled = true
	cfg.ApplyPublic(PublicConfig{LogPath: "new.log", LogFormat: "csv", MaxRows: 500})
	if cfg.OwnerSID != "owner-sid" || cfg.OwnerName != "owner-name" {
		t.Fatalf("owner changed: %#v", cfg)
	}
	if !cfg.Enabled {
		t.Fatal("public settings changed enabled state")
	}
	if cfg.LogFormat != "csv" || cfg.MaxRows != 500 {
		t.Fatalf("public settings were not applied: %#v", cfg)
	}
}
