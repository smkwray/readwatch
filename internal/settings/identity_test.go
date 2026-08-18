package settings

import (
	"errors"
	"testing"
)

// A version-1 configuration that still owns machine state cannot be upgraded:
// its snapshots name paths, and a path is exactly what stops being trustworthy.
// The upgrade has to stop rather than invent identities for those objects.
func TestMigrateFromV1RefusesOwnedAuditState(t *testing.T) {
	withSnapshot := Config{Version: 1, Snapshots: map[string]AuditSnapshot{
		`c:\docs`: {Path: `C:\Docs`, Original: "S:", Applied: "S:(AU;SA;0x1;;;WD)"},
	}}
	if err := withSnapshot.MigrateFromV1(); !errors.Is(err, ErrUnsafeV1Upgrade) {
		t.Fatalf("snapshot present: err = %v, want ErrUnsafeV1Upgrade", err)
	}

	withPolicy := Config{Version: 1, LegacyPolicyOwned: true, LegacyPolicyApplied: 1}
	if err := withPolicy.MigrateFromV1(); !errors.Is(err, ErrUnsafeV1Upgrade) {
		t.Fatalf("policy owned: err = %v, want ErrUnsafeV1Upgrade", err)
	}
}

func TestMigrateFromV1AcceptsCleanConfig(t *testing.T) {
	cfg := Config{Version: 1, Folders: []string{`C:\Docs`}}
	if err := cfg.MigrateFromV1(); err != nil {
		t.Fatal(err)
	}
	if cfg.Version != Version {
		t.Fatalf("version = %d, want %d", cfg.Version, Version)
	}
	if cfg.FolderBindings == nil || len(cfg.FolderBindings) != 0 {
		t.Fatalf("bindings = %#v, want empty and non-nil", cfg.FolderBindings)
	}
	// A migrated configuration claims no identities. The first owner-bound open
	// establishes them; nothing is inferred from the old pathname.
	if cfg.LogBinding != nil {
		t.Fatalf("log binding = %#v, want nil", cfg.LogBinding)
	}
}

func TestMigrateFromV1IsIdempotentOnV2(t *testing.T) {
	cfg := Config{Version: 2, Snapshots: map[string]AuditSnapshot{"x": {Phase: PhaseApplied}}}
	if err := cfg.MigrateFromV1(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Snapshots) != 1 {
		t.Fatalf("a version-2 config was rewritten by migration: %#v", cfg.Snapshots)
	}
}

// The key is what a snapshot is filed under, so two different objects must
// never collide and one object must key the same way every time.
func TestObjectIdentityKeyAndEquality(t *testing.T) {
	a := ObjectIdentity{VolumeGUID: `\\?\Volume{1}\`, VolumeSerial: 7, FileID128: [16]byte{1}, FileIndex64: 42, CreationTime: 99}
	same := a
	if !a.Equal(same) || a.Key() != same.Key() {
		t.Fatal("identical identities compared unequal")
	}

	// A recycled file identifier with a different creation time is a different
	// object: that is the case the creation time exists to catch.
	recycled := a
	recycled.CreationTime = 100
	if a.Equal(recycled) {
		t.Fatal("identities with different creation times compared equal")
	}
	if a.Key() == recycled.Key() {
		t.Fatal("a recycled file id produced the same key")
	}

	otherVolume := a
	otherVolume.VolumeGUID = `\\?\Volume{2}\`
	if a.Equal(otherVolume) || a.Key() == otherVolume.Key() {
		t.Fatal("identities on different volumes compared equal")
	}

	if !(ObjectIdentity{}).Zero() || a.Zero() {
		t.Fatal("Zero did not distinguish an unbound identity")
	}
}

func TestEqualComparesTheFilesystemToo(t *testing.T) {
	// A volume-only identity carries the filesystem as part of what it knows. If
	// the same GUID and serial came back describing a different filesystem, that
	// is a different volume, not the one that was authorised.
	base := ObjectIdentity{VolumeGUID: `\?\Volume{a}\`, VolumeSerial: 7, FileSystem: "exFAT"}
	same := base
	if !base.Equal(same) {
		t.Fatal("an identical identity did not compare equal")
	}
	other := base
	other.FileSystem = "NTFS"
	if base.Equal(other) {
		t.Fatal("identities differing only by filesystem compared equal")
	}
}
