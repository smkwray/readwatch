//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The flag words are the ones this host reports, captured in
// do/evidence/2026-08-17-exfat-capability. Using real values rather than
// hand-built ones is the point: the rules are checked against what Windows
// actually says, not against what the format is assumed to support.
const (
	flagsNTFSHere  = 0x03E72EFF
	flagsExFATHere = 0x00020206
)

func TestVolumeTraitsFromMeasuredFlags(t *testing.T) {
	ntfs := traitsFromFlags("NTFS", 1, flagsNTFSHere)
	if !ntfs.MarkerCapable() || !ntfs.IdentityCapable() || !ntfs.ReparsePoints {
		t.Fatalf("NTFS should support everything ReadWatch asks of a volume: %+v", ntfs)
	}

	exfat := traitsFromFlags("exFAT", 2, flagsExFATHere)
	if exfat.MarkerCapable() {
		t.Error("exFAT cannot carry an audit rule; a marker must never be applied to it")
	}
	if exfat.IdentityCapable() {
		t.Error("exFAT offers no durable file identity")
	}
	if exfat.ReparsePoints {
		t.Error("exFAT cannot hold a reparse point, which is why that check is skipped there")
	}
}

func TestMarkerCapabilityNeedsBothHalves(t *testing.T) {
	// Applying a rule that cannot later be found by identity would leave a change
	// ReadWatch could not undo, so either half missing is disqualifying.
	if traitsFromFlags("NTFS", 0, FILE_PERSISTENT_ACLS).MarkerCapable() {
		t.Error("persistent ACLs without open-by-id must not qualify")
	}
	if traitsFromFlags("NTFS", 0, FILE_SUPPORTS_OPEN_BY_FILE_ID).MarkerCapable() {
		t.Error("open-by-id without persistent ACLs must not qualify")
	}
	// A filesystem ReadWatch has never heard of does not qualify on flags alone:
	// the audit machinery is only established on NTFS and ReFS.
	if traitsFromFlags("SomethingNew", 0, flagsNTFSHere).MarkerCapable() {
		t.Error("an unknown filesystem must not be treated as marker-capable")
	}
}

// exfatRoot finds a mounted exFAT volume to test against, or skips. This is a
// hardware-dependent check by nature: the whole question is what a real volume
// does, and a fabricated one would prove nothing.
func exfatRoot(t *testing.T) (string, volumeTraits) {
	t.Helper()
	for letter := 'A'; letter <= 'Z'; letter++ {
		root := string(letter) + `:\`
		if driveType(root) == DRIVE_NO_ROOT_DIR {
			continue
		}
		traits, err := volumeTraitsFor(root)
		if err != nil {
			continue
		}
		if strings.EqualFold(traits.FileSystem, "exFAT") {
			return root, traits
		}
	}
	t.Skip("no exFAT volume mounted; this check needs one")
	return "", volumeTraits{}
}

func TestExFATFolderIsRefusedForMarkersAndAdmittedForTracing(t *testing.T) {
	root, traits := exfatRoot(t)
	dir := filepath.Join(root, "ReadWatch-Test-exfat")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot create a test folder on %s: %v", root, err)
	}
	defer os.Remove(dir)

	// Markers: refused, and the message has to say what to do instead rather than
	// only what is wrong.
	if _, _, _, err := openWatchedFolderAsClient(dir, false); err == nil {
		t.Fatal("an exFAT folder was admitted for the marker mechanism; no rule could ever attach there")
	} else if !strings.Contains(err.Error(), "event tracing") {
		t.Errorf("the refusal must point at the mechanism that does work, got %q", err)
	}

	// Event tracing: admitted, because ReadWatch writes nothing to the volume.
	h, identity, normalized, err := openWatchedFolderAsClient(dir, true)
	if err != nil {
		t.Fatalf("an exFAT folder was refused for event tracing, which is the whole point of the mechanism: %v", err)
	}
	defer closeHandle(h)

	if !strings.EqualFold(normalized, dir) {
		t.Errorf("normalized path = %q, want %q", normalized, dir)
	}
	if !identity.VolumeOnly() {
		t.Fatalf("expected a volume-only identity on a filesystem with no file identity, got %+v", identity)
	}
	if identity.VolumeGUID == "" {
		t.Error("even without file identity the binding must name the volume, or it cannot notice a different disk")
	}
	if identity.VolumeSerial != uint64(traits.Serial) {
		t.Errorf("volume serial = %d, want %d", identity.VolumeSerial, traits.Serial)
	}
	if !strings.EqualFold(identity.FileSystem, "exFAT") {
		t.Errorf("filesystem recorded as %q", identity.FileSystem)
	}
}

func TestVolumeOnlyIdentityCannotBeReopenedByIdentity(t *testing.T) {
	// The reopen path exists to find an object ReadWatch changed. It never
	// changes an object on such a volume, so reaching it means a record was
	// written that should not have been - and it must say so rather than reopen
	// something arbitrary.
	root, traits := exfatRoot(t)
	guid, _, _, err := volumeGUIDPath(root + "x")
	if err != nil {
		t.Skipf("cannot resolve %s: %v", root, err)
	}
	id := volumeOnlyIdentity(guid, traits)
	if _, err := openByIdentity(id); err == nil {
		t.Fatal("a volume-only identity was reopened by identity; there is no identity to reopen by")
	}
}
