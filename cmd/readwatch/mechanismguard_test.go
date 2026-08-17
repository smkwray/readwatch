//go:build windows

package main

import (
	"strings"
	"testing"

	"readwatch/internal/settings"
)

// The defect this guards against was real and shipped: the apply path bound the
// candidate configuration but computed the mechanism from the one it was
// replacing. A folder on an exFAT stick was therefore admitted for event
// tracing and then had an audit marker applied to it, which failed several
// layers away with a message about reopening by identity.
func TestMarkersAreRefusedForABindingWithNoFileIdentity(t *testing.T) {
	bound := &BoundConfig{Folders: []FolderCapability{
		{Path: `C:\Watched`, Identity: settings.ObjectIdentity{
			VolumeGUID: `\?\Volume{aaaa}\`, FileIndex64: 42,
		}},
		{Path: `D:\Stick`, Identity: settings.ObjectIdentity{
			VolumeGUID: `\?\Volume{bbbb}\`, FileSystem: "exFAT",
		}},
	}}
	err := refuseMarkersWithoutIdentity(bound)
	if err == nil {
		t.Fatal("markers were allowed over a volume-only binding; the rule could never be removed again")
	}
	if !strings.Contains(err.Error(), `D:\Stick`) {
		t.Errorf("the refusal must name the folder responsible, got %q", err)
	}
	if !strings.Contains(err.Error(), "event tracing") {
		t.Errorf("the refusal must say what should have happened instead, got %q", err)
	}
}

func TestMarkersAreAllowedWhenEveryBindingHasAnIdentity(t *testing.T) {
	bound := &BoundConfig{Folders: []FolderCapability{
		{Path: `C:\Watched`, Identity: settings.ObjectIdentity{
			VolumeGUID: `\?\Volume{aaaa}\`, FileIndex64: 42,
		}},
		{Path: `C:\Other`, Identity: settings.ObjectIdentity{
			VolumeGUID: `\?\Volume{aaaa}\`, FileID128: [16]byte{1},
		}},
	}}
	if err := refuseMarkersWithoutIdentity(bound); err != nil {
		t.Fatalf("ordinary NTFS bindings were refused: %v", err)
	}
	if err := refuseMarkersWithoutIdentity(&BoundConfig{}); err != nil {
		t.Fatalf("an empty binding was refused: %v", err)
	}
}

func TestMechanismComesFromTheConfigurationBeingBound(t *testing.T) {
	// mechanismFor takes the PublicConfig that is about to be bound, so the
	// answer and the binding cannot come from different folder lists. A folder
	// list with nothing in it has nothing that can block markers.
	if got := mechanismFor(settings.PublicConfig{}); got.Use != settings.MechanismMarkers {
		t.Fatalf("an empty configuration chose %q, want markers", got.Use)
	}
	if got := mechanismFor(settings.PublicConfig{Mechanism: settings.MechanismETW}); got.Use != settings.MechanismETW {
		t.Fatalf("an explicit preference was not honoured, chose %q", got.Use)
	}
}
