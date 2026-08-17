package settings

import (
	"strings"
	"testing"
)

func TestChooseMechanismDefaultsToMarkers(t *testing.T) {
	c := ChooseMechanism(MechanismAuto, map[string]bool{`C:\A`: true, `C:\B`: true})
	if c.Use != MechanismMarkers {
		t.Fatalf("all folders capable, auto: chose %q, want markers", c.Use)
	}
	if c.Overridden || len(c.Blocked) != 0 {
		t.Fatalf("nothing was blocked, so nothing was overridden: %+v", c)
	}
}

func TestChooseMechanismFallsBackWhenAFolderCannotCarryAMarker(t *testing.T) {
	// The owner's own USB stick is exFAT, as most are. A configuration that
	// includes one must still monitor, not refuse.
	c := ChooseMechanism(MechanismAuto, map[string]bool{`C:\A`: true, `D:\Stick`: false})
	if c.Use != MechanismETW {
		t.Fatalf("a folder that cannot carry a marker must fall back to ETW, chose %q", c.Use)
	}
	if len(c.Blocked) != 1 || c.Blocked[0] != `D:\Stick` {
		t.Fatalf("blocked list is %v, want just the exFAT folder", c.Blocked)
	}
	if c.Overridden {
		t.Fatal("the owner did not ask for markers, so nothing was overridden")
	}
	if !strings.Contains(c.Reason, `D:\Stick`) {
		t.Fatalf("the reason must name the folder responsible, got %q", c.Reason)
	}
}

func TestChoosingMarkersExplicitlyIsReportedWhenItCannotBeHonoured(t *testing.T) {
	// Running something other than what was asked for, without saying so, is the
	// failure this guards against.
	c := ChooseMechanism(MechanismMarkers, map[string]bool{`D:\Stick`: false})
	if c.Use != MechanismETW {
		t.Fatalf("chose %q; markers are impossible here", c.Use)
	}
	if !c.Overridden {
		t.Fatal("the owner asked for markers and did not get them; that must be reported")
	}
	if !strings.Contains(strings.ToLower(c.Reason), "requested") {
		t.Fatalf("the reason must say the request could not be met, got %q", c.Reason)
	}
}

func TestChoosingETWExplicitlyIsHonouredOnCapableVolumes(t *testing.T) {
	c := ChooseMechanism(MechanismETW, map[string]bool{`C:\A`: true})
	if c.Use != MechanismETW {
		t.Fatalf("chose %q, want the mechanism the owner asked for", c.Use)
	}
	if c.Overridden {
		t.Fatal("the owner's choice was met, so nothing was overridden")
	}
}

func TestAFolderOnAnAbsentDriveDoesNotForceTheMechanism(t *testing.T) {
	// A drive that is out is the resting state of a removable-drive
	// configuration. Letting an absent folder decide the mechanism would change
	// how the whole session runs depending on what happened to be plugged in.
	c := ChooseMechanism(MechanismAuto, map[string]bool{`C:\A`: true})
	if c.Use != MechanismMarkers {
		t.Fatalf("an unknown folder must not force a fallback, chose %q", c.Use)
	}
}

func TestUnknownStoredMechanismIsTreatedAsAuto(t *testing.T) {
	// A hand-edited or corrupted configuration must still start.
	c := ChooseMechanism(Mechanism("magnetics"), map[string]bool{`C:\A`: true})
	if c.Use != MechanismMarkers {
		t.Fatalf("an unrecognised stored value must fall back to auto, chose %q", c.Use)
	}
}

func TestReasonNamesFoldersUpToAPointAndThenCounts(t *testing.T) {
	capable := map[string]bool{}
	for _, f := range []string{`D:\1`, `D:\2`, `D:\3`, `D:\4`} {
		capable[f] = false
	}
	c := ChooseMechanism(MechanismAuto, capable)
	if !strings.Contains(c.Reason, "and 3 other folders") {
		t.Fatalf("a long list must be summarised rather than run on, got %q", c.Reason)
	}
	if len(c.Blocked) != 4 {
		t.Fatalf("the full list is still carried for the UI, got %v", c.Blocked)
	}
}
