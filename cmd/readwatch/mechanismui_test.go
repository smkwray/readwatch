//go:build windows

package main

import (
	"strings"
	"testing"

	"readwatch/internal/settings"
)

func TestMechanismComboRoundTrips(t *testing.T) {
	// The combo's order and the stored value have to agree, or opening Settings
	// and pressing Save would silently change the mechanism.
	for _, m := range []settings.Mechanism{settings.MechanismAuto, settings.MechanismMarkers, settings.MechanismETW} {
		if got := mechanismAtIndex(mechanismIndex(m)); got != m {
			t.Errorf("%q round-tripped to %q", m, got)
		}
	}
	// A stored value ReadWatch does not recognise must select automatic rather
	// than leaving the control blank.
	if mechanismIndex(settings.Mechanism("magnetics")) != 0 {
		t.Error("an unrecognised stored preference must select automatic")
	}
	if mechanismAtIndex(99) != settings.MechanismAuto {
		t.Error("an out-of-range index must resolve to automatic")
	}
}

func TestEveryMechanismChoiceExplainsItself(t *testing.T) {
	// "Markers or ETW" means nothing without the consequence, which is the whole
	// reason the choice is offered rather than made silently.
	seen := map[string]bool{}
	for _, m := range []settings.Mechanism{settings.MechanismAuto, settings.MechanismMarkers, settings.MechanismETW} {
		text := mechanismHintText(m)
		if strings.TrimSpace(text) == "" {
			t.Fatalf("%q has no explanation", m)
		}
		if seen[text] {
			t.Errorf("%q repeats another choice's explanation", m)
		}
		seen[text] = true
	}
	if !strings.Contains(mechanismHintText(settings.MechanismMarkers), "exFAT") {
		t.Error("the marker choice must say where it cannot be used")
	}
	if !strings.Contains(mechanismHintText(settings.MechanismETW), "memory mapping") {
		t.Error("the tracing choice must say what it cannot see")
	}
}

func TestMechanismLabelIsPlainWords(t *testing.T) {
	if got := mechanismLabel(string(settings.MechanismETW)); got != "event tracing" {
		t.Errorf("summary label = %q; the stored value must never reach the window", got)
	}
	if got := mechanismLabel(string(settings.MechanismMarkers)); got != "audit markers" {
		t.Errorf("summary label = %q", got)
	}
	if mechanismLabel("") != "" {
		t.Error("with no mechanism decided the summary must say nothing rather than guess")
	}
}
