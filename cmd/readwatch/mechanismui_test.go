//go:build windows

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"readwatch/internal/model"
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

func TestEnrichmentRefusesAProcessThatStartedAfterTheRead(t *testing.T) {
	// Windows reuses process ids, and enrichment runs after the deferred sweep,
	// so the gap can be seconds wide. A process that started after the read
	// cannot be the one that made it, and naming it would attribute a read to an
	// innocent process.
	self, _, _ := procOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(os.Getpid()))
	if self == 0 {
		t.Skip("cannot open own process")
	}
	defer procCloseHandle.Call(self)

	// This process plainly exists now, so a read timed now is attributable.
	if !startedBefore(self, time.Now().UTC()) {
		t.Fatal("a live process was rejected for a read happening now")
	}
	// A read from before this process existed is not.
	if startedBefore(self, time.Now().UTC().Add(-24*time.Hour)) {
		t.Error("a read from before this process started was attributed to it")
	}
	// An unreadable handle is a refusal, not a pass.
	if startedBefore(0, time.Now().UTC()) {
		t.Error("an unqueryable process was treated as verified")
	}
}

func TestEnrichmentLeavesFieldsBlankWhenIdentityIsUnproven(t *testing.T) {
	// Better a read with no process named than a read naming the wrong one.
	s := &etwSource{}
	e := model.Event{PID: 0xFFFFFFF0, Time: time.Now().UTC()}
	s.Enrich(&e)
	if e.Process != "" || e.ProcessPath != "" || e.User != "" {
		t.Fatalf("an unresolvable pid was given an identity: %+v", e)
	}
}
