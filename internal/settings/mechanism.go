package settings

import (
	"fmt"
	"sort"
	"strings"
)

// Mechanism names how ReadWatch observes reads. The two are genuinely
// different trades rather than an old way and a new way, which is why both are
// kept:
//
//   - Markers put an audit rule on the watched folder. Switching them on and off
//     costs about a tenth of a millisecond per file, so an ordinary folder is
//     imperceptible and a whole drive takes minutes. After that they generate
//     events only for what is watched, and they report a read made through a
//     memory mapping. They cannot be attached to exFAT or FAT at all.
//   - ETW writes nothing to the volume and starts instantly on any filesystem,
//     but the provider cannot be filtered by path, so ReadWatch sees every read
//     on the machine and discards what it did not ask for. It does not report a
//     read made purely through a memory mapping.
type Mechanism string

const (
	// MechanismAuto lets ReadWatch pick. This is the default and the value an
	// owner who has never opened the setting has.
	MechanismAuto Mechanism = ""
	// MechanismMarkers is the audit-rule mechanism.
	MechanismMarkers Mechanism = "markers"
	// MechanismETW is the event-tracing mechanism.
	MechanismETW Mechanism = "etw"
)

// Valid reports whether m is a mechanism ReadWatch knows. A stored value that is
// not is a corrupted or hand-edited configuration, and is treated as auto rather
// than failing to start.
func (m Mechanism) Valid() bool {
	switch m {
	case MechanismAuto, MechanismMarkers, MechanismETW:
		return true
	}
	return false
}

// MechanismChoice is the decision and the sentence explaining it. The sentence
// lives here rather than in the UI so that the rule and its explanation cannot
// drift apart: one conceptual change edits one place.
type MechanismChoice struct {
	Use Mechanism
	// Overridden is true when the owner asked for markers and could not have
	// them. It is not an error - monitoring proceeds - but the UI must say so
	// rather than silently running something other than what was asked for.
	Overridden bool
	// Blocked names the watched folders that cannot carry a marker, in the order
	// they should be shown.
	Blocked []string
	Reason  string
}

// ChooseMechanism decides which mechanism a session runs with. markerCapable
// says, for each watched folder, whether that folder's volume can carry an audit
// rule; a folder missing from the map is treated as capable, because a folder on
// a drive that is not attached must not force the whole session onto a different
// mechanism.
//
// Never both at once: an ETW session already reports reads on volumes that could
// carry a marker, so running the two together would report the same read twice.
func ChooseMechanism(pref Mechanism, markerCapable map[string]bool) MechanismChoice {
	if !pref.Valid() {
		pref = MechanismAuto
	}
	var blocked []string
	for folder, ok := range markerCapable {
		if !ok {
			blocked = append(blocked, folder)
		}
	}
	sort.Strings(blocked)

	switch {
	case len(blocked) > 0:
		c := MechanismChoice{Use: MechanismETW, Blocked: blocked, Overridden: pref == MechanismMarkers}
		c.Reason = fmt.Sprintf("Using event tracing: %s cannot carry an audit marker.", joinFolders(blocked))
		if c.Overridden {
			c.Reason += " Markers were requested but cannot be used while that folder is watched."
		}
		return c
	case pref == MechanismETW:
		return MechanismChoice{
			Use:    MechanismETW,
			Reason: "Using event tracing because you chose it. Nothing is written to the watched volumes.",
		}
	default:
		return MechanismChoice{
			Use:    MechanismMarkers,
			Reason: "Using audit markers: every watched folder can carry one, so only they generate events.",
		}
	}
}

// joinFolders renders a folder list the way a sentence needs it, and stops
// naming them individually once the list would be unreadable.
func joinFolders(f []string) string {
	switch len(f) {
	case 0:
		return "no folder"
	case 1:
		return f[0]
	case 2:
		return f[0] + " and " + f[1]
	case 3:
		return strings.Join(f[:2], ", ") + " and " + f[2]
	default:
		return fmt.Sprintf("%s and %d other folders", f[0], len(f)-1)
	}
}
