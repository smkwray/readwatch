//go:build windows

package main

import (
	"strings"
	"syscall"
	"testing"
)

// PendingFileRenameOperations is a flat list of pairs: a source, then a
// destination, with an empty destination meaning "delete this at reboot". Its
// parsing has to keep those empty entries, because they are the whole meaning of
// a delete order, and it has to leave other software's entries alone.
func TestSplitMultiSZKeepsEmptyEntries(t *testing.T) {
	// \??\C:\a  ""  \??\C:\b  \??\C:\c
	var buf []uint16
	for _, s := range []string{`\??\C:\a`, ``, `\??\C:\b`, `\??\C:\c`} {
		buf = append(buf, syscall.StringToUTF16(s)...)
	}
	buf = append(buf, 0)

	got := splitMultiSZ(buf)
	want := []string{`\??\C:\a`, ``, `\??\C:\b`, `\??\C:\c`}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitMultiSZOnEmptyInput(t *testing.T) {
	if got := splitMultiSZ([]uint16{0}); len(got) != 0 {
		t.Fatalf("an empty value produced %q", got)
	}
	if got := splitMultiSZ(nil); len(got) != 0 {
		t.Fatalf("a nil value produced %q", got)
	}
}

// filterPending is the decision cancelPendingDeletion makes, exercised without
// touching the real registry: drop the delete orders naming our own paths, and
// pass everything else through untouched.
func filterPending(existing []string, wanted []string) (kept []string, removed int) {
	lower := make([]string, 0, len(wanted))
	for _, w := range wanted {
		lower = append(lower, strings.ToLower(w))
	}
	for i := 0; i < len(existing); i++ {
		source := existing[i]
		var target string
		if i+1 < len(existing) {
			target = existing[i+1]
		}
		trimmed := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(source, `\??\`), `*1\??\`))
		mine := false
		for _, w := range lower {
			if trimmed == w {
				mine = true
				break
			}
		}
		if mine && target == "" {
			removed++
			i++
			continue
		}
		kept = append(kept, source)
		if i+1 < len(existing) {
			kept = append(kept, target)
			i++
		}
	}
	return kept, removed
}

func TestPendingFilterRemovesOnlyOurDeleteOrders(t *testing.T) {
	// The uninstall queues our exe and folder for deletion. Installing over that
	// without cancelling leaves the order standing, and the next restart deletes
	// the copy just installed - the program vanishes on reboot with no
	// explanation. Other software's entries must survive untouched.
	existing := []string{
		`\??\C:\Other\thing.dll`, `\??\C:\Other\thing.dll.new`, // somebody's rename
		`*1\??\C:\Program Files\ReadWatch\ReadWatch.exe`, ``, // ours, delete
		`\??\C:\Vendor\leftover.tmp`, ``, // somebody's delete
		`*1\??\C:\Program Files\ReadWatch`, ``, // ours, delete
	}
	kept, removed := filterPending(existing, []string{
		`C:\Program Files\ReadWatch\ReadWatch.exe`,
		`C:\Program Files\ReadWatch`,
	})
	if removed != 2 {
		t.Fatalf("removed %d of our delete orders, want 2", removed)
	}
	want := []string{
		`\??\C:\Other\thing.dll`, `\??\C:\Other\thing.dll.new`,
		`\??\C:\Vendor\leftover.tmp`, ``,
	}
	if len(kept) != len(want) {
		t.Fatalf("kept %q, want %q", kept, want)
	}
	for i := range want {
		if kept[i] != want[i] {
			t.Fatalf("kept[%d] = %q, want %q (another program's pending operation was disturbed)", i, kept[i], want[i])
		}
	}
}

func TestPendingFilterLeavesARenameOfOurPathAlone(t *testing.T) {
	// A rename naming our path is not a delete order and is none of our business.
	existing := []string{`*1\??\C:\Program Files\ReadWatch\ReadWatch.exe`, `\??\C:\Backup\ReadWatch.exe`}
	kept, removed := filterPending(existing, []string{`C:\Program Files\ReadWatch\ReadWatch.exe`})
	if removed != 0 {
		t.Fatal("a rename was treated as a delete order")
	}
	if len(kept) != 2 {
		t.Fatalf("kept %q, want the pair intact", kept)
	}
}

func TestSplitMultiSZKeepsATrailingEmptyEntry(t *testing.T) {
	// The defect this pins: a list ending in somebody else's delete order came
	// back one element short, and rewriting it would have left their source with
	// no destination - a malformed pending operation in a machine-wide value.
	var buf []uint16
	for _, s := range []string{`ours`, ``, `edge`, ``} {
		buf = append(buf, syscall.StringToUTF16(s)...)
	}
	buf = append(buf, 0)

	got := splitMultiSZ(buf)
	want := []string{`ours`, ``, `edge`, ``}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestOurDeleteInEveryPositionIsRemoved(t *testing.T) {
	// First, middle and last. The last position is the one that was broken.
	ours := `C:\Program Files\ReadWatch\ReadWatch.exe`
	cases := map[string][]string{
		"first":  {`*1\??\` + ours, ``, `\??\C:\Other\x`, ``},
		"middle": {`\??\C:\A\x`, ``, `*1\??\` + ours, ``, `\??\C:\B\y`, ``},
		"last":   {`\??\C:\Other\x`, ``, `*1\??\` + ours, ``},
	}
	for pos, existing := range cases {
		before := len(existing)
		kept, removed := filterPending(existing, []string{ours})
		if removed != 1 {
			t.Errorf("%s: removed %d, want 1", pos, removed)
		}
		if len(kept) != before-2 {
			t.Errorf("%s: kept %d entries %q, want %d", pos, len(kept), kept, before-2)
		}
		if len(kept)%2 != 0 {
			t.Errorf("%s: kept an odd number of entries %q - a pair was broken", pos, kept)
		}
		for _, k := range kept {
			if strings.Contains(strings.ToLower(k), "readwatch") {
				t.Errorf("%s: our own entry survived as %q", pos, k)
			}
		}
	}
}
