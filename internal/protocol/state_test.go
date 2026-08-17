package protocol

import "testing"

// The window reports what happened to every configured folder, so the counts
// have to add up to the list in Settings and a folder that needs the owner has
// to be findable among the ones that merely need a drive.
func TestFolderCounts(t *testing.T) {
	state := State{Folders: []FolderStatus{
		{Path: `C:\Watched`, State: FolderAvailable},
		{Path: `X:\Photos`, State: FolderWaiting, Detail: "the drive is not attached"},
		{Path: `Y:\Share`, State: FolderRefused, Detail: "network drives are not supported"},
		{Path: `F:\Card`, State: FolderWaiting, Detail: "the drive is not attached"},
	}}
	available, waiting, refused := state.Counts()
	if available != 1 || waiting != 2 || refused != 1 {
		t.Fatalf("counts are %d available, %d waiting, %d refused; want 1, 2, 1", available, waiting, refused)
	}
	first, ok := state.FirstRefused()
	if !ok || first.Path != `Y:\Share` {
		t.Fatalf("first refused folder is %+v (found=%v), want Y:\\Share", first, ok)
	}
}

func TestNoRefusedFolder(t *testing.T) {
	state := State{Folders: []FolderStatus{{Path: `X:\Photos`, State: FolderWaiting}}}
	if _, ok := state.FirstRefused(); ok {
		t.Error("a folder waiting for its drive was reported as one the owner has to act on")
	}
}
