//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"readwatch/internal/protocol"
	"readwatch/internal/settings"
)

// A watched folder may live on a drive that is not always in the machine. These
// tests pin the two things that decision rests on: telling "not here right now"
// apart from "not here ever", and never losing what the owner authorised while
// it is away.

// freeDriveLetter finds a letter with no volume behind it, which is what a
// removable drive looks like when it is unplugged. Z downwards, because the
// early letters are the ones a host is likely to be using.
func freeDriveLetter(t *testing.T) string {
	t.Helper()
	mask, _, _ := procGetLogicalDrives.Call()
	for i := 25; i >= 0; i-- {
		if uint32(mask)&(1<<uint(i)) == 0 {
			return string(rune('A'+i)) + ":"
		}
	}
	t.Skip("every drive letter is in use on this host")
	return ""
}

// The whole point: a path on a drive that is not attached is a legitimate thing
// to configure. The Settings dialog and the service share this function, so if
// it rejects the path there is no way to add one at all.
func TestValidateLexicalPathAcceptsAnUnattachedDrive(t *testing.T) {
	letter := freeDriveLetter(t)
	got, err := validateLexicalPath(letter + `\Photos\Raw`)
	if err != nil {
		t.Fatalf("%s\\Photos\\Raw was rejected because the drive is not attached: %v", letter, err)
	}
	if want := letter + `\Photos\Raw`; got != want {
		t.Errorf("normalised to %q, want %q", got, want)
	}
}

func TestUnattachedDriveLetterIsWaiting(t *testing.T) {
	letter := freeDriveLetter(t)
	root := letter + `\`
	if dt := driveType(root); dt != DRIVE_NO_ROOT_DIR {
		t.Fatalf("GetDriveType(%s) = %d, want DRIVE_NO_ROOT_DIR(%d); the letter is not actually free", root, dt, DRIVE_NO_ROOT_DIR)
	}
	_, _, err := volumeGUIDPath(letter + `\Photos`)
	if err == nil {
		t.Fatalf("%s\\Photos resolved to a volume although %s is not attached", letter, letter)
	}
	if !errors.Is(err, errDriveNotAttached) {
		t.Errorf("resolving %s\\Photos gave %v, want it to report the drive as not attached", letter, err)
	}
	if !waitingOpenFailure(err) {
		t.Error("an unattached drive was classified as a folder ReadWatch will not watch, rather than one it is waiting for")
	}
}

// The bind path as a whole, not just the volume lookup: an unreachable folder
// has to come back as "waiting" all the way out, because that classification is
// what decides whether the other folders keep being watched.
func TestOpenWatchedFolderClassifiesUnreachableFolders(t *testing.T) {
	letter := freeDriveLetter(t)
	cases := map[string]string{
		"a drive that is not attached": letter + `\Photos`,
		"a folder that does not exist": filepath.Join(t.TempDir(), "missing", "deeper"),
	}
	for why, path := range cases {
		h, _, _, err := openWatchedFolderAsClient(path)
		if err == nil {
			closeHandle(h)
			t.Errorf("%s (%s) opened successfully", path, why)
			continue
		}
		if !waitingOpenFailure(err) {
			t.Errorf("%s (%s) failed with %v, which is classified as permanent; it should be waiting", path, why, err)
		}
	}
}

// A junction and a network drive must NOT read as waiting. Calling a permanent
// refusal "waiting" would hide it behind a status that never resolves.
func TestPermanentRefusalsAreNotWaiting(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := makeJunction(link, target); err != nil {
		t.Skipf("could not create a junction on this host: %v", err)
	}
	h, _, _, err := openWatchedFolderAsClient(link)
	if err == nil {
		closeHandle(h)
		t.Fatal("a junction was accepted as a watched folder")
	}
	if waitingOpenFailure(err) {
		t.Errorf("a junction was classified as waiting (%v); it will never resolve on its own", err)
	}
}

// openByIdentity has two opens and they mean different things. This is the
// distinction that decides whether an audit rule is remembered or abandoned, and
// by error number alone the two are identical - both are ERROR_FILE_NOT_FOUND on
// this host - so it has to come from which open failed.
func TestUnattachedVolumeKeepsItsRecord(t *testing.T) {
	absent := settings.ObjectIdentity{
		VolumeGUID:  `\\?\Volume{00000000-0000-0000-0000-000000000000}\`,
		FileSystem:  "NTFS",
		FileIndex64: 42,
	}
	h, err := openByIdentityWithAccess(absent, FILE_READ_ATTRIBUTES)
	if err == nil {
		closeHandle(h)
		t.Fatal("a volume GUID that does not exist was opened")
	}
	if !errors.Is(err, errVolumeUnavailable) {
		t.Fatalf("opening an unattached volume gave %v, want it to report the volume as unavailable", err)
	}
	if !transientOpenFailure(err) {
		t.Error("an unattached volume was treated as gone for good; the audit rule on that disk would be forgotten")
	}
	if !deferredRemoval(err) {
		t.Error("an unattached volume was not reported as a deferred removal, so it would be raised as a fault instead")
	}
}

// The other half of the same distinction, and the one that keeps a deleted
// folder from stranding the app: the volume is right here, the object is not, so
// the record must be dropped rather than kept forever.
func TestDeletedFolderOnAnAttachedVolumeIsGone(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "watched")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	handle, identity, _, err := openWatchedFolderAsClient(dir)
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	closeHandle(handle)
	if err := os.Remove(dir); err != nil {
		t.Fatalf("remove %s: %v", dir, err)
	}

	h, err := openByIdentityWithAccess(identity, FILE_READ_ATTRIBUTES)
	if err == nil {
		closeHandle(h)
		t.Skip("the deleted folder was still reachable by file identity on this filesystem")
	}
	if errors.Is(err, errVolumeUnavailable) {
		t.Fatalf("a deleted folder on a mounted volume was reported as an unattached drive: %v", err)
	}
	if transientOpenFailure(err) {
		t.Errorf("a deleted folder was treated as a condition that will clear (%v); its record would block Stop, Apply and uninstall forever", err)
	}
}

// What the owner is told about a folder that is not there. The raw error names
// the \\?\Volume{...} path the walk built, which is no use in a window, and an
// unplugged drive must not read the same as a path that was mistyped.
func TestWaitingReasonIsReadable(t *testing.T) {
	letter := freeDriveLetter(t)
	_, _, driveErr := volumeGUIDPath(letter + `\Photos`)
	if driveErr == nil {
		t.Fatalf("%s resolved although it is not attached", letter)
	}
	if got := waitingReason(driveErr); got != "the drive is not attached" {
		t.Errorf("an unattached drive reads as %q", got)
	}

	_, _, _, missingErr := openWatchedFolderAsClient(filepath.Join(t.TempDir(), "missing", "deeper"))
	if missingErr == nil {
		t.Fatal("a folder that does not exist was opened")
	}
	got := waitingReason(missingErr)
	if got != "this folder does not exist" {
		t.Errorf("a missing folder on an attached drive reads as %q, want it distinguished from an unplugged drive", got)
	}
	if strings.Contains(got, `\\?\Volume`) || strings.Contains(got, "CreateFile") {
		t.Errorf("the reason shown to the owner leaks an internal path or API name: %q", got)
	}
}

// The log has no partial state, so an unreachable log stops monitoring - and the
// message has to say it was the log, because a watched folder on the same
// unplugged drive produces word-for-word the same underlying error.
func TestLogOnAnUnattachedDriveSaysItIsTheLog(t *testing.T) {
	letter := freeDriveLetter(t)
	h, _, _, err := openLogAsClient(letter + `\Logs\readwatch.log`)
	if err == nil {
		closeHandle(h)
		t.Fatalf("a log on %s was opened although the drive is not attached", letter)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "log") {
		t.Errorf("the log's failure reads %q, which never mentions the log", err)
	}
	if !errors.Is(err, errDriveNotAttached) {
		t.Errorf("the log's failure is %v, want it to report the drive as not attached", err)
	}
}

func TestAbsentDeviceErrnoCoversTheMeasuredCodes(t *testing.T) {
	// Measured on this host, not assumed: a free drive letter and an unattached
	// \\?\Volume{...} name both fail with ERROR_FILE_NOT_FOUND. Leaving that out
	// is what made an unplugged drive look permanently gone.
	waiting := []uintptr{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_NOT_READY, ERROR_DEV_NOT_EXIST, ERROR_NO_MEDIA_IN_DRIVE}
	for _, code := range waiting {
		if !absentDeviceErrno(syscall.Errno(code)) {
			t.Errorf("error %d is not treated as an absent device", code)
		}
	}
	for _, code := range []uintptr{ERROR_ACCESS_DENIED, ERROR_SUCCESS} {
		if absentDeviceErrno(syscall.Errno(code)) {
			t.Errorf("error %d is treated as an absent device", code)
		}
	}
	// Access denied is a decision about the owner, not about where the disk is.
	if waitingOpenFailure(errors.New("your account cannot open this folder: " + syscall.Errno(ERROR_ACCESS_DENIED).Error())) {
		t.Error("a permission failure was classified as waiting")
	}
}

// The security invariant behind partial binding. A folder that could not be
// opened keeps the identity it was last authorised with, because
// refuseChangedIdentities reads a missing binding as "never authorised, this
// bind decides" - so losing one would let the next volume to claim that drive
// letter be watched, and given a SACL by LocalSystem, with nobody deciding.
func TestBindingSurvivesAnUnreachableFolder(t *testing.T) {
	onDisk := settings.ObjectIdentity{VolumeGUID: "vol-c", FileIndex64: 7, CreationTime: 11}
	onStick := settings.ObjectIdentity{VolumeGUID: "vol-usb", FileIndex64: 9, CreationTime: 13}
	previous := map[string]settings.ObjectBinding{
		`c:\watched`: {Path: `C:\Watched`, Identity: onDisk},
		`x:\photos`:  {Path: `X:\Photos`, Identity: onStick},
		`d:\removed`: {Path: `D:\Removed`, Identity: settings.ObjectIdentity{VolumeGUID: "vol-d", FileIndex64: 3, CreationTime: 5}},
	}
	bound := &BoundConfig{
		Public:      settings.PublicConfig{Folders: []string{`C:\Watched`, `X:\Photos`}},
		Folders:     []FolderCapability{{Path: `C:\Watched`, Identity: onDisk}},
		Unavailable: []FolderUnavailable{{Path: `X:\Photos`, Reason: "the drive is not attached", Waiting: true}},
	}

	folders, _ := bound.MergeBindings(previous)
	kept, ok := folders[`x:\photos`]
	if !ok {
		t.Fatal("the binding for a folder whose drive was out was dropped; the next volume on that letter would be watched without being authorised")
	}
	if !kept.Identity.Equal(onStick) {
		t.Errorf("the retained binding is %+v, want the identity that was authorised %+v", kept.Identity, onStick)
	}
	if _, ok := folders[`d:\removed`]; ok {
		t.Error("a folder the owner removed from the configuration kept its binding")
	}
	if len(folders) != 2 {
		t.Errorf("kept %d bindings, want one per configured folder", len(folders))
	}
}

func TestRefuseChangedIdentitiesIsPerFolder(t *testing.T) {
	authorised := settings.ObjectIdentity{VolumeGUID: "vol-usb", FileIndex64: 9, CreationTime: 13}
	impostor := settings.ObjectIdentity{VolumeGUID: "vol-other", FileIndex64: 9, CreationTime: 13}
	stable := settings.ObjectIdentity{VolumeGUID: "vol-c", FileIndex64: 7, CreationTime: 11}
	cfg := &settings.Config{FolderBindings: map[string]settings.ObjectBinding{
		`c:\watched`: {Path: `C:\Watched`, Identity: stable},
		`x:\photos`:  {Path: `X:\Photos`, Identity: authorised},
	}}
	bound := &BoundConfig{
		Public: settings.PublicConfig{Folders: []string{`C:\Watched`, `X:\Photos`, `E:\New`}},
		Folders: []FolderCapability{
			{Path: `C:\Watched`, Identity: stable},
			{Path: `X:\Photos`, Identity: impostor},
			{Path: `E:\New`, Identity: settings.ObjectIdentity{VolumeGUID: "vol-e", FileIndex64: 1, CreationTime: 2}},
		},
	}

	refuseChangedIdentities(cfg, bound)

	attached := bound.AttachedPaths()
	if len(attached) != 2 {
		t.Fatalf("attached folders are %v, want the two that are still what they were", attached)
	}
	for _, path := range attached {
		if strings.EqualFold(path, `X:\Photos`) {
			t.Error("a folder whose identity changed is still being watched")
		}
	}
	if len(bound.Unavailable) != 1 || !strings.EqualFold(bound.Unavailable[0].Path, `X:\Photos`) {
		t.Fatalf("unavailable is %+v, want only the substituted folder", bound.Unavailable)
	}
	if bound.Unavailable[0].Waiting {
		t.Error("a substituted folder was reported as waiting; it needs the owner, and nothing will change it on its own")
	}
	// A folder with no recorded binding has never been opened - it was added
	// while its drive was out - so this bind is what authorises it.
	for _, path := range attached {
		if strings.EqualFold(path, `E:\New`) {
			return
		}
	}
	t.Error("a folder that has never been authorised was refused, so a folder added while its drive was out could never start being watched")
}

// A folder leaving the attached set must not leave the configuration. Persisting
// only what opened is how a watched folder would silently disappear from
// Settings the first time its drive was unplugged.
func TestUnavailableFolderStaysConfigured(t *testing.T) {
	bound := &BoundConfig{
		Public: settings.PublicConfig{Folders: []string{`C:\Watched`, `X:\Photos`}},
		Folders: []FolderCapability{
			{Path: `C:\Watched`},
			{Path: `X:\Photos`},
		},
	}
	bound.markUnavailable(1, errors.New("the drive is not attached"), true)

	if len(bound.Public.Folders) != 2 {
		t.Fatalf("configured folders are %v, want both still listed", bound.Public.Folders)
	}
	if paths := bound.AttachedPaths(); len(paths) != 1 || paths[0] != `C:\Watched` {
		t.Errorf("attached folders are %v, want only the reachable one", paths)
	}
	if len(bound.Unavailable) != 1 || !bound.Unavailable[0].Waiting {
		t.Errorf("unavailable is %+v, want the unreachable folder recorded as waiting", bound.Unavailable)
	}
}

// Audit rules are applied to the attached folders and to nothing else, so this
// is what decides which objects LocalSystem touches.
func TestEffectiveAuditRootsCollapsesNestedFolders(t *testing.T) {
	roots := effectiveAuditRoots([]string{`C:\A\B\C`, `C:\A`, `D:\Other`, `C:\A\B`})
	if len(roots) != 2 {
		t.Fatalf("roots are %v, want the two outermost", roots)
	}
	got := strings.ToLower(strings.Join(roots, "|"))
	if !strings.Contains(got, `c:\a`) || !strings.Contains(got, `d:\other`) {
		t.Errorf("roots are %v, want C:\\A and D:\\Other", roots)
	}
	if len(effectiveAuditRoots(nil)) != 0 {
		t.Error("no attached folders produced a root to apply a rule to")
	}
}

// A count on its own is enough for a drive the owner unplugged themselves. It
// is not enough for a path they mistyped, which is why the status line names one.
func TestWaitingSuffixNamesTheFolder(t *testing.T) {
	none := protocol.State{Folders: []protocol.FolderStatus{{Path: `C:\Watched`, State: protocol.FolderAvailable}}}
	if got := waitingSuffix(none); got != "" {
		t.Errorf("with nothing waiting the status line gained %q", got)
	}

	one := protocol.State{Folders: []protocol.FolderStatus{
		{Path: `C:\Watched`, State: protocol.FolderAvailable},
		{Path: `C:\Rendrs`, State: protocol.FolderWaiting, Detail: "this folder does not exist"},
	}}
	got := waitingSuffix(one)
	if !strings.Contains(got, `C:\Rendrs`) || !strings.Contains(got, "does not exist") {
		t.Errorf("the status line reads %q, want it to name the folder and say why", got)
	}

	two := protocol.State{Folders: []protocol.FolderStatus{
		{Path: `X:\Photos`, State: protocol.FolderWaiting, Detail: "the drive is not attached"},
		{Path: `F:\Card`, State: protocol.FolderWaiting, Detail: "the drive is not attached"},
	}}
	if got := waitingSuffix(two); !strings.Contains(got, `X:\Photos`) || !strings.Contains(got, "1 more") {
		t.Errorf("with two waiting the status line reads %q", got)
	}
}

func TestMatchesAnyFolder(t *testing.T) {
	watched := []string{`C:\Watched`}
	for _, path := range []string{`C:\Watched\file.txt`, `C:\Watched`, `c:\watched\deep\file.txt`} {
		if !matchesAnyFolder(path, watched) {
			t.Errorf("%s did not match the watched folder", path)
		}
	}
	for _, path := range []string{`C:\WatchedElsewhere\file.txt`, `D:\Watched\file.txt`} {
		if matchesAnyFolder(path, watched) {
			t.Errorf("%s matched the watched folder", path)
		}
	}
	if matchesAnyFolder(`X:\Photos\a.jpg`, nil) {
		t.Error("a read matched although no folder is attached")
	}
}
