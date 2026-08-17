//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"readwatch/internal/settings"
)

func TestValidateLexicalPathRejections(t *testing.T) {
	rejected := map[string]string{
		"":                          "empty",
		"   ":                       "blank",
		`Docs`:                      "relative",
		`\Docs`:                     "drive-relative",
		`C:Docs`:                    "drive-relative without separator",
		`\\server\share\docs`:       "UNC",
		`//server/share`:            "UNC with forward slashes",
		`\\?\C:\Docs`:               "extended-length device path",
		`\\.\PhysicalDrive0`:        "device namespace",
		`\??\C:\Docs`:               "object-manager path",
		`C:\Docs:hidden`:            "alternate data stream",
		`C:\Docs\..\Windows`:        "parent traversal",
		`C:\Docs\.\Sub`:             "current-directory component",
		`C:\Docs\Sub.`:              "component ending in a dot",
		`C:\Docs\Sub \Deep`:         "interior component ending in a space",
		`C:\Docs\Sub.\Deep`:         "interior component ending in a dot",
		`C:\Docs\*`:                 "wildcard",
		`C:\Docs\\Sub`:              "empty component",
		"C:\\Docs\x00\\Sub":         "embedded NUL",
		`1:\Docs`:                   "not a drive letter",
		`GLOBALROOT\Device\Foo`:     "device alias",
		`C:\Docs\Sub\..\..\Windows`: "traversal beyond the root",
	}
	for path, why := range rejected {
		if got, err := validateLexicalPath(path); err == nil {
			t.Errorf("%s (%s) was accepted as %q, want rejection", path, why, got)
		}
	}
}

func TestValidateLexicalPathNormalises(t *testing.T) {
	cases := map[string]string{
		`C:\Docs\Sub`:  `C:\Docs\Sub`,
		`c:\docs\sub`:  `C:\docs\sub`,
		`C:/Docs/Sub`:  `C:\Docs\Sub`,
		`C:\Docs\Sub\`: `C:\Docs\Sub`,
		// A deep path with an all-caps component: the case a real report showed
		// rendered wrongly, which turned out to be the path itself, not a defect.
		`C:\AI\Renders\batch\output`: `C:\AI\Renders\batch\output`,
		// A whole drive is a legitimate thing to watch, and for a removable drive
		// it is the obvious unit. Everything below this gate works on a volume
		// root - measured against NTFS on both NVMe and USB - so the refusal that
		// used to live here was ReadWatch's own rule, not a Windows limit.
		// `D:` on its own stays rejected: bare drive letters are relative to that
		// drive's current directory, which is not a location.
		`D:\`:  `D:\`,
		`d:\`:  `D:\`,
		`D:/`:  `D:\`,
		`D:\\`: `D:\`,
	}
	for in, want := range cases {
		got, err := validateLexicalPath(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("%s normalised to %q, want %q", in, got, want)
		}
	}
}

// The component walk opens every ancestor with a share mode narrow enough to
// stop one being swapped mid-walk. That is the part most likely to be too
// strict in practice, so it is exercised against a real directory under the
// temp tree - which sits several levels below the volume root and inside the
// user profile, the ancestors a real watched folder will have.
func TestWalkAncestorsOnRealDirectory(t *testing.T) {
	dir := t.TempDir()
	lexical, err := validateLexicalPath(dir)
	if err != nil {
		t.Fatalf("temp dir %s was rejected: %v", dir, err)
	}
	volumeGUID, internal, traits, err := volumeGUIDPath(lexical)
	if err != nil {
		t.Fatalf("resolve volume for %s: %v", lexical, err)
	}
	if !strings.HasPrefix(volumeGUID, `\\?\Volume{`) {
		t.Fatalf("volume name = %q, want a \\\\?\\Volume{...} path", volumeGUID)
	}
	guards, err := walkAncestors(volumeGUID, internal, traits)
	if err != nil {
		t.Fatalf("walk ancestors of %s: %v", internal, err)
	}
	if len(guards) < 2 {
		t.Fatalf("walk produced %d handles, want the volume root plus each parent", len(guards))
	}
	releaseGuards(guards)
}

// A junction anywhere in the path is refused rather than followed. Creating one
// needs no privilege for a directory junction via mklink /J, so this runs as an
// ordinary user; if the host refuses to create it the test says so rather than
// passing silently.
func TestWalkRefusesJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := makeJunction(link, target); err != nil {
		t.Skipf("could not create a junction on this host: %v", err)
	}

	// The junction itself.
	lexical, err := validateLexicalPath(link)
	if err != nil {
		t.Fatal(err)
	}
	volumeGUID, internal, traits, err := volumeGUIDPath(lexical)
	if err != nil {
		t.Fatal(err)
	}
	h, err := openDirectoryComponent(internal, traits)
	if err == nil {
		closeHandle(h)
		t.Error("opening a junction as a path component succeeded, want refusal")
	} else if !strings.Contains(err.Error(), "junction") {
		t.Errorf("junction refused with %v, want a message naming the junction", err)
	}

	// And a path that merely goes through it.
	through := filepath.Join(link, "inner")
	if err := os.Mkdir(filepath.Join(target, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	lexical, err = validateLexicalPath(through)
	if err != nil {
		t.Fatal(err)
	}
	volumeGUID, internal, traits, err = volumeGUIDPath(lexical)
	if err != nil {
		t.Fatal(err)
	}
	if guards, err := walkAncestors(volumeGUID, internal, traits); err == nil {
		releaseGuards(guards)
		t.Error("walking through a junction succeeded, want refusal")
	}
}

// Identity is the whole premise: it must survive a rename and must not be
// forgeable by putting a different folder at the same path.
func TestIdentitySurvivesRenameAndDistinguishesReplacement(t *testing.T) {
	base := t.TempDir()
	original := filepath.Join(base, "watched")
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}

	held, first, _, err := openWatchedFolderAsClientForTest(original)
	if err != nil {
		t.Fatalf("open %s: %v", original, err)
	}
	if first.Zero() {
		t.Fatal("identity of a real folder came back empty")
	}

	// The folder handle is opened without FILE_SHARE_DELETE precisely so the
	// watched root cannot be renamed or deleted while it is being watched.
	// Prove that holds before releasing it.
	renamed := filepath.Join(base, "moved")
	if err := os.Rename(original, renamed); err == nil {
		t.Error("the watched folder was renamed while ReadWatch held it open; the audit rule could be moved off the object it was applied to")
	}
	closeHandle(held)

	if err := os.Rename(original, renamed); err != nil {
		t.Fatalf("rename after releasing the handle: %v", err)
	}
	afterHandle, afterRename, _, err := openWatchedFolderAsClientForTest(renamed)
	if err != nil {
		t.Fatalf("open %s after rename: %v", renamed, err)
	}
	closeHandle(afterHandle)
	if !first.Equal(afterRename) {
		t.Error("renaming the folder changed its identity; a rename must not look like a substitution")
	}

	// A different folder now occupying the original path is a different object.
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	impostorHandle, impostor, _, err := openWatchedFolderAsClientForTest(original)
	if err != nil {
		t.Fatalf("open replacement at %s: %v", original, err)
	}
	closeHandle(impostorHandle)
	if first.Equal(impostor) {
		t.Error("a different folder at the same path produced the same identity; substitution would go unnoticed")
	}
}

// The binder opens a second handle by file ID while the owner's original
// no-delete handle is still open. This proves the two coexist, and pins down
// which of them actually holds the folder still.
//
// The answer is not the identity handle. It asks for no data access, and
// Windows exempts attribute-only opens from share-mode enforcement, so on its
// own it does not stop a rename - the first version of this test asserted that
// it did and failed here on the host. That is why the binder keeps the owner
// handle for the whole session rather than closing it once the identity handle
// exists.
//
// Ordinary attribute access is used deliberately; the privileged
// ACCESS_SYSTEM_SECURITY open needs the service and is covered by a host run.
func TestOpenByIdentityHandoffKeepsRootPinned(t *testing.T) {
	base := t.TempDir()
	original := filepath.Join(base, "watched")
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}

	ownerHandle, identity, _, err := openWatchedFolderAsClientForTest(original)
	if err != nil {
		t.Fatalf("open %s as owner: %v", original, err)
	}
	ownerOpen := true
	defer func() {
		if ownerOpen {
			closeHandle(ownerHandle)
		}
	}()

	identityHandle, err := openByIdentityWithAccess(identity, FILE_READ_ATTRIBUTES)
	if err != nil {
		t.Fatalf("open %s by identity while the owner handle is open: %v", original, err)
	}
	identityOpen := true
	defer func() {
		if identityOpen {
			closeHandle(identityHandle)
		}
	}()

	// While the owner handle is open, the folder is pinned.
	renamed := filepath.Join(base, "moved")
	if err := os.Rename(original, renamed); err == nil {
		t.Fatal("the folder was renamed while the owner handle was open; the audit rule could be moved off the object it was applied to")
	}

	// Close it, and the identity handle alone does not hold the folder. This is
	// the measurement the binder's lifetime decision rests on: if this ever
	// starts blocking renames, the owner handle could be released at bind time.
	closeHandle(ownerHandle)
	ownerOpen = false
	if err := os.Rename(original, renamed); err != nil {
		t.Fatalf("an attribute-only identity handle blocked a rename, which the binder does not rely on: %v", err)
	}
	if err := os.Rename(renamed, original); err != nil {
		t.Fatal(err)
	}

	closeHandle(identityHandle)
	identityOpen = false
}

// openWatchedFolderAsClientForTest runs the binder's per-folder open without
// impersonation, which is what a test can do: the tests here are about what the
// walk and identity capture accept, not about whose token is in force.
func openWatchedFolderAsClientForTest(path string) (HANDLE, settings.ObjectIdentity, string, error) {
	return openWatchedFolderAsClient(path, false)
}

// makeJunction shells out to mklink because creating a reparse point through
// DeviceIoControl is a large amount of interop for a test fixture.
func makeJunction(link, target string) error {
	cmd := exec.Command("cmd", "/c", "mklink", "/J", link, target)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
