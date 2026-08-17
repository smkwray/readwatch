//go:build windows

package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"readwatch/internal/settings"
)

// A capability is an open handle to an object the connected owner proved they
// could reach. Everything privileged is done through one.
//
// The alternative - the shape this replaces - was to validate a pathname while
// impersonating the client, close the handle, and let LocalSystem resolve that
// same string again later. Between the two resolutions the medium-integrity
// owner can point the name somewhere else, and SYSTEM then creates a log or
// rewrites audit entries on whatever it now names. Rechecking the string harder
// narrows the window; only holding the object closes it.

type FolderCapability struct {
	Path     string
	Identity settings.ObjectIdentity
	Security HANDLE // opened by identity for ACCESS_SYSTEM_SECURITY, still the same object
	// Owner is the handle the owner's own token opened, kept for the session. It
	// is what pins the folder: Security asks for no data access, and Windows
	// exempts attribute-only opens from share-mode enforcement, so Security
	// alone does not stop a rename. Measured, not assumed - see
	// TestOpenByIdentityHandoffKeepsRootPinned.
	Owner HANDLE
}

type LogCapability struct {
	Path     string
	Identity settings.ObjectIdentity
	Master   HANDLE // duplicated per watcher start; closed when the binding is replaced
}

// FolderUnavailable is a configured folder this bind did not open. It is a
// status, not a failure: the owner asked for it, so it keeps its place in the
// configuration and is reported, and the folders that did open are watched.
type FolderUnavailable struct {
	Path   string
	Reason string
	// Waiting distinguishes a folder that will come back on its own - a drive
	// that is not plugged in - from one that needs the owner to do something.
	Waiting bool
}

// BoundConfig is a configuration whose objects are held open. Folders holds only
// what was opened; Public.Folders still holds every configured path, and
// Unavailable accounts for the difference. The three always reconcile, because
// silently losing a configured folder is the failure mode this shape exists to
// prevent.
type BoundConfig struct {
	Public      settings.PublicConfig
	Folders     []FolderCapability
	Unavailable []FolderUnavailable
	Log         LogCapability
}

// Close is safe on a partially built value: binding closes what it opened when
// a later object fails.
func (b *BoundConfig) Close() {
	if b == nil {
		return
	}
	for i := range b.Folders {
		if b.Folders[i].Security != 0 {
			closeHandle(b.Folders[i].Security)
			b.Folders[i].Security = 0
		}
		if b.Folders[i].Owner != 0 {
			closeHandle(b.Folders[i].Owner)
			b.Folders[i].Owner = 0
		}
	}
	if b.Log.Master != 0 {
		closeHandle(b.Log.Master)
		b.Log.Master = 0
	}
}

func (b *BoundConfig) folderByPath(path string) *FolderCapability {
	for i := range b.Folders {
		if strings.EqualFold(b.Folders[i].Path, path) {
			return &b.Folders[i]
		}
	}
	return nil
}

// AttachedPaths is the set of folders that are actually being watched. Audit
// rules are applied to these and to nothing else.
func (b *BoundConfig) AttachedPaths() []string {
	paths := make([]string, 0, len(b.Folders))
	for _, f := range b.Folders {
		paths = append(paths, f.Path)
	}
	return paths
}

// markUnavailable moves a folder out of the attached set and closes what it
// held. The path stays in Public.Folders: a folder that went away is a status
// to report, never a reason to forget the owner asked for it.
func (b *BoundConfig) markUnavailable(i int, reason error, waiting bool) {
	f := b.Folders[i]
	if f.Security != 0 {
		closeHandle(f.Security)
	}
	if f.Owner != 0 {
		closeHandle(f.Owner)
	}
	b.Unavailable = append(b.Unavailable, FolderUnavailable{Path: f.Path, Reason: reason.Error(), Waiting: waiting})
	b.Folders = append(b.Folders[:i], b.Folders[i+1:]...)
}

// MergeBindings projects the identities to persist alongside the configuration.
//
// It merges rather than replaces, and that is the whole point of the function.
// A folder that could not be opened has no identity to record, and dropping its
// previous one would not merely lose information: resumeIdentitiesMatch treats a
// folder with no recorded binding as one that has never been authorised, so the
// next volume to claim that drive letter would be watched - and given a SACL by
// LocalSystem - without anyone deciding to. An unreachable folder therefore
// keeps the identity it was last authorised with. Only a folder the owner
// removed from the configuration loses its binding.
func (b *BoundConfig) MergeBindings(previous map[string]settings.ObjectBinding) (map[string]settings.ObjectBinding, *settings.ObjectBinding) {
	folders := make(map[string]settings.ObjectBinding, len(b.Public.Folders))
	for _, path := range b.Public.Folders {
		key := strings.ToLower(path)
		if existing, ok := previous[key]; ok && !existing.Identity.Zero() {
			folders[key] = existing
		}
	}
	for _, f := range b.Folders {
		folders[strings.ToLower(f.Path)] = settings.ObjectBinding{Path: f.Path, Identity: f.Identity}
	}
	log := &settings.ObjectBinding{Path: b.Log.Path, Identity: b.Log.Identity}
	return folders, log
}

// errRevertFailed is unrecoverable: the thread may still carry the client's
// token, so nothing else in this process may run privileged work.
var errRevertFailed = errors.New("ReadWatch could not drop the client's identity and stopped for safety")

// bindPublicConfigAsPipeClient opens every configured object under the token of
// the client on the far end of the pipe, and returns handles rather than paths.
func bindPublicConfigAsPipeClient(pipe HANDLE, ownerSID string, public settings.PublicConfig, allowVolumeOnly bool) (*BoundConfig, error) {
	type result struct {
		bound *BoundConfig
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		// The impersonation token is a property of the OS thread, so the whole
		// bind runs on one locked thread and nothing else is scheduled onto it.
		runtime.LockOSThread()
		bound, err, fatal := bindOnLockedThread(pipe, ownerSID, public, allowVolumeOnly)
		ch <- result{bound, err}
		if fatal {
			// Returning without UnlockOSThread terminates this thread rather
			// than handing a possibly still-impersonated one back to the
			// scheduler. The service is stopping anyway.
			return
		}
		runtime.UnlockOSThread()
	}()
	r := <-ch
	if errors.Is(r.err, errRevertFailed) {
		writeServiceDiagnostic(r.err)
		requestServiceStop()
	}
	return r.bound, r.err
}

func bindOnLockedThread(pipe HANDLE, ownerSID string, public settings.PublicConfig, allowVolumeOnly bool) (bound *BoundConfig, err error, fatal bool) {
	if r, _, e := procImpersonateNamedPipeClient.Call(uintptr(pipe)); r == 0 {
		return nil, winErr("ImpersonateNamedPipeClient", e), false
	}
	reverted := false
	revert := func() error {
		if reverted {
			return nil
		}
		reverted = true
		if r, _, _ := procRevertToSelf.Call(); r == 0 {
			return errRevertFailed
		}
		return nil
	}

	// The pipe ACL already restricts who may connect; this proves the token on
	// the other end is the account the configuration belongs to, not merely
	// someone who got a handle to the pipe.
	if err := requireOwnerToken(ownerSID); err != nil {
		if revertErr := revert(); revertErr != nil {
			return nil, revertErr, true
		}
		return nil, err, false
	}

	if len(public.Folders) > maxWatchedFolders {
		if revertErr := revert(); revertErr != nil {
			return nil, revertErr, true
		}
		return nil, fmt.Errorf("a maximum of %d watched folders is supported", maxWatchedFolders), false
	}
	if public.LogFormat != "text" && public.LogFormat != "jsonl" && public.LogFormat != "csv" {
		if revertErr := revert(); revertErr != nil {
			return nil, revertErr, true
		}
		return nil, errors.New("unsupported log format"), false
	}
	if public.MaxRows < 200 || public.MaxRows > 5000 {
		public.MaxRows = 1000
	}

	out := &BoundConfig{Public: public}

	// One folder that cannot be opened does not fail the bind. A watched folder
	// may live on a drive that is not always plugged in, and the folders that are
	// present must keep being watched regardless of the ones that are not.
	//
	// Skipping is fail-closed per folder: a folder that is skipped is not opened,
	// carries no audit rule and produces no events. Nothing a skip can do is
	// weaker than what the whole-bind refusal did - it only stops one folder's
	// problem from becoming every folder's problem.
	configured := make([]string, 0, len(public.Folders))
	for _, raw := range public.Folders {
		handle, identity, normalized, openErr := openWatchedFolderAsClient(raw, allowVolumeOnly)
		if openErr != nil {
			// Keep the owner's path in the configuration. Persisting only what
			// opened would delete a folder from Settings the first time its drive
			// was unplugged.
			display, lexicalErr := validateLexicalPath(raw)
			if lexicalErr != nil {
				display = strings.TrimSpace(raw)
			}
			configured = append(configured, display)
			waiting := waitingOpenFailure(openErr)
			reason := openErr.Error()
			if waiting {
				reason = waitingReason(openErr)
			}
			out.Unavailable = append(out.Unavailable, FolderUnavailable{
				Path:    display,
				Reason:  reason,
				Waiting: waiting,
			})
			continue
		}
		configured = append(configured, normalized)
		// The capability owns the handle from here, so every exit below releases
		// it through out.Close() and there is no second list to keep in step.
		out.Folders = append(out.Folders, FolderCapability{Path: normalized, Identity: identity, Owner: handle})
	}
	out.Public.Folders = configured

	// The log has no partial state to fall back to: with nowhere to write, there
	// is no monitoring at all. It stays all or nothing.
	logHandle, logIdentity, logPath, logErr := openLogAsClient(public.LogPath)
	if logErr != nil {
		out.Close()
		if revertErr := revert(); revertErr != nil {
			return nil, revertErr, true
		}
		return nil, logErr, false
	}
	out.Log = LogCapability{Path: logPath, Identity: logIdentity, Master: logHandle}
	out.Public.LogPath = logPath

	// Everything below runs as LocalSystem again.
	if revertErr := revert(); revertErr != nil {
		out.Close()
		return nil, revertErr, true
	}

	// The owner-opened handles stay alive across the privileged open and then for
	// the whole session. Their no-delete share mode is what prevents deletion,
	// rename and file-ID reuse - both during the handoff, when a swap would
	// defeat the identity check, and afterwards, when a rename would move the
	// watched root away from the audit rule applied to it. The configured
	// pathname is never consulted a second time.
	upgradeErr := withPrivilege("SeSecurityPrivilege", func() error {
		// Backwards, because a folder that fails here leaves the slice.
		for i := len(out.Folders) - 1; i >= 0; i-- {
			secure, err := openByIdentity(out.Folders[i].Identity)
			if err == nil {
				out.Folders[i].Security = secure
				continue
			}
			// The owner opened this object moments ago, so a failure now is the
			// drive leaving between the two opens, not a decision about the folder.
			out.markUnavailable(i, err, waitingOpenFailure(err))
		}
		return nil
	})
	if upgradeErr != nil {
		out.Close()
		return nil, upgradeErr, false
	}
	return out, nil, false
}

// errDriveNotAttached is the ordinary state of a removable drive, not a fault,
// so it is a value the rest of the code can recognise rather than one more
// Win32 error code to interpret.
var errDriveNotAttached = errors.New("the drive is not attached")

// errVolumeUnavailable means the volume carrying a recorded object is not in the
// machine. Unlike a missing object it says nothing about whether ReadWatch's
// audit rule is still there - it is, on a disk that is somewhere else - so the
// journal record must be kept rather than forgotten.
var errVolumeUnavailable = errors.New("the drive holding this folder is not attached")

// absentDeviceErrno is the set of Win32 errors that mean "the storage is not
// here", as distinct from "you may not have it" or "it is not that kind of
// object". The first two entries are the ones that matter and the ones that were
// wrong: measured on this host, both a free drive letter and an unattached
// \\?\Volume{...} name fail with ERROR_FILE_NOT_FOUND, not with any of the
// device-shaped codes. TestUnattachedDriveLetterIsWaiting and
// TestUnattachedVolumeKeepsItsRecord hold that measurement in place.
func absentDeviceErrno(errno syscall.Errno) bool {
	switch uintptr(errno) {
	case ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_INVALID_DRIVE,
		ERROR_NOT_READY, ERROR_BAD_UNIT, ERROR_DEV_NOT_EXIST, ERROR_INVALID_NAME,
		ERROR_NO_SUCH_DEVICE, ERROR_UNRECOGNIZED_VOLUME, ERROR_NO_MEDIA_IN_DRIVE,
		ERROR_DEVICE_NOT_CONNECTED:
		return true
	}
	return false
}

// waitingReason says why a folder is not here, in the owner's terms. The raw
// error names a \\?\Volume{...} pathname the walk built, which is the wrong
// thing to put in a window: what is needed is which of their folders is missing
// and whether that is the drive or the folder itself. A drive that is out and a
// path that was mistyped are both "waiting", and they must not read alike.
func waitingReason(err error) string {
	if errors.Is(err, errDriveNotAttached) || errors.Is(err, errVolumeUnavailable) {
		return "the drive is not attached"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch uintptr(errno) {
		case ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND:
			return "this folder does not exist"
		case ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION:
			return "another program has this folder open"
		case ERROR_NOT_READY, ERROR_NO_MEDIA_IN_DRIVE:
			return "the drive has no disk in it"
		}
	}
	return "this folder cannot be reached right now"
}

// waitingOpenFailure separates a folder that is not here right now from one
// ReadWatch will not watch. Only the first is retried on its own; a junction, a
// refused permission or a volume that cannot carry an audit rule reads the same
// way every time, and calling that "waiting" would hide it behind a spinner
// forever.
func waitingOpenFailure(err error) bool {
	if errors.Is(err, errDriveNotAttached) || errors.Is(err, errVolumeUnavailable) {
		return true
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	// Another process holding the folder incompatibly also clears on its own,
	// with nobody changing anything.
	if uintptr(errno) == ERROR_SHARING_VIOLATION || uintptr(errno) == ERROR_LOCK_VIOLATION {
		return true
	}
	return absentDeviceErrno(errno)
}

const maxWatchedFolders = 32

func requireOwnerToken(ownerSID string) error {
	var token HANDLE
	thread, _, _ := procGetCurrentThread.Call()
	r, _, e := procOpenThreadToken.Call(thread, TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return winErr("OpenThreadToken", e)
	}
	defer closeHandle(token)
	sid, err := tokenUserSID(token)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sid, ownerSID) {
		return errors.New("this ReadWatch configuration belongs to another Windows account")
	}
	return nil
}

// validateLexicalPath refuses everything that is not an ordinary local
// drive-absolute path, before any filesystem call. A name rejected here can
// never reach an API that might interpret it.
func validateLexicalPath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", errors.New("the path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("the path contains an invalid character")
	}
	if strings.ContainsAny(p, "*?") {
		return "", errors.New("wildcards are not a path")
	}
	p = strings.ReplaceAll(p, "/", `\`)
	if strings.HasPrefix(p, `\\`) {
		return "", errors.New("network, UNC and device paths are not supported; monitor a local folder on the machine that holds it")
	}
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' {
		return "", errors.New("use a full path on a local drive, like D:\\Renders\\output")
	}
	letter := p[0]
	if !(letter >= 'A' && letter <= 'Z') && !(letter >= 'a' && letter <= 'z') {
		return "", errors.New("use a full path on a local drive, like D:\\Renders\\output")
	}
	// A colon after the drive colon is an alternate data stream.
	if strings.Contains(p[2:], ":") {
		return "", errors.New("alternate data streams are not supported")
	}
	// A bare drive root is allowed. Everything below this gate works on one -
	// measured on this host against NTFS volumes on NVMe and USB alike - and for
	// a removable drive the whole drive is the unit the owner thinks in. It is
	// expensive rather than impossible: the audit entry is inheritable, so
	// applying it rewrites the security descriptor of every file already on the
	// volume, and every read then produces a Security-log event. That is a cost
	// to warn about where the owner can see it, not a reason to refuse here.
	rest := strings.Trim(p[3:], `\`)
	if rest == "" {
		return strings.ToUpper(p[:1]) + `:\`, nil
	}
	components := strings.Split(rest, `\`)
	clean := make([]string, 0, len(components))
	for _, c := range components {
		if c == "" {
			return "", errors.New("the path has an empty folder name")
		}
		if c == "." || c == ".." {
			return "", errors.New("relative path components are not supported")
		}
		if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
			return "", errors.New("a folder name may not end in a dot or a space")
		}
		clean = append(clean, c)
	}
	return strings.ToUpper(p[:1]) + `:\` + strings.Join(clean, `\`), nil
}

// volumeGUIDPath turns C:\a\b into \\?\Volume{...}\a\b. The walk uses the
// volume's own name so a drive-letter reassignment cannot redirect it midway.
func volumeGUIDPath(driveAbsolute string) (string, string, volumeTraits, error) {
	var traits volumeTraits
	root := strings.ToUpper(driveAbsolute[:1]) + `:\`
	// Ask what kind of drive this is before asking the filesystem anything. A
	// letter with no volume behind it is the ordinary state of a drive that is
	// unplugged, and it has to read differently from a real failure; a network
	// drive is a permanent refusal, and without this it would look like a drive
	// that might come back and would sit in "waiting" forever.
	switch driveType(root) {
	case DRIVE_NO_ROOT_DIR:
		return "", "", traits, fmt.Errorf("%w (%s)", errDriveNotAttached, root)
	case DRIVE_REMOTE:
		return "", "", traits, errors.New("network drives are not supported; monitor a local folder on the machine that holds it")
	}
	// Ask what the volume is formatted as before walking into it. Windows audits
	// file access through the security descriptor, and exFAT and FAT have no
	// security descriptors at all - so there is nothing to attach an audit entry
	// to and nothing will ever generate an event. Without this the walk fails at
	// the volume root with "GetFileInformationByHandleEx(FileAttributeTagInfo):
	// The parameter is incorrect", which tells the owner nothing. Most USB sticks
	// ship formatted exFAT, so this is the common case, not the exotic one.
	traits, err := volumeTraitsFor(root)
	if err != nil {
		return "", "", traits, err
	}
	buf := make([]uint16, 64)
	r, _, e := procGetVolumeNameForVolumeMountPntW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(root))),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r == 0 {
		return "", "", traits, fmt.Errorf("identify the volume holding %s: %w", root, e)
	}
	guid := syscall.UTF16ToString(buf)
	rest := strings.TrimPrefix(driveAbsolute, driveAbsolute[:3])
	return guid, guid + rest, traits, nil
}

// volumeTraits are the filesystem capabilities that decide which of ReadWatch's
// admission checks are meaningful on a volume. They are asked of Windows rather
// than inferred from the filesystem's name: the point is what this volume can
// do, not what its format is usually assumed to do.
type volumeTraits struct {
	FileSystem     string
	Serial         uint32
	PersistentACLs bool
	OpenByFileID   bool
	ReparsePoints  bool
}

// MarkerCapable reports whether an audit rule can be put on this volume and
// found again afterwards. Both halves matter: applying a rule that cannot later
// be located by identity would leave a change ReadWatch could not undo.
func (t volumeTraits) MarkerCapable() bool {
	return t.PersistentACLs && t.OpenByFileID &&
		(strings.EqualFold(t.FileSystem, "NTFS") || strings.EqualFold(t.FileSystem, "ReFS"))
}

// IdentityCapable reports whether an object on this volume can be identified
// durably enough to be recognised again.
func (t volumeTraits) IdentityCapable() bool { return t.OpenByFileID }

func volumeTraitsFor(root string) (volumeTraits, error) {
	var t volumeTraits
	name := make([]uint16, 32)
	var serial, maxComponent, flags uint32
	r, _, e := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(root))),
		0, 0,
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&maxComponent)),
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)),
	)
	if r == 0 {
		return t, winErr("GetVolumeInformation", e)
	}
	return traitsFromFlags(syscall.UTF16ToString(name), serial, flags), nil
}

// traitsFromFlags is separated so the capability rules can be tested against the
// flag words this host actually reports, without needing the volume present.
func traitsFromFlags(filesystem string, serial, flags uint32) volumeTraits {
	return volumeTraits{
		FileSystem:     filesystem,
		Serial:         serial,
		PersistentACLs: flags&FILE_PERSISTENT_ACLS != 0,
		OpenByFileID:   flags&FILE_SUPPORTS_OPEN_BY_FILE_ID != 0,
		ReparsePoints:  flags&FILE_SUPPORTS_REPARSE_POINTS != 0,
	}
}

func driveType(root string) uint32 {
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(utf16Ptr(root))))
	return uint32(r)
}

// volumeFileSystem names the filesystem on a mounted root, by path rather than
// by handle, so it can be consulted before anything is opened.
func volumeFileSystem(root string) (string, error) {
	name := make([]uint16, 32)
	r, _, e := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(root))),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)),
	)
	if r == 0 {
		return "", winErr("GetVolumeInformation", e)
	}
	return syscall.UTF16ToString(name), nil
}

// openDirectoryComponent opens one path component and proves it is an ordinary
// directory. FILE_FLAG_OPEN_REPARSE_POINT means the handle refers to the
// component itself rather than silently following it somewhere else, and the
// narrow share mode holds the checked namespace still: nothing can rename this
// component or turn it into a junction while the walk continues below it.
func openDirectoryComponent(path string, traits volumeTraits) (HANDLE, error) {
	r, _, e := procCreateFileW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(path))),
		FILE_READ_ATTRIBUTES|FILE_TRAVERSE,
		FILE_SHARE_READ,
		0, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if r == INVALID_HANDLE_VALUE || r == 0 {
		return 0, fmt.Errorf("open %s: %w", path, e)
	}
	h := HANDLE(r)
	if err := requireOrdinaryDirectory(h, traits); err != nil {
		closeHandle(h)
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return h, nil
}

// requireOrdinaryDirectory proves the handle refers to a real directory and not
// to something that redirects elsewhere.
//
// On a volume that cannot hold a reparse point the redirection question does not
// arise, and the call that would answer it is not available either: measured on
// this host, FileAttributeTagInfo fails outright on exFAT
// (do/evidence/2026-08-17-exfat-capability). The check is then satisfied from
// the plain attributes instead. That is a narrowing justified by the volume's
// own reported capability, not by an assumption about the format - a volume that
// claims reparse-point support is checked the strict way whatever it is called.
func requireOrdinaryDirectory(h HANDLE, traits volumeTraits) error {
	if !traits.ReparsePoints {
		var basic BY_HANDLE_FILE_INFORMATION
		r, _, e := procGetFileInformationByHandle.Call(uintptr(h), uintptr(unsafe.Pointer(&basic)))
		if r == 0 {
			return winErr("GetFileInformationByHandle", e)
		}
		if basic.FileAttributes&FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errors.New("this is a file, not a folder")
		}
		if basic.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			// The volume said it cannot hold one and an object on it says it is one.
			// Refuse rather than reconcile: one of the two is lying.
			return errors.New("this path goes through a junction, symbolic link, mount point or cloud placeholder, which ReadWatch does not follow")
		}
		return nil
	}
	var info FILE_ATTRIBUTE_TAG_INFO
	r, _, e := procGetFileInformationByHandleEx.Call(
		uintptr(h), FileAttributeTagInfo,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info),
	)
	if r == 0 {
		return winErr("GetFileInformationByHandleEx(FileAttributeTagInfo)", e)
	}
	if info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("this is a file, not a folder")
	}
	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("this path goes through a junction, symbolic link, mount point or cloud placeholder, which ReadWatch does not follow")
	}
	return nil
}

func requireNotReparsePoint(h HANDLE) error {
	var info FILE_ATTRIBUTE_TAG_INFO
	r, _, e := procGetFileInformationByHandleEx.Call(
		uintptr(h), FileAttributeTagInfo,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info),
	)
	if r == 0 {
		return winErr("GetFileInformationByHandleEx(FileAttributeTagInfo)", e)
	}
	if info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY != 0 {
		return errors.New("the log path points to a folder")
	}
	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("the log path goes through a junction, symbolic link or cloud placeholder, which ReadWatch does not follow")
	}
	return nil
}

// walkAncestors pins every directory from the volume root down to (but not
// including) the leaf. The returned handles must stay open until the leaf is
// open and verified; releasing them earlier reopens the race they exist to shut.
func walkAncestors(volumeGUID, internalPath string, traits volumeTraits) ([]HANDLE, error) {
	guards := make([]HANDLE, 0, 8)
	release := func() {
		for _, h := range guards {
			closeHandle(h)
		}
	}
	root, err := openDirectoryComponent(volumeGUID, traits)
	if err != nil {
		return nil, err
	}
	guards = append(guards, root)

	rest := strings.Trim(strings.TrimPrefix(internalPath, volumeGUID), `\`)
	components := strings.Split(rest, `\`)
	prefix := volumeGUID
	for i := 0; i < len(components)-1; i++ {
		prefix = prefix + components[i] + `\`
		h, err := openDirectoryComponent(prefix, traits)
		if err != nil {
			release()
			return nil, err
		}
		guards = append(guards, h)
	}
	return guards, nil
}

func releaseGuards(guards []HANDLE) {
	for _, h := range guards {
		closeHandle(h)
	}
}

// openWatchedFolderAsClient is the whole admission check for one folder: it runs
// under impersonation, so a folder the owner cannot open is refused here rather
// than being opened later by SYSTEM on their behalf.
// allowVolumeOnly says whether a folder on a volume with no durable file
// identity may be admitted. It is true only under event tracing, where ReadWatch
// writes nothing to the volume and so has nothing it must find again to undo.
func openWatchedFolderAsClient(raw string, allowVolumeOnly bool) (HANDLE, settings.ObjectIdentity, string, error) {
	var zero settings.ObjectIdentity
	lexical, err := validateLexicalPath(raw)
	if err != nil {
		return 0, zero, "", err
	}
	volumeGUID, internal, traits, err := volumeGUIDPath(lexical)
	if err != nil {
		return 0, zero, "", err
	}
	guards, err := walkAncestors(volumeGUID, internal, traits)
	if err != nil {
		return 0, zero, "", err
	}
	defer releaseGuards(guards)

	// No FILE_SHARE_DELETE: while ReadWatch watches a folder, that folder cannot
	// be renamed or deleted out from under the audit rule applied to it.
	r, _, e := procCreateFileW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(internal))),
		FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		0, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if r == INVALID_HANDLE_VALUE || r == 0 {
		return 0, zero, "", fmt.Errorf("your account cannot open this folder: %w", e)
	}
	h := HANDLE(r)
	if err := requireOrdinaryDirectory(h, traits); err != nil {
		closeHandle(h)
		return 0, zero, "", err
	}
	identity, err := captureIdentity(h, volumeGUID, traits, allowVolumeOnly)
	if err != nil {
		closeHandle(h)
		return 0, zero, "", err
	}
	if err := requireFinalPath(h, internal); err != nil {
		closeHandle(h)
		return 0, zero, "", err
	}
	return h, identity, lexical, nil
}

// openLogAsClient creates the log under the owner's authority if it does not
// exist. The parent must already exist: creating directories as SYSTEM from a
// user-supplied string is the other half of the primitive being closed here.
func openLogAsClient(raw string) (HANDLE, settings.ObjectIdentity, string, error) {
	var zero settings.ObjectIdentity
	lexical, err := validateLexicalPath(raw)
	if err != nil {
		return 0, zero, "", fmt.Errorf("log file: %w", err)
	}
	volumeGUID, internal, traits, err := volumeGUIDPath(lexical)
	if err != nil {
		// Say it is the log. A watched folder on the same unplugged drive
		// produces word-for-word the same message, and that one is annotated with
		// the folder it belongs to while this one would not be.
		return 0, zero, "", fmt.Errorf("log file %s: %w", lexical, err)
	}
	guards, err := walkAncestors(volumeGUID, internal, traits)
	if err != nil {
		return 0, zero, "", fmt.Errorf("log folder: %w", ownerFacing(err, volumeGUID, lexical))
	}
	defer releaseGuards(guards)

	r, _, e := procCreateFileW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(internal))),
		FILE_APPEND_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		0, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if r == INVALID_HANDLE_VALUE || r == 0 {
		return 0, zero, "", fmt.Errorf("your account cannot append to the selected log: %w", e)
	}
	h := HANDLE(r)
	if err := requireNotReparsePoint(h); err != nil {
		closeHandle(h)
		return 0, zero, "", err
	}
	// The log is where every event is written, and a log ReadWatch cannot
	// recognise again is not something to be relaxed about whatever mechanism is
	// running. It keeps the strict requirement.
	identity, err := captureIdentity(h, volumeGUID, traits, false)
	if err != nil {
		closeHandle(h)
		return 0, zero, "", err
	}
	return h, identity, lexical, nil
}

// captureIdentity records what this handle refers to, and refuses volumes that
// cannot carry the audit rule or be searched by identity afterwards.
func captureIdentity(h HANDLE, volumeGUID string, traits volumeTraits, allowVolumeOnly bool) (settings.ObjectIdentity, error) {
	var zero settings.ObjectIdentity
	if !traits.IdentityCapable() {
		if !allowVolumeOnly {
			return zero, fmt.Errorf("%s volumes cannot carry Windows audit rules; watch this folder with event tracing instead, or use an NTFS or ReFS folder", traits.FileSystem)
		}
		return volumeOnlyIdentity(volumeGUID, traits), nil
	}
	var idInfo FILE_ID_INFO
	r, _, e := procGetFileInformationByHandleEx.Call(
		uintptr(h), FileIdInfo,
		uintptr(unsafe.Pointer(&idInfo)), unsafe.Sizeof(idInfo),
	)
	if r == 0 {
		return zero, winErr("GetFileInformationByHandleEx(FileIdInfo)", e)
	}
	var basic BY_HANDLE_FILE_INFORMATION
	r, _, e = procGetFileInformationByHandle.Call(uintptr(h), uintptr(unsafe.Pointer(&basic)))
	if r == 0 {
		return zero, winErr("GetFileInformationByHandle", e)
	}

	fsName := make([]uint16, 32)
	var flags uint32
	r, _, e = procGetVolumeInformationByHandleW.Call(
		uintptr(h), 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&fsName[0])), uintptr(len(fsName)),
	)
	if r == 0 {
		return zero, winErr("GetVolumeInformationByHandle", e)
	}
	filesystem := syscall.UTF16ToString(fsName)
	if !strings.EqualFold(filesystem, "NTFS") && !strings.EqualFold(filesystem, "ReFS") {
		return zero, fmt.Errorf("%s volumes cannot carry Windows audit rules; use an NTFS or ReFS folder", filesystem)
	}
	if flags&FILE_PERSISTENT_ACLS == 0 {
		return zero, errors.New("this volume does not keep permissions, so an audit rule would not survive on it")
	}
	if flags&FILE_SUPPORTS_OPEN_BY_FILE_ID == 0 {
		// Without this ReadWatch could apply an audit rule and then be unable to
		// find that exact object again to remove it.
		return zero, errors.New("this volume cannot be searched by file identity, which ReadWatch needs to undo its own changes")
	}
	return settings.ObjectIdentity{
		VolumeGUID:   volumeGUID,
		VolumeSerial: idInfo.VolumeSerialNumber,
		FileSystem:   filesystem,
		FileID128:    idInfo.FileID,
		FileIndex64:  uint64(basic.FileIndexHigh)<<32 | uint64(basic.FileIndexLow),
		CreationTime: basic.CreationTime.Uint64(),
	}, nil
}

// ownerFacing rewrites an internal volume path back into the drive letter the
// owner typed. The walk addresses folders by volume GUID so a drive-letter
// reassignment cannot redirect it midway, which is right - but a refusal that
// reads "\\?\Volume{6ee44c6e-...}\Photos: ..." tells the person reading it
// nothing, and that is what one actually said.
func ownerFacing(err error, volumeGUID, lexical string) error {
	if err == nil || volumeGUID == "" || len(lexical) < 3 {
		return err
	}
	text := err.Error()
	replaced := strings.ReplaceAll(text, strings.TrimRight(volumeGUID, `\`)+`\`, lexical[:3])
	if replaced == text {
		return err
	}
	// Rebuilt rather than wrapped: the substitution is inside the message, and
	// keeping the original as a cause would show the owner both versions.
	return errors.New(replaced)
}

// volumeOnlyIdentity is everything a volume with no file identity can offer:
// which volume, and what it is formatted as. Enough to catch the path being
// pointed at a different volume, not enough to catch a folder replaced on this
// one.
func volumeOnlyIdentity(volumeGUID string, traits volumeTraits) settings.ObjectIdentity {
	return settings.ObjectIdentity{
		VolumeGUID:   volumeGUID,
		VolumeSerial: uint64(traits.Serial),
		FileSystem:   traits.FileSystem,
	}
}

// requireFinalPath confirms the object the handle reached is the one the walk
// addressed, catching any redirection the attribute checks would not.
func requireFinalPath(h HANDLE, expected string) error {
	buf := make([]uint16, 1024)
	r, _, e := procGetFinalPathNameByHandleW.Call(
		uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), VOLUME_NAME_GUID,
	)
	if r == 0 || int(r) >= len(buf) {
		return winErr("GetFinalPathNameByHandle", e)
	}
	final := syscall.UTF16ToString(buf[:r])
	if !strings.EqualFold(strings.TrimRight(final, `\`), strings.TrimRight(expected, `\`)) {
		return fmt.Errorf("this path resolves to %s, which is not where it appeared to point", final)
	}
	return nil
}

// openByIdentity is both the privileged binder handoff and the recovery seam.
// The stored path may name something else entirely, so the object is found by
// its identity or not at all.
//
// READ_CONTROL is required even though ReadWatch only ever reads and writes the
// SACL. The documentation assigns READ_CONTROL to the owner, group and DACL, so
// it looks droppable; measured on this host, GetSecurityInfo returns
// ERROR_ACCESS_DENIED without it whether the handle came from OpenFileById or
// CreateFile, and succeeds with it.
func openByIdentity(id settings.ObjectIdentity) (HANDLE, error) {
	return openByIdentityWithAccess(id, ACCESS_SYSTEM_SECURITY|READ_CONTROL|FILE_READ_ATTRIBUTES)
}

// openByIdentityWithAccess exists so the Windows filesystem tests can exercise
// the identity/share handoff without requiring SeSecurityPrivilege.
func openByIdentityWithAccess(id settings.ObjectIdentity, desiredAccess uintptr) (HANDLE, error) {
	if id.VolumeOnly() {
		// Nothing to open by identity: the volume offered none. This path exists to
		// find an object ReadWatch changed, and it never changes an object on such
		// a volume, so reaching here at all means a record was written that should
		// not have been.
		return 0, fmt.Errorf("%s carries no file identity, so ReadWatch cannot reopen an object on it by identity", id.VolumeGUID)
	}
	volume, _, e := procCreateFileW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(strings.TrimRight(id.VolumeGUID, `\`)))),
		FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		0, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if volume == INVALID_HANDLE_VALUE || volume == 0 {
		// Which of the two opens failed is the whole question. Failing here means
		// the disk is not in the machine, so ReadWatch's audit rule is still on it
		// and the journal record has to be kept. Failing at OpenFileById below
		// means the volume is mounted and the object is not on it any more, which
		// is the only case where the record can safely be forgotten.
		if errno, ok := e.(syscall.Errno); ok && absentDeviceErrno(errno) {
			return 0, fmt.Errorf("%w (%s)", errVolumeUnavailable, id.VolumeGUID)
		}
		return 0, fmt.Errorf("open volume %s: %w", id.VolumeGUID, e)
	}
	defer closeHandle(HANDLE(volume))

	descriptor := FILE_ID_DESCRIPTOR{DwSize: uint32(unsafe.Sizeof(FILE_ID_DESCRIPTOR{}))}
	if strings.EqualFold(id.FileSystem, "ReFS") {
		descriptor.Type = FileIdTypeExtended
		descriptor.ID = id.FileID128
	} else {
		descriptor.Type = FileIdTypeIndex
		*(*uint64)(unsafe.Pointer(&descriptor.ID[0])) = id.FileIndex64
	}
	r, _, e := procOpenFileById.Call(
		volume,
		uintptr(unsafe.Pointer(&descriptor)),
		desiredAccess,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		0,
		FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,
	)
	if r == INVALID_HANDLE_VALUE || r == 0 {
		// The volume opened, so this is about the object rather than the disk - but
		// only some of the ways it can fail actually establish that the object is
		// gone. The rest are indeterminate and must stay that way, because the
		// caller deletes its only record of an applied audit rule on "gone".
		if errno, ok := e.(syscall.Errno); ok && objectGoneErrno(errno) {
			return 0, fmt.Errorf("%w (%v)", errObjectGone, errno)
		}
		return 0, fmt.Errorf("open the recorded folder by identity: %w", winErr("OpenFileById", e))
	}
	h := HANDLE(r)
	traits, err := volumeTraitsFor(strings.TrimRight(id.VolumeGUID, `\`) + `\`)
	if err != nil {
		closeHandle(h)
		return 0, err
	}
	current, err := captureIdentity(h, id.VolumeGUID, traits, false)
	if err != nil {
		closeHandle(h)
		return 0, err
	}
	// A file identifier can be reused by a different object after a deletion, so
	// the whole tuple has to match before anything privileged happens to it.
	if !current.Equal(id) {
		closeHandle(h)
		return 0, fmt.Errorf("%w: a different object now holds its identifier", errObjectGone)
	}
	return h, nil
}

// errObjectGone means the volume is here and the recorded object is provably not
// on it. It is the only outcome that authorises forgetting an audit record: the
// rule lived on the object, so it went with it.
var errObjectGone = errors.New("the recorded folder no longer exists")

// objectGoneErrno is what an attached volume says when the recorded object is not
// on it. Measured on this host: OpenFileById fails with ERROR_INVALID_PARAMETER
// both for a directory that was deleted after its identity was captured and for
// a file identifier that was never allocated. Neither produces a not-found code,
// which is exactly why this list is measured rather than reasoned about;
// TestDeletedFolderOnAnAttachedVolumeIsGone keeps it honest.
//
// ERROR_ACCESS_DENIED is deliberately absent. Windows documents it for an object
// that still exists but is pending deletion, so it cannot be read as absence,
// and reading it that way would discard the only record of a rule still applied.
// Anything not listed here stays indeterminate and keeps its record.
func objectGoneErrno(errno syscall.Errno) bool {
	switch uintptr(errno) {
	case ERROR_INVALID_PARAMETER, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND:
		return true
	}
	return false
}

// withPrivilege enables a privilege for exactly the call that needs it and puts
// the token back afterwards. Failing to restore leaves the process holding more
// authority than it should, which is a reason to stop rather than continue.
func withPrivilege(name string, fn func() error) error {
	var token HANDLE
	r, _, e := procOpenProcessToken.Call(procGetCurrentProcessHandle(), TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return winErr("OpenProcessToken", e)
	}
	defer closeHandle(token)

	var luid LUID
	r, _, e = procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(utf16Ptr(name))), uintptr(unsafe.Pointer(&luid)))
	if r == 0 {
		return winErr("LookupPrivilegeValue", e)
	}
	enable := TOKEN_PRIVILEGES{PrivilegeCount: 1}
	enable.Privileges[0] = LUIDAndAttributes{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED}
	var previous TOKEN_PRIVILEGES
	var returned uint32
	r, _, e = procAdjustTokenPrivileges.Call(
		uintptr(token), 0,
		uintptr(unsafe.Pointer(&enable)),
		unsafe.Sizeof(previous),
		uintptr(unsafe.Pointer(&previous)),
		uintptr(unsafe.Pointer(&returned)),
	)
	if r == 0 {
		return winErr("AdjustTokenPrivileges", e)
	}
	if last, _, _ := procGetLastError.Call(); last == ERROR_NOT_ALL_ASSIGNED {
		return fmt.Errorf("%s is not assigned to this account", name)
	}
	err := fn()
	if r, _, restoreErr := procAdjustTokenPrivileges.Call(
		uintptr(token), 0,
		uintptr(unsafe.Pointer(&previous)),
		0, 0, 0,
	); r == 0 {
		writeServiceDiagnostic(fmt.Errorf("restore %s to its previous state: %v", name, restoreErr))
		requestServiceStop()
		if err == nil {
			err = fmt.Errorf("could not restore %s and stopped for safety", name)
		}
	}
	return err
}

func tokenUserSID(token HANDLE) (string, error) {
	var needed uint32
	procGetTokenInformation.Call(uintptr(token), TokenUser, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return "", errors.New("GetTokenInformation returned an empty token user")
	}
	buf := make([]byte, needed)
	r, _, e := procGetTokenInformation.Call(uintptr(token), TokenUser, uintptr(unsafe.Pointer(&buf[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return "", winErr("GetTokenInformation", e)
	}
	tu := (*TOKEN_USER)(unsafe.Pointer(&buf[0]))
	var sidText *uint16
	r, _, e = procConvertSidToStringSidW.Call(tu.User.Sid, uintptr(unsafe.Pointer(&sidText)))
	if r == 0 {
		return "", winErr("ConvertSidToStringSid", e)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(sidText)))
	return utf16FromPtr(sidText), nil
}

// markerCapableFolder answers only one question: can this folder's volume carry
// an audit rule? It is deliberately separate from binding, because the answer
// decides which mechanism runs and that decision has to be made before anything
// privileged happens.
//
// known is false when the question cannot be answered right now - a drive that
// is not attached is the ordinary case. An unanswerable folder must not decide
// the mechanism for the whole session: which volumes happen to be plugged in
// would otherwise change how everything else is watched.
func markerCapableFolder(path string) (capable, known bool) {
	if len(path) < 2 || path[1] != ':' {
		// A UNC or otherwise unlettered path. Neither mechanism supports it, and
		// the bind step refuses it with a specific message; nothing to decide here.
		return false, false
	}
	root := strings.ToUpper(path[:1]) + `:\`
	switch driveType(root) {
	case DRIVE_NO_ROOT_DIR, DRIVE_REMOTE:
		return false, false
	}
	fs, err := volumeFileSystem(root)
	if err != nil {
		return false, false
	}
	return strings.EqualFold(fs, "NTFS") || strings.EqualFold(fs, "ReFS"), true
}

// markerCapability reports, for each watched folder, whether it can carry a
// marker. Folders whose answer is unknown are left out entirely, which
// ChooseMechanism treats as capable.
func markerCapability(folders []string) map[string]bool {
	out := make(map[string]bool, len(folders))
	for _, f := range folders {
		if capable, known := markerCapableFolder(f); known {
			out[f] = capable
		}
	}
	return out
}
