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

// BoundConfig is a configuration whose objects are held open.
type BoundConfig struct {
	Public  settings.PublicConfig
	Folders []FolderCapability
	Log     LogCapability
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

// Bindings projects the identities to persist alongside the configuration.
func (b *BoundConfig) Bindings() (map[string]settings.ObjectBinding, *settings.ObjectBinding) {
	folders := make(map[string]settings.ObjectBinding, len(b.Folders))
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
func bindPublicConfigAsPipeClient(pipe HANDLE, ownerSID string, public settings.PublicConfig) (*BoundConfig, error) {
	type result struct {
		bound *BoundConfig
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		// The impersonation token is a property of the OS thread, so the whole
		// bind runs on one locked thread and nothing else is scheduled onto it.
		runtime.LockOSThread()
		bound, err, fatal := bindOnLockedThread(pipe, ownerSID, public)
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

func bindOnLockedThread(pipe HANDLE, ownerSID string, public settings.PublicConfig) (bound *BoundConfig, err error, fatal bool) {
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
	userFolders := make([]HANDLE, 0, len(public.Folders))
	closeUserFolders := func() {
		for _, h := range userFolders {
			closeHandle(h)
		}
		userFolders = nil
	}

	normalizedFolders := make([]string, 0, len(public.Folders))
	for _, raw := range public.Folders {
		handle, identity, normalized, openErr := openWatchedFolderAsClient(raw)
		if openErr != nil {
			closeUserFolders()
			out.Close()
			if revertErr := revert(); revertErr != nil {
				return nil, revertErr, true
			}
			return nil, fmt.Errorf("%s: %w", raw, openErr), false
		}
		userFolders = append(userFolders, handle)
		out.Folders = append(out.Folders, FolderCapability{Path: normalized, Identity: identity})
		normalizedFolders = append(normalizedFolders, normalized)
	}
	out.Public.Folders = normalizedFolders

	logHandle, logIdentity, logPath, logErr := openLogAsClient(public.LogPath)
	if logErr != nil {
		closeUserFolders()
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
		closeUserFolders()
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
		for i := range out.Folders {
			secure, err := openByIdentity(out.Folders[i].Identity)
			if err != nil {
				return fmt.Errorf("%s: %w", out.Folders[i].Path, err)
			}
			out.Folders[i].Security = secure
		}
		return nil
	})
	if upgradeErr == nil {
		// Hand the owner handles to the capability, which now owns closing them.
		for i := range out.Folders {
			out.Folders[i].Owner = userFolders[i]
		}
		userFolders = nil
	}
	closeUserFolders()
	if upgradeErr != nil {
		out.Close()
		return nil, upgradeErr, false
	}
	return out, nil, false
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
	rest := strings.Trim(p[3:], `\`)
	if rest == "" {
		return "", errors.New("watching an entire drive is blocked because it can generate extreme audit volume")
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
func volumeGUIDPath(driveAbsolute string) (string, string, error) {
	root := strings.ToUpper(driveAbsolute[:1]) + `:\`
	buf := make([]uint16, 64)
	r, _, e := procGetVolumeNameForVolumeMountPntW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(root))),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r == 0 {
		return "", "", fmt.Errorf("identify the volume holding %s: %w", root, e)
	}
	guid := syscall.UTF16ToString(buf)
	rest := strings.TrimPrefix(driveAbsolute, driveAbsolute[:3])
	return guid, guid + rest, nil
}

// openDirectoryComponent opens one path component and proves it is an ordinary
// directory. FILE_FLAG_OPEN_REPARSE_POINT means the handle refers to the
// component itself rather than silently following it somewhere else, and the
// narrow share mode holds the checked namespace still: nothing can rename this
// component or turn it into a junction while the walk continues below it.
func openDirectoryComponent(path string) (HANDLE, error) {
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
	if err := requireOrdinaryDirectory(h); err != nil {
		closeHandle(h)
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return h, nil
}

func requireOrdinaryDirectory(h HANDLE) error {
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
func walkAncestors(volumeGUID, internalPath string) ([]HANDLE, error) {
	guards := make([]HANDLE, 0, 8)
	release := func() {
		for _, h := range guards {
			closeHandle(h)
		}
	}
	root, err := openDirectoryComponent(volumeGUID)
	if err != nil {
		return nil, err
	}
	guards = append(guards, root)

	rest := strings.Trim(strings.TrimPrefix(internalPath, volumeGUID), `\`)
	components := strings.Split(rest, `\`)
	prefix := volumeGUID
	for i := 0; i < len(components)-1; i++ {
		prefix = prefix + components[i] + `\`
		h, err := openDirectoryComponent(prefix)
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
func openWatchedFolderAsClient(raw string) (HANDLE, settings.ObjectIdentity, string, error) {
	var zero settings.ObjectIdentity
	lexical, err := validateLexicalPath(raw)
	if err != nil {
		return 0, zero, "", err
	}
	volumeGUID, internal, err := volumeGUIDPath(lexical)
	if err != nil {
		return 0, zero, "", err
	}
	guards, err := walkAncestors(volumeGUID, internal)
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
	if err := requireOrdinaryDirectory(h); err != nil {
		closeHandle(h)
		return 0, zero, "", err
	}
	identity, err := captureIdentity(h, volumeGUID)
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
	volumeGUID, internal, err := volumeGUIDPath(lexical)
	if err != nil {
		return 0, zero, "", err
	}
	guards, err := walkAncestors(volumeGUID, internal)
	if err != nil {
		return 0, zero, "", fmt.Errorf("log folder: %w", err)
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
	identity, err := captureIdentity(h, volumeGUID)
	if err != nil {
		closeHandle(h)
		return 0, zero, "", err
	}
	return h, identity, lexical, nil
}

// captureIdentity records what this handle refers to, and refuses volumes that
// cannot carry the audit rule or be searched by identity afterwards.
func captureIdentity(h HANDLE, volumeGUID string) (settings.ObjectIdentity, error) {
	var zero settings.ObjectIdentity
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
// its identity or not at all. ACCESS_SYSTEM_SECURITY is the only security-
// descriptor right needed because ReadWatch reads and writes only the SACL.
func openByIdentity(id settings.ObjectIdentity) (HANDLE, error) {
	return openByIdentityWithAccess(id, ACCESS_SYSTEM_SECURITY|FILE_READ_ATTRIBUTES)
}

// openByIdentityWithAccess exists so the Windows filesystem tests can exercise
// the identity/share handoff without requiring SeSecurityPrivilege.
func openByIdentityWithAccess(id settings.ObjectIdentity, desiredAccess uintptr) (HANDLE, error) {
	volume, _, e := procCreateFileW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(strings.TrimRight(id.VolumeGUID, `\`)))),
		FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		0, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if volume == INVALID_HANDLE_VALUE || volume == 0 {
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
		return 0, fmt.Errorf("open the recorded folder by identity: %w", winErr("OpenFileById", e))
	}
	h := HANDLE(r)
	current, err := captureIdentity(h, id.VolumeGUID)
	if err != nil {
		closeHandle(h)
		return 0, err
	}
	// A file identifier can be reused by a different object after a deletion, so
	// the whole tuple has to match before anything privileged happens to it.
	if !current.Equal(id) {
		closeHandle(h)
		return 0, errors.New("the recorded object no longer exists; a different object now holds its identifier")
	}
	return h, nil
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
