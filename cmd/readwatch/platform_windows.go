//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	appName        = "ReadWatch"
	serviceName    = "ReadWatchSvc"
	serviceDisplay = "ReadWatch folder read monitor"
	installedExe   = "ReadWatch.exe"
	configFile     = "config.json"
	pipeBaseName   = `\\.\pipe\ReadWatch.`
)

type appPaths struct {
	InstallDir string
	Exe        string
	Icon       string
	Manifest   string
	DataDir    string
	Config     string
	DefaultLog string
	StartMenu  string
}

func paths() appPaths {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(os.Getenv("USERPROFILE"), `AppData\Roaming`)
	}
	installDir := filepath.Join(programFiles, appName)
	dataDir := filepath.Join(programData, appName)
	return appPaths{
		InstallDir: installDir,
		Exe:        filepath.Join(installDir, installedExe),
		Icon:       filepath.Join(installDir, "ReadWatch.ico"),
		Manifest:   filepath.Join(installDir, installedExe+".manifest"),
		DataDir:    dataDir,
		Config:     filepath.Join(dataDir, configFile),
		DefaultLog: `C:\Tools\ReadWatch.log`,
		StartMenu:  filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs`, "ReadWatch.lnk"),
	}
}

func pipeName(ownerSID string) string {
	s := strings.NewReplacer("-", "_", "\\", "_", "/", "_").Replace(ownerSID)
	return pipeBaseName + s
}

func isElevated() bool {
	var token HANDLE
	r, _, _ := procOpenProcessToken.Call(procGetCurrentProcessHandle(), TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer closeHandle(token)
	var elevation TOKEN_ELEVATION
	var returned uint32
	r, _, _ = procGetTokenInformation.Call(uintptr(token), TokenElevation, uintptr(unsafe.Pointer(&elevation)), unsafe.Sizeof(elevation), uintptr(unsafe.Pointer(&returned)))
	return r != 0 && elevation.TokenIsElevated != 0
}

func procGetCurrentProcessHandle() uintptr {
	r, _, _ := procGetCurrentProcess.Call()
	return r
}

func currentUserSID() (string, error) {
	var token HANDLE
	r, _, e := procOpenProcessToken.Call(procGetCurrentProcessHandle(), TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return "", winErr("OpenProcessToken", e)
	}
	defer closeHandle(token)

	var needed uint32
	procGetTokenInformation.Call(uintptr(token), TokenUser, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return "", errors.New("GetTokenInformation returned an empty token user")
	}
	buf := make([]byte, needed)
	r, _, e = procGetTokenInformation.Call(uintptr(token), TokenUser, uintptr(unsafe.Pointer(&buf[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
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

func currentUserName() string {
	domain := strings.TrimSpace(os.Getenv("USERDOMAIN"))
	name := strings.TrimSpace(os.Getenv("USERNAME"))
	if name == "" {
		name = strings.TrimSpace(os.Getenv("USER"))
	}
	if domain != "" && name != "" {
		return domain + `\` + name
	}
	return name
}

func enablePrivilege(name string) error {
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
	tp := TOKEN_PRIVILEGES{PrivilegeCount: 1}
	tp.Privileges[0] = LUIDAndAttributes{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED}
	r, _, e = procAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return winErr("AdjustTokenPrivileges", e)
	}
	last, _, _ := procGetLastError.Call()
	if last == ERROR_NOT_ALL_ASSIGNED {
		return errors.New("SeSecurityPrivilege is not assigned to this account")
	}
	return nil
}

func securityAttributesFromSDDL(sddl string) (SECURITY_ATTRIBUTES, uintptr, error) {
	var sd uintptr
	var size uint32
	r, _, e := procConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(sddl))), 1, uintptr(unsafe.Pointer(&sd)), uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return SECURITY_ATTRIBUTES{}, 0, winErr("ConvertStringSecurityDescriptorToSecurityDescriptor", e)
	}
	return SECURITY_ATTRIBUTES{Length: uint32(unsafe.Sizeof(SECURITY_ATTRIBUTES{})), SecurityDescriptor: sd}, sd, nil
}

func setProtectedDACL(path, sddl string) error {
	var sd uintptr
	var size uint32
	r, _, e := procConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(sddl))), 1, uintptr(unsafe.Pointer(&sd)), uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return winErr("ConvertStringSecurityDescriptorToSecurityDescriptor", e)
	}
	defer procLocalFree.Call(sd)
	var present, defaulted int32
	var dacl uintptr
	r, _, e = procGetSecurityDescriptorDacl.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if r == 0 || present == 0 {
		return winErr("GetSecurityDescriptorDacl", e)
	}
	code, _, _ := procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(path))), SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
		0, 0, dacl, 0,
	)
	if code != ERROR_SUCCESS {
		return fmt.Errorf("set permissions on %s: %w", path, syscall.Errno(code))
	}
	return nil
}

func protectDataDirectory(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	return setProtectedDACL(path, `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`)
}

func prepareDefaultLogDirectory(ownerSID string) error {
	dir := filepath.Dir(paths().DefaultLog)
	_, statErr := os.Stat(dir)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return statErr
	}
	if created {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if ownerSID != "" {
			sddl := `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;` + ownerSID + `)`
			if err := setProtectedDACL(dir, sddl); err != nil {
				return err
			}
		}
	}
	return nil
}

func activationEventName(sid string) string { return `Local\ReadWatch.Activate.` + sid }
func exitEventName(sid string) string       { return `Local\ReadWatch.Exit.` + sid }
func instanceMutexName(sid string) string   { return `Local\ReadWatch.Instance.` + sid }

func createUserEvent(name, sid string) (HANDLE, error) {
	sddl := `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;` + sid + `)`
	sa, sd, err := securityAttributesFromSDDL(sddl)
	if err != nil {
		return 0, err
	}
	defer procLocalFree.Call(sd)
	r, _, e := procCreateEventW.Call(uintptr(unsafe.Pointer(&sa)), 1, 0, uintptr(unsafe.Pointer(utf16Ptr(name))))
	if r == 0 {
		return 0, winErr("CreateEvent", e)
	}
	return HANDLE(r), nil
}

func createActivationEvent(sid string) (HANDLE, error) {
	return createUserEvent(activationEventName(sid), sid)
}

func createExitEvent(sid string) (HANDLE, error) {
	return createUserEvent(exitEventName(sid), sid)
}

func signalUserEvent(name string) bool {
	r, _, _ := procOpenEventW.Call(EVENT_MODIFY_STATE, 0, uintptr(unsafe.Pointer(utf16Ptr(name))))
	if r == 0 {
		return false
	}
	defer closeHandle(HANDLE(r))
	ok, _, _ := procSetEvent.Call(r)
	return ok != 0
}

func signalActivation(sid string) bool { return signalUserEvent(activationEventName(sid)) }
func signalExit(sid string) bool       { return signalUserEvent(exitEventName(sid)) }

func waitForUIExit(sid string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		h, exists, err := acquireInstanceMutex(sid)
		if err == nil {
			closeHandle(h)
			if !exists {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func acquireInstanceMutex(sid string) (HANDLE, bool, error) {
	r, _, e := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(utf16Ptr(instanceMutexName(sid)))))
	if r == 0 {
		return 0, false, winErr("CreateMutex", e)
	}
	last, _, _ := procGetLastError.Call()
	return HANDLE(r), last == ERROR_ALREADY_EXISTS, nil
}

func elevateSelf(args string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	r, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr("runas"))),
		uintptr(unsafe.Pointer(utf16Ptr(exe))),
		uintptr(unsafe.Pointer(utf16Ptr(args))),
		uintptr(unsafe.Pointer(utf16Ptr(filepath.Dir(exe)))),
		SW_SHOWNORMAL,
	)
	if r <= 32 {
		return fmt.Errorf("elevation was cancelled or failed (code %d)", r)
	}
	return nil
}

func shellOpen(path string) error {
	r, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(utf16Ptr("open"))), uintptr(unsafe.Pointer(utf16Ptr(path))), 0, 0, SW_SHOWNORMAL)
	if r <= 32 {
		return fmt.Errorf("Windows could not open %s (code %d)", path, r)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, cpErr := io.Copy(out, in)
	closeErr := out.Close()
	if cpErr != nil {
		_ = os.Remove(tmp)
		return cpErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

func copyAdjacentAsset(name, dst string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	src := filepath.Join(filepath.Dir(exe), name)
	if _, statErr := os.Stat(src); statErr == nil {
		return copyFile(src, dst)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	data := embeddedAsset(name)
	if len(data) == 0 {
		return fmt.Errorf("required installation asset %s is missing", name)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	_ = os.Remove(dst)
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func launch(path string, args string) error {
	r, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(utf16Ptr("open"))), uintptr(unsafe.Pointer(utf16Ptr(path))), uintptr(unsafe.Pointer(utf16Ptr(args))), uintptr(unsafe.Pointer(utf16Ptr(filepath.Dir(path)))), SW_SHOWNORMAL)
	if r <= 32 {
		return fmt.Errorf("launch failed (code %d)", r)
	}
	return nil
}

func setLeanRuntime() {
	// The UI and service are event-driven. Limiting the scheduler avoids creating
	// unnecessary worker threads on large-core machines while retaining headroom
	// for the event log callback, IPC, and UI.
	n := runtime.NumCPU()
	if n > 2 {
		n = 2
	}
	if n < 1 {
		n = 1
	}
	runtime.GOMAXPROCS(n)
}
