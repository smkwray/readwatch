//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"readwatch/internal/protocol"
	"readwatch/internal/settings"
)

func installApp() error {
	if !isElevated() {
		ownerSID, err := currentUserSID()
		if err != nil {
			return err
		}
		return elevateSelf("--install-elevated --owner-sid " + ownerSID)
	}
	p := paths()
	ownerSID, err := currentUserSID()
	if err != nil {
		return err
	}
	if expectedInstallOwnerSID != "" && !strings.EqualFold(ownerSID, expectedInstallOwnerSID) {
		return errors.New("approve installation using the same Windows account that launched ReadWatch")
	}
	ownerName := currentUserName()

	// A running UI keeps the installed executable open. Close an older instance
	// before updating it, but never signal the installer process itself.
	if !executableIsInstalled() {
		if existing, loadErr := loadServiceConfig(p.Config, p.DefaultLog); loadErr == nil && existing.OwnerSID != "" {
			// 15s, not 4s: exiting the viewer now also stops the service, so a
			// normal shutdown takes about a second and a slow one can take
			// several. The old budget made upgrading over a running viewer fail
			// with a message telling you to close a viewer that was already
			// closing.
			if signalExit(existing.OwnerSID) && !waitForUIExit(existing.OwnerSID, 15*time.Second) {
				return errors.New("ReadWatch is still shutting down; wait a moment and retry installation")
			}
		}
	}
	if err := stopInstalledService(8 * time.Second); err != nil {
		return err
	}
	if err := os.MkdirAll(p.InstallDir, 0o755); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(exe), filepath.Clean(p.Exe)) {
		if err := copyFile(exe, p.Exe); err != nil {
			return fmt.Errorf("install executable: %w", err)
		}
	}
	if err := copyAdjacentAsset("ReadWatch.ico", p.Icon); err != nil {
		return err
	}
	if err := copyAdjacentAsset(installedExe+".manifest", p.Manifest); err != nil {
		return err
	}
	if err := protectDataDirectory(p.DataDir); err != nil {
		return err
	}
	cfg, err := settings.Load(p.Config, p.DefaultLog, ownerSID, ownerName)
	if err != nil {
		return err
	}
	if cfg.OwnerSID != "" && !strings.EqualFold(cfg.OwnerSID, ownerSID) {
		return errors.New("ReadWatch is already configured for another Windows account")
	}
	cfg.OwnerSID = ownerSID
	cfg.OwnerName = ownerName
	if err := settings.Save(p.Config, cfg); err != nil {
		return err
	}
	if err := protectDataDirectory(p.DataDir); err != nil {
		return err
	}
	if err := prepareDefaultLogDirectory(ownerSID); err != nil {
		return err
	}
	if err := createOrUpdateService(ownerSID); err != nil {
		return err
	}
	if err := createShellLink(p.StartMenu, p.Exe, p.Icon); err != nil {
		return err
	}
	if err := registerUninstaller(version); err != nil {
		return err
	}
	if err := setStartup(cfg.StartAtLogin); err != nil {
		return err
	}
	// Installing no longer starts LocalSystem. The service comes up only when
	// monitoring is on, so a fresh install leaves nothing privileged running and
	// the viewer starts it on demand. An upgrade over a configuration that was
	// already monitoring resumes it here.
	if cfg.Enabled {
		if err := startInstalledService(); err != nil {
			return err
		}
		if err := waitForServiceState(SERVICE_RUNNING, 10*time.Second); err != nil {
			return err
		}
	}
	if err := launch(p.Exe, "--installed"); err != nil {
		return err
	}
	return nil
}

func beginUninstall(quiet bool) error {
	if !executableIsInstalled() && isElevated() {
		return uninstallElevated(quiet)
	}
	tempDir := filepath.Join(os.TempDir(), "ReadWatch-Uninstall")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return err
	}
	tempExe := filepath.Join(tempDir, fmt.Sprintf("ReadWatch-Uninstall-%d.exe", time.Now().UnixNano()))
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if err := copyFile(src, tempExe); err != nil {
		return err
	}
	args := "--uninstall-elevated"
	if quiet {
		args += " --quiet"
	}
	return elevatePath(tempExe, args)
}

func elevatePath(exe, args string) error {
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

func uninstallElevated(quiet bool) error {
	if !isElevated() {
		return errors.New("uninstall requires administrator permission")
	}
	p := paths()
	cfg, cfgErr := loadServiceConfig(p.Config, p.DefaultLog)
	if cfgErr != nil && !errors.Is(cfgErr, os.ErrNotExist) {
		return fmt.Errorf("read configuration before uninstall: %w", cfgErr)
	}
	serviceStopped := false
	if cfgErr == nil {
		if sid, err := currentUserSID(); err == nil && cfg.OwnerSID != "" && !strings.EqualFold(sid, cfg.OwnerSID) {
			return errors.New("approve uninstall using the same Windows account that installed ReadWatch")
		}
		if cfg.OwnerSID != "" {
			_ = signalExit(cfg.OwnerSID)
			if !waitForUIExit(cfg.OwnerSID, 15*time.Second) {
				return errors.New("ReadWatch is still running; exit it from the tray and retry uninstall")
			}
		}
		if client, err := ConnectIPC(cfg.OwnerSID, 1500*time.Millisecond, nil, nil, nil); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cleanupErr := client.Command(ctx, protocol.CmdCleanup, nil)
			cancel()
			client.Close()
			if cleanupErr != nil {
				return fmt.Errorf("remove folder audit rules: %w", cleanupErr)
			}
		} else {
			if err := stopInstalledService(8 * time.Second); err != nil {
				return err
			}
			serviceStopped = true
			if err := directAuditCleanup(&cfg); err != nil {
				return fmt.Errorf("remove folder audit rules: %w", err)
			}
		}
	}
	if !serviceStopped {
		if err := stopInstalledService(8 * time.Second); err != nil {
			return err
		}
	}
	if err := deleteInstalledService(); err != nil {
		return err
	}
	if err := setStartup(false); err != nil {
		return err
	}
	_ = removeViewerPreferences()
	_ = os.Remove(p.StartMenu)
	if err := unregisterUninstaller(); err != nil {
		return err
	}
	if err := os.RemoveAll(p.InstallDir); err != nil {
		return fmt.Errorf("remove installation folder: %w", err)
	}
	if err := os.RemoveAll(p.DataDir); err != nil {
		return fmt.Errorf("remove configuration folder: %w", err)
	}

	self, _ := os.Executable()
	if self != "" && !strings.EqualFold(filepath.Clean(self), filepath.Clean(p.Exe)) {
		procMoveFileExW.Call(uintptr(unsafe.Pointer(utf16Ptr(self))), 0, 0x4)
	}
	if !quiet {
		messageBox(0, "ReadWatch was removed. Your log file was left in place.", appName, MB_OK|MB_ICONINFORMATION)
	}
	return nil
}

func directAuditCleanup(cfg *settings.Config) error {
	if err := cleanupAuditState(cfg); err != nil {
		return err
	}
	cfg.Enabled = false
	return settings.Save(paths().Config, *cfg)
}

// serviceSDDL grants the interactive owner exactly enough to run the service on
// demand and no more. Start (RP), stop (WP), query status (LC), query config
// (CC), interrogate (LO) and read the descriptor (RC) are granted; change config
// (DC), delete (SD), WRITE_DAC (WD) and WRITE_OWNER (WO) are withheld, because a
// medium-integrity process that could rewrite the service's ImagePath would have
// arbitrary code execution as LocalSystem.
//
// The OWNER RIGHTS ACE is load-bearing, not decoration. Whoever owns the object
// otherwise gets implicit READ_CONTROL|WRITE_DAC, which would let the owning
// account hand itself the rights withheld above. Capping OWNER RIGHTS at RC
// closes that path.
func serviceSDDL(ownerSID string) string {
	const full = "CCDCLCSWRPWPDTLOCRSDRCWDWO"
	sddl := "D:P(A;;" + full + ";;;SY)(A;;" + full + ";;;BA)"
	if ownerSID != "" {
		sddl += "(A;;CCLCSWRPWPLORC;;;" + ownerSID + ")"
	}
	return sddl + "(A;;RC;;;OW)"
}

func applyServiceSecurity(svc uintptr, ownerSID string) error {
	_, sd, err := securityAttributesFromSDDL(serviceSDDL(ownerSID))
	if err != nil {
		return err
	}
	defer procLocalFree.Call(sd)
	r, _, e := procSetServiceObjectSecurity.Call(svc, DACL_SECURITY_INFORMATION, sd)
	if r == 0 {
		return winErr("SetServiceObjectSecurity", e)
	}
	return nil
}

func createOrUpdateService(ownerSID string) error {
	scm, _, e := procOpenSCManagerW.Call(0, 0, SC_MANAGER_ALL_ACCESS)
	if scm == 0 {
		return winErr("OpenSCManager", e)
	}
	defer closeServiceHandle(SC_HANDLE(scm))

	binaryPath := fmt.Sprintf(`"%s" --service`, paths().Exe)
	svc, _, createErr := procCreateServiceW.Call(
		scm,
		uintptr(unsafe.Pointer(utf16Ptr(serviceName))),
		uintptr(unsafe.Pointer(utf16Ptr(serviceDisplay))),
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		uintptr(unsafe.Pointer(utf16Ptr(binaryPath))),
		0, 0, 0, 0, 0,
	)
	if svc == 0 {
		if errno, ok := createErr.(syscall.Errno); !ok || errno != ERROR_SERVICE_EXISTS {
			return winErr("CreateService", createErr)
		}
		svc, _, e = procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(utf16Ptr(serviceName))), SERVICE_ALL_ACCESS)
		if svc == 0 {
			return winErr("OpenService", e)
		}
	}
	defer closeServiceHandle(SC_HANDLE(svc))
	r, _, e := procChangeServiceConfigW.Call(
		svc,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		uintptr(unsafe.Pointer(utf16Ptr(binaryPath))),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(utf16Ptr(serviceDisplay))),
	)
	if r == 0 {
		return winErr("ChangeServiceConfig", e)
	}
	desc := SERVICE_DESCRIPTIONW{Description: utf16Ptr("Records successful reads from selected local folders and streams them to ReadWatch.")}
	r, _, e = procChangeServiceConfig2W.Call(svc, SERVICE_CONFIG_DESCRIPTION, uintptr(unsafe.Pointer(&desc)))
	if r == 0 {
		return winErr("ChangeServiceConfig2(description)", e)
	}
	// Demand-start has no autostart to delay, so the delayed-autostart setting is
	// gone. The DACL replaces it as the thing that makes on-demand control work:
	// without it a medium-integrity UI cannot start or stop the service at all.
	return applyServiceSecurity(svc, ownerSID)
}

func openInstalledService(access uint32) (SC_HANDLE, SC_HANDLE, error) {
	scm, _, e := procOpenSCManagerW.Call(0, 0, SC_MANAGER_CONNECT)
	if scm == 0 {
		return 0, 0, winErr("OpenSCManager", e)
	}
	svc, _, e := procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(utf16Ptr(serviceName))), uintptr(access))
	if svc == 0 {
		closeServiceHandle(SC_HANDLE(scm))
		return 0, 0, winErr("OpenService", e)
	}
	return SC_HANDLE(scm), SC_HANDLE(svc), nil
}

func startInstalledService() error {
	scm, svc, err := openInstalledService(SERVICE_START | SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer closeServiceHandle(scm)
	defer closeServiceHandle(svc)
	r, _, e := procStartServiceW.Call(uintptr(svc), 0, 0)
	if r == 0 {
		if errno, ok := e.(syscall.Errno); ok && errno == ERROR_SERVICE_ALREADY_RUNNING {
			return nil
		}
		return winErr("StartService", e)
	}
	return nil
}

func stopInstalledService(timeout time.Duration) error {
	scm, svc, err := openInstalledService(SERVICE_STOP | SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, syscall.Errno(ERROR_SERVICE_DOES_NOT_EXIST)) {
			return nil
		}
		return err
	}
	defer closeServiceHandle(scm)
	defer closeServiceHandle(svc)
	var status SERVICE_STATUS
	r, _, e := procControlService.Call(uintptr(svc), SERVICE_CONTROL_STOP, uintptr(unsafe.Pointer(&status)))
	if r == 0 {
		if errno, ok := e.(syscall.Errno); ok && errno == ERROR_SERVICE_NOT_ACTIVE {
			return nil
		}
		return winErr("ControlService(stop)", e)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, qErr := queryServiceStateHandle(svc)
		if qErr == nil && state == SERVICE_STOPPED {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.New("timed out waiting for the ReadWatch service to stop")
}

func deleteInstalledService() error {
	scm, svc, err := openInstalledService(DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, syscall.Errno(ERROR_SERVICE_DOES_NOT_EXIST)) {
			return nil
		}
		return err
	}
	defer closeServiceHandle(scm)
	defer closeServiceHandle(svc)
	r, _, e := procDeleteService.Call(uintptr(svc))
	if r == 0 {
		return winErr("DeleteService", e)
	}
	return nil
}

func queryServiceStateHandle(svc SC_HANDLE) (uint32, error) {
	var status SERVICE_STATUS_PROCESS
	var needed uint32
	r, _, e := procQueryServiceStatusEx.Call(uintptr(svc), SC_STATUS_PROCESS_INFO, uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Sizeof(status)), uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return 0, winErr("QueryServiceStatusEx", e)
	}
	return status.CurrentState, nil
}

func queryInstalledServiceState() (uint32, error) {
	scm, svc, err := openInstalledService(SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer closeServiceHandle(scm)
	defer closeServiceHandle(svc)
	return queryServiceStateHandle(svc)
}

func waitForServiceState(want uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := queryInstalledServiceState()
		if err == nil && state == want {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("ReadWatch service did not reach state %d", want)
}
