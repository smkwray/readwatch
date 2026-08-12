//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	personalizeKey = `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`
	runKey         = `Software\Microsoft\Windows\CurrentVersion\Run`
	uninstallKey   = `Software\Microsoft\Windows\CurrentVersion\Uninstall\ReadWatch`
)

func regReadDWORD(root uintptr, subkey, name string) (uint32, bool) {
	var key uintptr
	r, _, _ := procRegOpenKeyExW.Call(root, uintptr(unsafe.Pointer(utf16Ptr(subkey))), 0, KEY_READ, uintptr(unsafe.Pointer(&key)))
	if r != ERROR_SUCCESS {
		return 0, false
	}
	defer procRegCloseKey.Call(key)
	var typ uint32
	var value uint32
	size := uint32(4)
	r, _, _ = procRegQueryValueExW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(name))), 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&size)))
	return value, r == ERROR_SUCCESS && typ == REG_DWORD
}

func regSetString(root uintptr, subkey, name, value string, wow64 bool) error {
	var key uintptr
	var disposition uint32
	access := uintptr(KEY_WRITE)
	if wow64 {
		access |= KEY_WOW64_64KEY
	}
	r, _, _ := procRegCreateKeyExW.Call(
		root,
		uintptr(unsafe.Pointer(utf16Ptr(subkey))),
		0, 0, REG_OPTION_NON_VOLATILE, access, 0,
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&disposition)),
	)
	if r != ERROR_SUCCESS {
		return fmt.Errorf("create registry key: %w", syscall.Errno(r))
	}
	defer procRegCloseKey.Call(key)
	u := syscall.StringToUTF16(value)
	r, _, _ = procRegSetValueExW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(name))), 0, REG_SZ, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)*2))
	if r != ERROR_SUCCESS {
		return fmt.Errorf("set registry value: %w", syscall.Errno(r))
	}
	return nil
}

func regDeleteValue(root uintptr, subkey, name string, wow64 bool) error {
	var key uintptr
	access := uintptr(KEY_WRITE)
	if wow64 {
		access |= KEY_WOW64_64KEY
	}
	r, _, _ := procRegOpenKeyExW.Call(root, uintptr(unsafe.Pointer(utf16Ptr(subkey))), 0, access, uintptr(unsafe.Pointer(&key)))
	if r != ERROR_SUCCESS {
		return nil
	}
	defer procRegCloseKey.Call(key)
	r, _, _ = procRegDeleteValueW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(name))))
	if r != ERROR_SUCCESS && r != 2 {
		return fmt.Errorf("delete registry value: %w", syscall.Errno(r))
	}
	return nil
}

func regDeleteTree(root uintptr, subkey string, wow64 bool) error {
	var key uintptr
	access := uintptr(KEY_ALL_ACCESS)
	if wow64 {
		access |= KEY_WOW64_64KEY
	}
	r, _, _ := procRegOpenKeyExW.Call(root, uintptr(unsafe.Pointer(utf16Ptr(`Software\Microsoft\Windows\CurrentVersion\Uninstall`))), 0, access, uintptr(unsafe.Pointer(&key)))
	if r != ERROR_SUCCESS {
		return nil
	}
	defer procRegCloseKey.Call(key)
	r, _, _ = procRegDeleteTreeW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(filepath.Base(subkey)))))
	if r != ERROR_SUCCESS && r != 2 {
		return fmt.Errorf("delete registry tree: %w", syscall.Errno(r))
	}
	return nil
}

func isHighContrast() bool {
	hc := HIGHCONTRASTW{CbSize: uint32(unsafe.Sizeof(HIGHCONTRASTW{}))}
	r, _, _ := procSystemParametersInfoW.Call(SPI_GETHIGHCONTRAST, uintptr(hc.CbSize), uintptr(unsafe.Pointer(&hc)), 0)
	return r != 0 && hc.DwFlags&HCF_HIGHCONTRASTON != 0
}

func systemDarkMode() bool {
	if isHighContrast() {
		return false
	}
	v, ok := regReadDWORD(HKEY_CURRENT_USER, personalizeKey, "AppsUseLightTheme")
	return ok && v == 0
}

func setStartup(enabled bool) error {
	if !enabled {
		return regDeleteValue(HKEY_CURRENT_USER, runKey, appName, false)
	}
	cmd := fmt.Sprintf(`"%s" --startup`, paths().Exe)
	return regSetString(HKEY_CURRENT_USER, runKey, appName, cmd, false)
}

func registerUninstaller(version string) error {
	p := paths()
	values := map[string]string{
		"DisplayName":          appName,
		"DisplayVersion":       version,
		"Publisher":            "ReadWatch",
		"DisplayIcon":          p.Icon,
		"InstallLocation":      p.InstallDir,
		"UninstallString":      fmt.Sprintf(`"%s" --uninstall`, p.Exe),
		"QuietUninstallString": fmt.Sprintf(`"%s" --uninstall --quiet`, p.Exe),
	}
	for k, v := range values {
		if err := regSetString(HKEY_LOCAL_MACHINE, uninstallKey, k, v, true); err != nil {
			return err
		}
	}
	return nil
}

func unregisterUninstaller() error {
	return regDeleteTree(HKEY_LOCAL_MACHINE, uninstallKey, true)
}

func executableIsInstalled() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	a, errA := filepath.Abs(exe)
	b, errB := filepath.Abs(paths().Exe)
	return errA == nil && errB == nil && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
