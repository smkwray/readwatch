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
	// Preferences about the window rather than about what is watched. The
	// service config is machine state and needs a running service to change;
	// these need neither, so they live in the user's own hive.
	viewerKey = `Software\ReadWatch`
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

// regReadMultiSZ reads a REG_MULTI_SZ value as its list of strings. Used for
// PendingFileRenameOperations, which is where Windows keeps reboot-time file
// operations.
func regReadMultiSZ(root uintptr, subkey, name string) ([]string, error) {
	var key uintptr
	r, _, _ := procRegOpenKeyExW.Call(root, uintptr(unsafe.Pointer(utf16Ptr(subkey))), 0, KEY_READ, uintptr(unsafe.Pointer(&key)))
	if r != ERROR_SUCCESS {
		return nil, syscall.Errno(r)
	}
	defer procRegCloseKey.Call(key)

	var typ, size uint32
	r, _, _ = procRegQueryValueExW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(name))), 0,
		uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&size)))
	if r != ERROR_SUCCESS || size == 0 {
		return nil, nil
	}
	if typ != REG_MULTI_SZ {
		return nil, fmt.Errorf("%s is type %d, not REG_MULTI_SZ", name, typ)
	}
	buf := make([]uint16, (size+1)/2)
	r, _, _ = procRegQueryValueExW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(name))), 0,
		uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != ERROR_SUCCESS {
		return nil, syscall.Errno(r)
	}
	return splitMultiSZ(buf), nil
}

// splitMultiSZ turns the wide double-null-terminated form into strings. Empty
// entries are significant here: a pending rename with no destination means
// "delete", so they are kept rather than skipped.
func splitMultiSZ(buf []uint16) []string {
	var out []string
	start := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] != 0 {
			continue
		}
		if i == start {
			// The terminating empty string ends the list, unless a real empty
			// entry precedes more data.
			if i+1 >= len(buf) || buf[i+1] == 0 {
				break
			}
			out = append(out, "")
			start = i + 1
			continue
		}
		out = append(out, syscall.UTF16ToString(buf[start:i]))
		start = i + 1
	}
	return out
}

func regWriteMultiSZ(root uintptr, subkey, name string, values []string) error {
	var key uintptr
	r, _, _ := procRegOpenKeyExW.Call(root, uintptr(unsafe.Pointer(utf16Ptr(subkey))), 0, KEY_WRITE, uintptr(unsafe.Pointer(&key)))
	if r != ERROR_SUCCESS {
		return syscall.Errno(r)
	}
	defer procRegCloseKey.Call(key)

	if len(values) == 0 {
		// Nothing left to schedule. Removing the value entirely is what Windows
		// itself leaves behind when the last operation is consumed.
		r, _, _ = procRegDeleteValueW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(name))))
		if r != ERROR_SUCCESS && r != ERROR_FILE_NOT_FOUND {
			return syscall.Errno(r)
		}
		return nil
	}

	var buf []uint16
	for _, v := range values {
		buf = append(buf, syscall.StringToUTF16(v)...)
	}
	buf = append(buf, 0)
	r, _, _ = procRegSetValueExW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(name))), 0,
		REG_MULTI_SZ, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2))
	if r != ERROR_SUCCESS {
		return syscall.Errno(r)
	}
	return nil
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

func regSetDWORD(root uintptr, subkey, name string, value uint32) error {
	var key uintptr
	var disposition uint32
	r, _, _ := procRegCreateKeyExW.Call(
		root,
		uintptr(unsafe.Pointer(utf16Ptr(subkey))),
		0, 0, REG_OPTION_NON_VOLATILE, KEY_WRITE, 0,
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&disposition)),
	)
	if r != ERROR_SUCCESS {
		return fmt.Errorf("create registry key: %w", syscall.Errno(r))
	}
	defer procRegCloseKey.Call(key)
	r, _, _ = procRegSetValueExW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(name))), 0, REG_DWORD, uintptr(unsafe.Pointer(&value)), 4)
	if r != ERROR_SUCCESS {
		return fmt.Errorf("set registry value: %w", syscall.Errno(r))
	}
	return nil
}

func alwaysOnTopPreference() bool {
	v, ok := regReadDWORD(HKEY_CURRENT_USER, viewerKey, "AlwaysOnTop")
	return ok && v != 0
}

func setAlwaysOnTopPreference(on bool) error {
	value := uint32(0)
	if on {
		value = 1
	}
	return regSetDWORD(HKEY_CURRENT_USER, viewerKey, "AlwaysOnTop", value)
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

func regDeleteTree(root uintptr, parent, child string, wow64 bool) error {
	var key uintptr
	access := uintptr(KEY_ALL_ACCESS)
	if wow64 {
		access |= KEY_WOW64_64KEY
	}
	r, _, _ := procRegOpenKeyExW.Call(root, uintptr(unsafe.Pointer(utf16Ptr(parent))), 0, access, uintptr(unsafe.Pointer(&key)))
	if r != ERROR_SUCCESS {
		return nil
	}
	defer procRegCloseKey.Call(key)
	r, _, _ = procRegDeleteTreeW.Call(key, uintptr(unsafe.Pointer(utf16Ptr(child))))
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
	return regDeleteTree(HKEY_LOCAL_MACHINE, filepath.Dir(uninstallKey), filepath.Base(uninstallKey), true)
}

// removeViewerPreferences leaves no key of ours behind after an uninstall. Like
// setStartup(false) beside it, this reaches the hive of whoever ran the
// uninstall, which is the same account that installed in the ordinary case.
func removeViewerPreferences() error {
	return regDeleteTree(HKEY_CURRENT_USER, filepath.Dir(viewerKey), filepath.Base(viewerKey), false)
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
