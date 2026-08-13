//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// Every vtable method below gets its own wrapper with exact pointer and scalar
// parameter types. The generic `comMethod(obj, index, ...uintptr)` this
// replaces converted Go pointers to uintptr at each call site, carried them
// through a []uintptr and only then reached syscall.SyscallN - so the value had
// stopped being a pointer long before the call that consumes it, which is
// exactly what the unsafe.Pointer rules forbid. go vet was clean because the
// helper hid the conversion from it, not because the pattern was sound.
//
// A wrapper taking unsafe.Pointer arguments would have been legal, but it
// cannot describe this surface honestly: Show takes an HWND, SetOptions a flag
// word, SetIconLocation a string and an index. Scalars written as
// unsafe.Pointer(uintptr(v)) would put the ambiguity straight back. The
// signature is the ABI documentation.

var (
	clsidShellLink  = GUID{0x00021401, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidIShellLinkW  = GUID{0x000214F9, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidIPersistFile = GUID{0x0000010B, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}

	clsidFileOpenDialog = GUID{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	iidIFileOpenDialog  = GUID{0xD57C7288, 0xD4AD, 0x4768, [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
	clsidFileSaveDialog = GUID{0xC0B4E2F3, 0xBA21, 0x4773, [8]byte{0x8D, 0xBA, 0x33, 0x5E, 0xC9, 0x46, 0xEB, 0x8B}}
	iidIFileSaveDialog  = GUID{0x84BCCD23, 0x5FDE, 0x4CDB, [8]byte{0xAE, 0xA4, 0xAF, 0x64, 0xB8, 0x3D, 0x78, 0xAB}}
)

func failed(hr uintptr) bool { return int32(hr) < 0 }
func hrError(label string, hr uintptr) error {
	return fmt.Errorf("%s failed: HRESULT 0x%08x", label, uint32(hr))
}

// hrCancelled is what a dialog returns when the user closes it.
const hrCancelled = 0x800704C7 // HRESULT_FROM_WIN32(ERROR_CANCELLED)

// comSlot reads a method address out of an object's vtable. It returns a code
// address, never an argument, so nothing here outlives the read.
func comSlot(obj unsafe.Pointer, index uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(obj)
	return *(*uintptr)(unsafe.Add(vtbl, index*unsafe.Sizeof(uintptr(0))))
}

// --- IUnknown -------------------------------------------------------------

func comQueryInterface(obj unsafe.Pointer, iid *GUID) (unsafe.Pointer, error) {
	var out unsafe.Pointer
	hr, _, _ := syscall.SyscallN(
		comSlot(obj, 0),
		uintptr(obj),
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(iid)
	if failed(hr) {
		return nil, hrError("IUnknown.QueryInterface", hr)
	}
	if out == nil {
		return nil, errors.New("IUnknown.QueryInterface returned a nil interface")
	}
	return out, nil
}

func comRelease(obj unsafe.Pointer) {
	if obj == nil {
		return
	}
	syscall.SyscallN(comSlot(obj, 2), uintptr(obj))
}

// --- IShellLinkW ----------------------------------------------------------

func shellLinkSetPath(link unsafe.Pointer, path *uint16) error {
	hr, _, _ := syscall.SyscallN(
		comSlot(link, 20),
		uintptr(link),
		uintptr(unsafe.Pointer(path)),
	)
	runtime.KeepAlive(path)
	if failed(hr) {
		return hrError("IShellLinkW.SetPath", hr)
	}
	return nil
}

func shellLinkSetDescription(link unsafe.Pointer, text *uint16) error {
	hr, _, _ := syscall.SyscallN(
		comSlot(link, 7),
		uintptr(link),
		uintptr(unsafe.Pointer(text)),
	)
	runtime.KeepAlive(text)
	if failed(hr) {
		return hrError("IShellLinkW.SetDescription", hr)
	}
	return nil
}

func shellLinkSetWorkingDirectory(link unsafe.Pointer, dir *uint16) error {
	hr, _, _ := syscall.SyscallN(
		comSlot(link, 9),
		uintptr(link),
		uintptr(unsafe.Pointer(dir)),
	)
	runtime.KeepAlive(dir)
	if failed(hr) {
		return hrError("IShellLinkW.SetWorkingDirectory", hr)
	}
	return nil
}

func shellLinkSetIconLocation(link unsafe.Pointer, path *uint16, index int32) error {
	hr, _, _ := syscall.SyscallN(
		comSlot(link, 17),
		uintptr(link),
		uintptr(unsafe.Pointer(path)),
		uintptr(index),
	)
	runtime.KeepAlive(path)
	if failed(hr) {
		return hrError("IShellLinkW.SetIconLocation", hr)
	}
	return nil
}

// --- IPersistFile ---------------------------------------------------------

func persistFileSave(persist unsafe.Pointer, path *uint16, remember bool) error {
	flag := uintptr(0)
	if remember {
		flag = 1
	}
	hr, _, _ := syscall.SyscallN(
		comSlot(persist, 6),
		uintptr(persist),
		uintptr(unsafe.Pointer(path)),
		flag,
	)
	runtime.KeepAlive(path)
	if failed(hr) {
		return hrError("IPersistFile.Save", hr)
	}
	return nil
}

// --- IFileDialog ----------------------------------------------------------

// fileDialogShow reports ok=false for a user cancellation, which is an outcome
// rather than a failure.
func fileDialogShow(dialog unsafe.Pointer, owner HWND) (bool, error) {
	hr, _, _ := syscall.SyscallN(
		comSlot(dialog, 3),
		uintptr(dialog),
		uintptr(owner),
	)
	if uint32(hr) == hrCancelled {
		return false, nil
	}
	if failed(hr) {
		return false, hrError("IFileDialog.Show", hr)
	}
	return true, nil
}

func fileDialogGetOptions(dialog unsafe.Pointer) (uint32, error) {
	var options uint32
	hr, _, _ := syscall.SyscallN(
		comSlot(dialog, 10),
		uintptr(dialog),
		uintptr(unsafe.Pointer(&options)),
	)
	if failed(hr) {
		return 0, hrError("IFileDialog.GetOptions", hr)
	}
	return options, nil
}

func fileDialogSetOptions(dialog unsafe.Pointer, options uint32) error {
	hr, _, _ := syscall.SyscallN(
		comSlot(dialog, 9),
		uintptr(dialog),
		uintptr(options),
	)
	if failed(hr) {
		return hrError("IFileDialog.SetOptions", hr)
	}
	return nil
}

func fileDialogSetTitle(dialog unsafe.Pointer, title *uint16) error {
	hr, _, _ := syscall.SyscallN(
		comSlot(dialog, 17),
		uintptr(dialog),
		uintptr(unsafe.Pointer(title)),
	)
	runtime.KeepAlive(title)
	if failed(hr) {
		return hrError("IFileDialog.SetTitle", hr)
	}
	return nil
}

func fileDialogSetFileName(dialog unsafe.Pointer, name *uint16) error {
	hr, _, _ := syscall.SyscallN(
		comSlot(dialog, 15),
		uintptr(dialog),
		uintptr(unsafe.Pointer(name)),
	)
	runtime.KeepAlive(name)
	if failed(hr) {
		return hrError("IFileDialog.SetFileName", hr)
	}
	return nil
}

func fileDialogSetDefaultExtension(dialog unsafe.Pointer, ext *uint16) error {
	hr, _, _ := syscall.SyscallN(
		comSlot(dialog, 22),
		uintptr(dialog),
		uintptr(unsafe.Pointer(ext)),
	)
	runtime.KeepAlive(ext)
	if failed(hr) {
		return hrError("IFileDialog.SetDefaultExtension", hr)
	}
	return nil
}

func fileDialogGetResult(dialog unsafe.Pointer) (unsafe.Pointer, error) {
	var item unsafe.Pointer
	hr, _, _ := syscall.SyscallN(
		comSlot(dialog, 20),
		uintptr(dialog),
		uintptr(unsafe.Pointer(&item)),
	)
	if failed(hr) {
		return nil, hrError("IFileDialog.GetResult", hr)
	}
	if item == nil {
		return nil, errors.New("IFileDialog.GetResult returned a nil item")
	}
	return item, nil
}

// --- IShellItem -----------------------------------------------------------

// shellItemGetDisplayName returns COM-allocated memory the caller frees with
// CoTaskMemFree.
func shellItemGetDisplayName(item unsafe.Pointer, kind uint32) (*uint16, error) {
	var text *uint16
	hr, _, _ := syscall.SyscallN(
		comSlot(item, 5),
		uintptr(item),
		uintptr(kind),
		uintptr(unsafe.Pointer(&text)),
	)
	if failed(hr) {
		return nil, hrError("IShellItem.GetDisplayName", hr)
	}
	if text == nil {
		return nil, errors.New("IShellItem.GetDisplayName returned nil")
	}
	return text, nil
}

// --- COM lifetime ---------------------------------------------------------

func coInit() (bool, error) {
	hr, _, _ := procCoInitializeEx.Call(0, COINIT_APARTMENTTHREADED)
	if failed(hr) {
		return false, hrError("CoInitializeEx", hr)
	}
	return true, nil
}

func coCreate(clsid, iid *GUID) (unsafe.Pointer, error) {
	var obj unsafe.Pointer
	hr, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(clsid)), 0, CLSCTX_INPROC_SERVER,
		uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&obj)),
	)
	if failed(hr) {
		return nil, hrError("CoCreateInstance", hr)
	}
	if obj == nil {
		return nil, errors.New("CoCreateInstance returned a nil interface")
	}
	return obj, nil
}

// --- Callers --------------------------------------------------------------

func createShellLink(linkPath, targetPath, iconPath string) error {
	target, err := syscall.UTF16PtrFromString(targetPath)
	if err != nil {
		return fmt.Errorf("encode shortcut target: %w", err)
	}
	description, err := syscall.UTF16PtrFromString("Monitor which processes read selected folders")
	if err != nil {
		return err
	}
	workingDir, err := syscall.UTF16PtrFromString(filepath.Dir(targetPath))
	if err != nil {
		return fmt.Errorf("encode shortcut working directory: %w", err)
	}
	link16, err := syscall.UTF16PtrFromString(linkPath)
	if err != nil {
		return fmt.Errorf("encode shortcut path: %w", err)
	}

	inited, err := coInit()
	if err != nil {
		return err
	}
	if inited {
		defer procCoUninitialize.Call()
	}
	link, err := coCreate(&clsidShellLink, &iidIShellLinkW)
	if err != nil {
		return err
	}
	defer comRelease(link)

	if err := shellLinkSetPath(link, target); err != nil {
		return err
	}
	if err := shellLinkSetDescription(link, description); err != nil {
		return err
	}
	if err := shellLinkSetWorkingDirectory(link, workingDir); err != nil {
		return err
	}
	if iconPath != "" {
		icon, err := syscall.UTF16PtrFromString(iconPath)
		if err != nil {
			return fmt.Errorf("encode shortcut icon path: %w", err)
		}
		if err := shellLinkSetIconLocation(link, icon, 0); err != nil {
			return err
		}
	}

	persist, err := comQueryInterface(link, &iidIPersistFile)
	if err != nil {
		return err
	}
	defer comRelease(persist)
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
		return err
	}
	return persistFileSave(persist, link16, true)
}

func pickFolder(owner HWND) (string, bool, error) {
	title, err := syscall.UTF16PtrFromString("Choose a folder to watch")
	if err != nil {
		return "", false, err
	}
	inited, err := coInit()
	if err != nil {
		return "", false, err
	}
	if inited {
		defer procCoUninitialize.Call()
	}
	dlg, err := coCreate(&clsidFileOpenDialog, &iidIFileOpenDialog)
	if err != nil {
		return "", false, err
	}
	defer comRelease(dlg)

	options, err := fileDialogGetOptions(dlg)
	if err != nil {
		return "", false, err
	}
	// FOS_PICKFOLDERS is what makes this the folder picker the contract
	// requires, so a failure here must not fall through to a file dialog.
	options |= FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST
	if err := fileDialogSetOptions(dlg, options); err != nil {
		return "", false, err
	}
	if err := fileDialogSetTitle(dlg, title); err != nil {
		return "", false, err
	}
	shown, err := fileDialogShow(dlg, owner)
	if err != nil || !shown {
		return "", false, err
	}
	return fileDialogResult(dlg)
}

func pickLogFile(owner HWND, current, format string) (string, bool, error) {
	ext := ".log"
	if format == "jsonl" {
		ext = ".jsonl"
	} else if format == "csv" {
		ext = ".csv"
	}
	name := filepath.Base(current)
	if name == "." || name == string(filepath.Separator) || name == "" {
		name = "ReadWatch" + ext
	}
	title, err := syscall.UTF16PtrFromString("Choose the ReadWatch log file")
	if err != nil {
		return "", false, err
	}
	name16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", false, err
	}
	ext16, err := syscall.UTF16PtrFromString(strings.TrimPrefix(ext, "."))
	if err != nil {
		return "", false, err
	}

	inited, err := coInit()
	if err != nil {
		return "", false, err
	}
	if inited {
		defer procCoUninitialize.Call()
	}
	dlg, err := coCreate(&clsidFileSaveDialog, &iidIFileSaveDialog)
	if err != nil {
		return "", false, err
	}
	defer comRelease(dlg)

	options, err := fileDialogGetOptions(dlg)
	if err != nil {
		return "", false, err
	}
	options |= FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT | FOS_NOREADONLYRETURN
	if err := fileDialogSetOptions(dlg, options); err != nil {
		return "", false, err
	}
	if err := fileDialogSetTitle(dlg, title); err != nil {
		return "", false, err
	}
	if err := fileDialogSetFileName(dlg, name16); err != nil {
		return "", false, err
	}
	if err := fileDialogSetDefaultExtension(dlg, ext16); err != nil {
		return "", false, err
	}

	shown, err := fileDialogShow(dlg, owner)
	if err != nil || !shown {
		return "", false, err
	}
	path, ok, err := fileDialogResult(dlg)
	if err == nil && ok && filepath.Ext(path) == "" {
		path += ext
	}
	return path, ok, err
}

func fileDialogResult(dlg unsafe.Pointer) (string, bool, error) {
	item, err := fileDialogGetResult(dlg)
	if err != nil {
		return "", false, err
	}
	defer comRelease(item)
	text, err := shellItemGetDisplayName(item, SIGDN_FILESYSPATH)
	if err != nil {
		return "", false, err
	}
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(text)))
	return utf16FromPtr(text), true, nil
}
