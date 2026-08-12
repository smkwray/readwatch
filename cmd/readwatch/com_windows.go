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

func comMethod(obj unsafe.Pointer, index uintptr, args ...uintptr) (uintptr, uintptr, syscall.Errno) {
	vtbl := *(*unsafe.Pointer)(obj)
	fn := *(*uintptr)(unsafe.Add(vtbl, index*unsafe.Sizeof(uintptr(0))))
	all := make([]uintptr, 0, len(args)+1)
	all = append(all, uintptr(obj))
	all = append(all, args...)
	r1, r2, err := syscall.SyscallN(fn, all...)
	return r1, r2, err
}

func comRelease(obj unsafe.Pointer) {
	if obj != nil {
		comMethod(obj, 2)
	}
}

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
	return obj, nil
}

func comQueryInterface(obj unsafe.Pointer, iid *GUID) (unsafe.Pointer, error) {
	var out unsafe.Pointer
	hr, _, _ := comMethod(obj, 0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))
	if failed(hr) {
		return nil, hrError("QueryInterface", hr)
	}
	return out, nil
}

func createShellLink(linkPath, targetPath, iconPath string) error {
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

	if hr, _, _ := comMethod(link, 20, uintptr(unsafe.Pointer(utf16Ptr(targetPath)))); failed(hr) {
		return hrError("IShellLink.SetPath", hr)
	}
	if hr, _, _ := comMethod(link, 7, uintptr(unsafe.Pointer(utf16Ptr("Monitor which processes read selected folders")))); failed(hr) {
		return hrError("IShellLink.SetDescription", hr)
	}
	if hr, _, _ := comMethod(link, 9, uintptr(unsafe.Pointer(utf16Ptr(filepath.Dir(targetPath))))); failed(hr) {
		return hrError("IShellLink.SetWorkingDirectory", hr)
	}
	if iconPath != "" {
		if hr, _, _ := comMethod(link, 17, uintptr(unsafe.Pointer(utf16Ptr(iconPath))), 0); failed(hr) {
			return hrError("IShellLink.SetIconLocation", hr)
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
	if hr, _, _ := comMethod(persist, 6, uintptr(unsafe.Pointer(utf16Ptr(linkPath))), 1); failed(hr) {
		return hrError("IPersistFile.Save", hr)
	}
	return nil
}

func pickFolder(owner HWND) (string, bool, error) {
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

	var options uint32
	if hr, _, _ := comMethod(dlg, 10, uintptr(unsafe.Pointer(&options))); failed(hr) {
		return "", false, hrError("IFileDialog.GetOptions", hr)
	}
	options |= FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST
	if hr, _, _ := comMethod(dlg, 9, uintptr(options)); failed(hr) {
		return "", false, hrError("IFileDialog.SetOptions", hr)
	}
	comMethod(dlg, 17, uintptr(unsafe.Pointer(utf16Ptr("Choose a folder to watch"))))
	hr, _, _ := comMethod(dlg, 3, uintptr(owner))
	if uint32(hr) == 0x800704C7 { // HRESULT_FROM_WIN32(ERROR_CANCELLED)
		return "", false, nil
	}
	if failed(hr) {
		return "", false, hrError("IFileDialog.Show", hr)
	}
	return fileDialogResult(dlg)
}

func pickLogFile(owner HWND, current, format string) (string, bool, error) {
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

	var options uint32
	comMethod(dlg, 10, uintptr(unsafe.Pointer(&options)))
	options |= FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT | FOS_NOREADONLYRETURN
	comMethod(dlg, 9, uintptr(options))
	comMethod(dlg, 17, uintptr(unsafe.Pointer(utf16Ptr("Choose the ReadWatch log file"))))

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
	comMethod(dlg, 15, uintptr(unsafe.Pointer(utf16Ptr(name))))
	comMethod(dlg, 22, uintptr(unsafe.Pointer(utf16Ptr(strings.TrimPrefix(ext, ".")))))

	hr, _, _ := comMethod(dlg, 3, uintptr(owner))
	if uint32(hr) == 0x800704C7 {
		return "", false, nil
	}
	if failed(hr) {
		return "", false, hrError("IFileDialog.Show", hr)
	}
	path, ok, err := fileDialogResult(dlg)
	if err == nil && ok && filepath.Ext(path) == "" {
		path += ext
	}
	return path, ok, err
}

func fileDialogResult(dlg unsafe.Pointer) (string, bool, error) {
	var item unsafe.Pointer
	if hr, _, _ := comMethod(dlg, 20, uintptr(unsafe.Pointer(&item))); failed(hr) {
		return "", false, hrError("IFileDialog.GetResult", hr)
	}
	defer comRelease(item)
	var text *uint16
	if hr, _, _ := comMethod(item, 5, SIGDN_FILESYSPATH, uintptr(unsafe.Pointer(&text))); failed(hr) {
		return "", false, hrError("IShellItem.GetDisplayName", hr)
	}
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(text)))
	return utf16FromPtr(text), true, nil
}
