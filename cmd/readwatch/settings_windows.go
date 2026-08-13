//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"readwatch/internal/protocol"
	"readwatch/internal/settings"
)

const (
	idFolderList       = 301
	idAddFolder        = 302
	idRemoveFolder     = 303
	idLogPath          = 304
	idBrowseLog        = 305
	idLogFormat        = 306
	idIncludeFolders   = 307
	idStartAtLogin     = 308
	idOpenAtLogin      = 309
	idFolderPath       = 310
	idAddFolderPath    = 311
	idExcludeList      = 312
	idExcludeText      = 313
	idAddExclude       = 314
	idRemoveExclude    = 315
	idAlwaysOnTop      = 316
	settingsWindowBase = 520
)

var (
	settingsWindowClass = "ReadWatch.SettingsWindow"
	settingsWndProcPtr  = syscall.NewCallback(settingsWindowProc)
	settingsUI          *SettingsUI
)

type SettingsUI struct {
	app  *AppUI
	hwnd HWND
	dpi  uint32
	font HFONT
	cfg  settings.PublicConfig

	foldersLabel HWND
	folderList   HWND
	addBtn       HWND
	removeBtn    HWND
	folderPath   HWND
	addPathBtn   HWND

	excludeLabel     HWND
	excludeList      HWND
	excludeText      HWND
	excludeAddBtn    HWND
	excludeRemoveBtn HWND

	logLabel    HWND
	logPath     HWND
	browseBtn   HWND
	formatLabel HWND
	formatCombo HWND
	includeDirs HWND
	startLogin  HWND
	openLogin   HWND
	alwaysTop   HWND
	saveBtn     HWND
	cancelBtn   HWND

	hover   hintHover
	closing atomic.Bool
}

func (u *AppUI) openSettings() {
	if settingsUI != nil && settingsUI.hwnd != 0 {
		procShowWindow.Call(uintptr(settingsUI.hwnd), SW_RESTORE)
		procSetForegroundWindow.Call(uintptr(settingsUI.hwnd))
		return
	}
	if !u.state.ServiceReady {
		u.queueError(fmt.Errorf("ReadWatch service is not connected"))
		return
	}
	if u.commandBusy.Load() {
		return
	}
	// Both lists are edited in place here and collected back on Save, so both
	// need their own backing array; sharing one with the live state let the
	// dialog rewrite the app's current configuration as it was being typed.
	cfg := u.state.Config
	cfg.Folders = append([]string(nil), cfg.Folders...)
	cfg.ExcludedProcesses = append([]string(nil), cfg.ExcludedProcesses...)
	if cfg.MaxRows < 200 {
		cfg.MaxRows = 1000
	}
	s := &SettingsUI{app: u, cfg: cfg, dpi: u.dpi}
	settingsUI = s
	if err := s.create(); err != nil {
		settingsUI = nil
		u.queueError(err)
		return
	}
	procEnableWindow.Call(uintptr(u.hwnd), 0)
	procShowWindow.Call(uintptr(s.hwnd), SW_SHOW)
	procUpdateWindow.Call(uintptr(s.hwnd))
	procSetForegroundWindow.Call(uintptr(s.hwnd))
	procSetFocus.Call(uintptr(s.folderList))
}

func (s *SettingsUI) create() error {
	instance, _, _ := procGetModuleHandleW.Call(0)
	cursor, _, _ := procLoadCursorW.Call(0, IDC_ARROW)
	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         CS_HREDRAW | CS_VREDRAW,
		LpfnWndProc:   settingsWndProcPtr,
		HInstance:     HINSTANCE(instance),
		HIcon:         s.app.icon,
		HCursor:       HCURSOR(cursor),
		LpszClassName: utf16Ptr(settingsWindowClass),
		HIconSm:       s.app.iconSmall,
	}
	atom, _, e := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		if errno, ok := e.(syscall.Errno); !ok || errno != ERROR_CLASS_ALREADY_EXISTS {
			return winErr("RegisterClassEx(settings)", e)
		}
	}
	if s.dpi == 0 {
		s.dpi = 96
	}
	width := s.scale(520)
	// Tall enough that the last checkbox still clears the Save row, which the
	// layout below anchors to the bottom edge.
	height := s.scale(566)
	x, y := centeredWindowPosition(s.app.hwnd, width, height)
	style := uintptr(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN)
	hwnd, _, e := procCreateWindowExW.Call(
		WS_EX_DLGMODALFRAME|WS_EX_CONTROLPARENT,
		uintptr(unsafe.Pointer(utf16Ptr(settingsWindowClass))),
		uintptr(unsafe.Pointer(utf16Ptr("ReadWatch Settings"))),
		style,
		uintptr(int64(x)), uintptr(int64(y)), uintptr(width), uintptr(height),
		uintptr(s.app.hwnd), 0, instance, 0,
	)
	if hwnd == 0 {
		return winErr("CreateWindowEx(settings)", e)
	}
	s.hwnd = HWND(hwnd)
	if dpi, _, _ := procGetDpiForWindow.Call(hwnd); dpi != 0 {
		s.dpi = uint32(dpi)
	}
	s.createControls()
	s.layout()
	s.applyTheme()
	s.attachHints()
	return nil
}

func centeredWindowPosition(owner HWND, width, height int32) (int32, int32) {
	var rc RECT
	if owner != 0 {
		if ok, _, _ := procGetWindowRect.Call(uintptr(owner), uintptr(unsafe.Pointer(&rc))); ok != 0 {
			return rc.Left + ((rc.Right-rc.Left)-width)/2, rc.Top + ((rc.Bottom-rc.Top)-height)/2
		}
	}
	cx, _, _ := procGetSystemMetrics.Call(0)
	cy, _, _ := procGetSystemMetrics.Call(1)
	return (int32(cx) - width) / 2, (int32(cy) - height) / 2
}

func (s *SettingsUI) scale(v int32) int32 {
	return int32(int64(v) * int64(s.dpi) / 96)
}

func (s *SettingsUI) createControls() {
	s.font = createUIFont(s.dpi)
	s.foldersLabel = createControl("STATIC", "Folders to watch", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE, 0, s.hwnd, 0)
	s.folderList = createControl("LISTBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|WS_VSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT, 0, s.hwnd, idFolderList)
	s.addBtn = createControl("BUTTON", "Browse…", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, idAddFolder)
	s.removeBtn = createControl("BUTTON", "Remove", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, idRemoveFolder)
	// Typing or pasting a path is the primary way to add a folder; the picker is
	// the fallback. Most target folders are already on the clipboard.
	s.folderPath = createControl("EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_AUTOHSCROLL, 0, s.hwnd, idFolderPath)
	s.addPathBtn = createControl("BUTTON", "Add", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, idAddFolderPath)
	sendMessage(s.folderPath, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(utf16Ptr(`Paste a folder path, e.g. D:\Renders\output`))))

	s.excludeLabel = createControl("STATIC", "Ignore reads by these processes", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE, 0, s.hwnd, 0)
	s.excludeList = createControl("LISTBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|WS_VSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT, 0, s.hwnd, idExcludeList)
	s.excludeText = createControl("EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_AUTOHSCROLL, 0, s.hwnd, idExcludeText)
	s.excludeAddBtn = createControl("BUTTON", "Add", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, idAddExclude)
	s.excludeRemoveBtn = createControl("BUTTON", "Remove", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, idRemoveExclude)
	sendMessage(s.excludeText, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(utf16Ptr("Image name, or a full path to match only that binary"))))
	s.logLabel = createControl("STATIC", "Log file", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE, 0, s.hwnd, 0)
	s.logPath = createControl("EDIT", s.cfg.LogPath, WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_AUTOHSCROLL, 0, s.hwnd, idLogPath)
	s.browseBtn = createControl("BUTTON", "Browse…", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, idBrowseLog)
	s.formatLabel = createControl("STATIC", "Format", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE, 0, s.hwnd, 0)
	s.formatCombo = createControl("COMBOBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_VSCROLL|CBS_DROPDOWNLIST, 0, s.hwnd, idLogFormat)
	// The old labels described the visible symptom rather than what the setting
	// does, and both were misread on first use.
	s.includeDirs = createControl("BUTTON", "Also log reads of the folder itself, not just files", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 0, s.hwnd, idIncludeFolders)
	s.startLogin = createControl("BUTTON", "Start ReadWatch at sign-in (runs in the tray)", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 0, s.hwnd, idStartAtLogin)
	s.openLogin = createControl("BUTTON", "…and open the window too", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 0, s.hwnd, idOpenAtLogin)
	// A window preference rather than a watch setting: it is stored per user and
	// applied by the viewer, so it is the one control here the service knows
	// nothing about.
	s.alwaysTop = createControl("BUTTON", "Keep the ReadWatch window on top of other windows", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 0, s.hwnd, idAlwaysOnTop)
	s.saveBtn = createControl("BUTTON", "Save", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON, 0, s.hwnd, IDOK)
	s.cancelBtn = createControl("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, IDCANCEL)

	for _, h := range s.controls() {
		sendMessage(h, WM_SETFONT, uintptr(s.font), 1)
	}
	for _, text := range []string{"Plain text (.log)", "JSON Lines (.jsonl)", "CSV (.csv)"} {
		sendMessage(s.formatCombo, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16Ptr(text))))
	}
	formatIndex := 0
	if s.cfg.LogFormat == "jsonl" {
		formatIndex = 1
	} else if s.cfg.LogFormat == "csv" {
		formatIndex = 2
	}
	sendMessage(s.formatCombo, CB_SETCURSEL, uintptr(formatIndex), 0)
	setChecked(s.includeDirs, s.cfg.IncludeDirectories)
	setChecked(s.startLogin, s.cfg.StartAtLogin)
	setChecked(s.openLogin, s.cfg.OpenAtLogin)
	setChecked(s.alwaysTop, s.app.alwaysOnTop)
	for _, folder := range s.cfg.Folders {
		sendMessage(s.folderList, LB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16Ptr(folder))))
	}
	if len(s.cfg.Folders) > 0 {
		sendMessage(s.folderList, LB_SETCURSEL, 0, 0)
	}
	for _, entry := range s.cfg.ExcludedProcesses {
		sendMessage(s.excludeList, LB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16Ptr(entry))))
	}
	if len(s.cfg.ExcludedProcesses) > 0 {
		sendMessage(s.excludeList, LB_SETCURSEL, 0, 0)
	}
	s.updateOpenAtLoginEnabled()
}

func (s *SettingsUI) controls() []HWND {
	return []HWND{
		s.foldersLabel, s.folderList, s.addBtn, s.removeBtn, s.folderPath, s.addPathBtn,
		s.excludeLabel, s.excludeList, s.excludeText, s.excludeAddBtn, s.excludeRemoveBtn,
		s.logLabel, s.logPath, s.browseBtn, s.formatLabel, s.formatCombo,
		s.includeDirs, s.startLogin, s.openLogin, s.alwaysTop, s.saveBtn, s.cancelBtn,
	}
}

func (s *SettingsUI) layout() {
	if s.hwnd == 0 {
		return
	}
	var rc RECT
	procGetClientRect.Call(uintptr(s.hwnd), uintptr(unsafe.Pointer(&rc)))
	w := rc.Right - rc.Left
	h := rc.Bottom - rc.Top
	m := s.scale(12)
	gap := s.scale(8)
	buttonW := s.scale(76)
	buttonH := s.scale(25)
	labelH := s.scale(20)
	fieldH := s.scale(24)

	// A running cursor rather than fixed offsets: the window gained two sections
	// and hand-maintained magic numbers had already made it fragile.
	fieldW := w - m*3 - buttonW
	rightX := w - m - buttonW
	y := s.scale(8)
	place := func(h HWND, x, top, cw, ch int32) {
		procMoveWindow.Call(uintptr(h), uintptr(x), uintptr(top), uintptr(cw), uintptr(ch), 1)
	}

	place(s.foldersLabel, m, y, fieldW, labelH)
	place(s.addBtn, rightX, y-s.scale(1), buttonW, buttonH)
	y += labelH + s.scale(4)
	place(s.folderList, m, y, fieldW, s.scale(74))
	place(s.removeBtn, rightX, y, buttonW, buttonH)
	y += s.scale(74) + s.scale(6)
	place(s.folderPath, m, y, fieldW, fieldH)
	place(s.addPathBtn, rightX, y, buttonW, buttonH)
	y += fieldH + s.scale(14)

	place(s.excludeLabel, m, y, w-2*m, labelH)
	y += labelH + s.scale(4)
	place(s.excludeList, m, y, fieldW, s.scale(64))
	place(s.excludeRemoveBtn, rightX, y, buttonW, buttonH)
	y += s.scale(64) + s.scale(6)
	place(s.excludeText, m, y, fieldW, fieldH)
	place(s.excludeAddBtn, rightX, y, buttonW, buttonH)
	y += fieldH + s.scale(14)

	place(s.logLabel, m, y, fieldW, labelH)
	place(s.browseBtn, rightX, y-s.scale(1), buttonW, buttonH)
	y += labelH + s.scale(4)
	place(s.logPath, m, y, w-2*m, fieldH)
	y += fieldH + s.scale(12)

	formatLabelW := s.scale(46)
	comboW := s.scale(148)
	place(s.formatLabel, m, y, formatLabelW, fieldH)
	place(s.formatCombo, m+formatLabelW+gap, y, comboW, s.scale(180))
	includeX := m + formatLabelW + gap + comboW + s.scale(15)
	place(s.includeDirs, includeX, y, w-includeX-m, fieldH)
	y += fieldH + s.scale(10)

	place(s.startLogin, m, y, w-2*m, fieldH)
	y += fieldH + s.scale(2)
	place(s.openLogin, m+s.scale(20), y, w-2*m-s.scale(20), fieldH)
	y += fieldH + s.scale(2)
	place(s.alwaysTop, m, y, w-2*m, fieldH)

	bottomY := h - m - buttonH
	procMoveWindow.Call(uintptr(s.cancelBtn), uintptr(w-m-buttonW*2-gap), uintptr(bottomY), uintptr(buttonW), uintptr(buttonH), 1)
	procMoveWindow.Call(uintptr(s.saveBtn), uintptr(w-m-buttonW), uintptr(bottomY), uintptr(buttonW), uintptr(buttonH), 1)
}

func (s *SettingsUI) applyTheme() {
	if s.app.theme.brush == 0 {
		s.app.applyTheme(true)
	}
	dark := s.app.theme.dark
	value := int32(0)
	if dark {
		value = 1
	}
	procDwmSetWindowAttribute.Call(uintptr(s.hwnd), DWMWA_USE_IMMERSIVE_DARK_MODE, uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value))
	corner := uint32(DWMWCP_ROUND)
	procDwmSetWindowAttribute.Call(uintptr(s.hwnd), DWMWA_WINDOW_CORNER_PREFERENCE, uintptr(unsafe.Pointer(&corner)), unsafe.Sizeof(corner))
	themeName := "Explorer"
	if dark {
		themeName = "DarkMode_Explorer"
	}
	for _, h := range []HWND{s.folderList, s.folderPath, s.addPathBtn, s.excludeList, s.excludeText, s.excludeAddBtn, s.excludeRemoveBtn, s.logPath, s.formatCombo, s.addBtn, s.removeBtn, s.browseBtn, s.includeDirs, s.startLogin, s.openLogin, s.alwaysTop, s.saveBtn, s.cancelBtn} {
		procSetWindowTheme.Call(uintptr(h), uintptr(unsafe.Pointer(utf16Ptr(themeName))), 0)
	}
	procInvalidateRect.Call(uintptr(s.hwnd), 0, 1)
	procInvalidateRect.Call(uintptr(s.folderList), 0, 1)
}

func (s *SettingsUI) updateOpenAtLoginEnabled() {
	enabled := isChecked(s.startLogin)
	procEnableWindow.Call(uintptr(s.openLogin), boolToUintptr(enabled))
	if !enabled {
		setChecked(s.openLogin, false)
	}
}

func setChecked(hwnd HWND, checked bool) {
	state := uintptr(BST_UNCHECKED)
	if checked {
		state = BST_CHECKED
	}
	sendMessage(hwnd, BM_SETCHECK, state, 0)
}

func isChecked(hwnd HWND) bool {
	return sendMessage(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED
}

func (s *SettingsUI) addFolder() {
	folder, ok, err := pickFolder(s.hwnd)
	if err != nil {
		messageBox(s.hwnd, err.Error(), appName, MB_OK|MB_ICONERROR)
		return
	}
	if !ok || folder == "" {
		return
	}
	count := int(sendMessage(s.folderList, LB_GETCOUNT, 0, 0))
	for i := 0; i < count; i++ {
		if existing, ok := listBoxText(s.folderList, i); ok && strings.EqualFold(existing, folder) {
			sendMessage(s.folderList, LB_SETCURSEL, uintptr(i), 0)
			return
		}
	}
	idx := int(sendMessage(s.folderList, LB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16Ptr(folder)))))
	if idx >= 0 {
		sendMessage(s.folderList, LB_SETCURSEL, uintptr(idx), 0)
	}
}

// addToList appends a trimmed, case-insensitively unique entry and clears the
// source field. Shared by the folder path box and the exclusion box.
func addToList(list HWND, source HWND, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	count := int(sendMessage(list, LB_GETCOUNT, 0, 0))
	for i := 0; i < count; i++ {
		if existing, ok := listBoxText(list, i); ok && strings.EqualFold(strings.TrimSpace(existing), value) {
			sendMessage(list, LB_SETCURSEL, uintptr(i), 0)
			if source != 0 {
				setWindowText(source, "")
			}
			return
		}
	}
	if idx := int(sendMessage(list, LB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16Ptr(value))))); idx >= 0 {
		sendMessage(list, LB_SETCURSEL, uintptr(idx), 0)
	}
	if source != 0 {
		setWindowText(source, "")
	}
}

func removeSelected(list HWND) {
	idx := int(int32(sendMessage(list, LB_GETCURSEL, 0, 0)))
	if idx == LB_ERR {
		return
	}
	sendMessage(list, LB_DELETESTRING, uintptr(idx), 0)
	count := int(sendMessage(list, LB_GETCOUNT, 0, 0))
	if count > 0 {
		if idx >= count {
			idx = count - 1
		}
		sendMessage(list, LB_SETCURSEL, uintptr(idx), 0)
	}
}

// addTypedFolder takes whatever was pasted or typed and validates it before it
// reaches the list, so a typo surfaces here rather than as a silent no-match
// once monitoring starts.
func (s *SettingsUI) addTypedFolder() {
	raw := strings.TrimSpace(windowText(s.folderPath))
	if raw == "" {
		return
	}
	// Explorer's "Copy as path" wraps the path in quotes, which is a very likely
	// way for one to arrive here.
	raw = strings.Trim(raw, `"`)
	full, err := filepath.Abs(raw)
	if err != nil || full == "" {
		messageBox(s.hwnd, "That does not look like a usable folder path:\r\n\r\n"+raw, appName, MB_OK|MB_ICONWARNING)
		return
	}
	if fi, statErr := os.Stat(full); statErr != nil || !fi.IsDir() {
		messageBox(s.hwnd, "That folder does not exist:\r\n\r\n"+full, appName, MB_OK|MB_ICONWARNING)
		return
	}
	addToList(s.folderList, s.folderPath, full)
}

func (s *SettingsUI) removeFolder() {
	idx := int(int32(sendMessage(s.folderList, LB_GETCURSEL, 0, 0)))
	if idx == LB_ERR {
		return
	}
	sendMessage(s.folderList, LB_DELETESTRING, uintptr(idx), 0)
	count := int(sendMessage(s.folderList, LB_GETCOUNT, 0, 0))
	if count > 0 {
		if idx >= count {
			idx = count - 1
		}
		sendMessage(s.folderList, LB_SETCURSEL, uintptr(idx), 0)
	}
}

func listBoxText(list HWND, index int) (string, bool) {
	length := int(int32(sendMessage(list, LB_GETTEXTLEN, uintptr(index), 0)))
	if length < 0 {
		return "", false
	}
	buf := make([]uint16, length+1)
	result := int(int32(sendMessage(list, LB_GETTEXT, uintptr(index), uintptr(unsafe.Pointer(&buf[0])))))
	if result < 0 {
		return "", false
	}
	return syscall.UTF16ToString(buf), true
}

func (s *SettingsUI) selectedFormat() string {
	index := int(int32(sendMessage(s.formatCombo, CB_GETCURSEL, 0, 0)))
	switch index {
	case 1:
		return "jsonl"
	case 2:
		return "csv"
	default:
		return "text"
	}
}

func (s *SettingsUI) browseLog() {
	path, ok, err := pickLogFile(s.hwnd, windowText(s.logPath), s.selectedFormat())
	if err != nil {
		messageBox(s.hwnd, err.Error(), appName, MB_OK|MB_ICONERROR)
		return
	}
	if ok {
		setWindowText(s.logPath, path)
	}
}

func (s *SettingsUI) collect() (settings.PublicConfig, error) {
	cfg := s.cfg
	cfg.Folders = cfg.Folders[:0]
	count := int(sendMessage(s.folderList, LB_GETCOUNT, 0, 0))
	for i := 0; i < count; i++ {
		folder, ok := listBoxText(s.folderList, i)
		if ok && strings.TrimSpace(folder) != "" {
			cfg.Folders = append(cfg.Folders, folder)
		}
	}
	cfg.ExcludedProcesses = cfg.ExcludedProcesses[:0]
	exCount := int(sendMessage(s.excludeList, LB_GETCOUNT, 0, 0))
	for i := 0; i < exCount; i++ {
		if entry, ok := listBoxText(s.excludeList, i); ok && strings.TrimSpace(entry) != "" {
			cfg.ExcludedProcesses = append(cfg.ExcludedProcesses, entry)
		}
	}
	cfg.LogPath = strings.TrimSpace(windowText(s.logPath))
	if cfg.LogPath == "" {
		return cfg, fmt.Errorf("choose a log file")
	}
	cfg.LogFormat = s.selectedFormat()
	cfg.IncludeDirectories = isChecked(s.includeDirs)
	cfg.StartAtLogin = isChecked(s.startLogin)
	cfg.OpenAtLogin = cfg.StartAtLogin && isChecked(s.openLogin)
	if cfg.MaxRows < 200 || cfg.MaxRows > 5000 {
		cfg.MaxRows = 1000
	}
	return cfg, nil
}

func (s *SettingsUI) save() {
	// A path pasted into the box but never Added used to be dropped without a
	// word - Save collects the list, and the box is not in it. Commit both
	// pending edits first. addTypedFolder clears the box when it accepts the
	// path, so text still sitting there means it was rejected and said why;
	// saving over that would discard the folder the user came here to add.
	if strings.TrimSpace(windowText(s.folderPath)) != "" {
		s.addTypedFolder()
		if strings.TrimSpace(windowText(s.folderPath)) != "" {
			return
		}
	}
	addToList(s.excludeList, s.excludeText, windowText(s.excludeText))
	cfg, err := s.collect()
	if err != nil {
		messageBox(s.hwnd, err.Error(), appName, MB_OK|MB_ICONWARNING)
		return
	}
	if !s.app.applySettings(cfg) {
		// Refusing silently is what a dead button looks like.
		messageBox(s.hwnd, "ReadWatch is still applying an earlier change.\r\n\r\nTry Save again in a moment.", appName, MB_OK|MB_ICONINFORMATION)
		return
	}
	s.app.setAlwaysOnTop(isChecked(s.alwaysTop))
	s.close()
}

func (s *SettingsUI) close() {
	if s.hwnd != 0 && s.closing.CompareAndSwap(false, true) {
		procDestroyWindow.Call(uintptr(s.hwnd))
	}
}

func (s *SettingsUI) dpiChanged(newDPI uint32, suggested *RECT) {
	if newDPI == 0 {
		return
	}
	s.dpi = newDPI
	if suggested != nil {
		procSetWindowPos.Call(uintptr(s.hwnd), 0, uintptr(int64(suggested.Left)), uintptr(int64(suggested.Top)), uintptr(suggested.Right-suggested.Left), uintptr(suggested.Bottom-suggested.Top), SWP_NOZORDER|SWP_NOACTIVATE)
	}
	oldFont := s.font
	s.font = createUIFont(s.dpi)
	for _, h := range s.controls() {
		sendMessage(h, WM_SETFONT, uintptr(s.font), 1)
	}
	if oldFont != 0 {
		deleteObject(uintptr(oldFont))
	}
	s.layout()
}

func (u *AppUI) applySettings(cfg settings.PublicConfig) bool {
	if !u.beginCommand(protocol.CmdApply) {
		return false
	}
	oldStart := u.state.Config.StartAtLogin
	oldOpen := u.state.Config.OpenAtLogin
	go func() {
		defer u.endCommand()
		u.clientMu.RLock()
		client := u.client
		u.clientMu.RUnlock()
		if client == nil {
			u.queueError(fmt.Errorf("ReadWatch service is not connected"))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := client.Command(ctx, protocol.CmdApply, &cfg)
		cancel()
		if err == nil {
			err = setStartup(cfg.StartAtLogin)
			if err != nil {
				rollback := cfg
				rollback.StartAtLogin = oldStart
				rollback.OpenAtLogin = oldOpen
				rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 8*time.Second)
				_ = client.Command(rollbackCtx, protocol.CmdApply, &rollback)
				rollbackCancel()
				err = fmt.Errorf("save startup setting: %w", err)
			}
		}
		if err != nil {
			u.queueError(err)
		}
	}()
	return true
}

func settingsWindowProc(hwnd uintptr, msg uint32, wParam uintptr, lParam unsafe.Pointer) uintptr {
	s := settingsUI
	if s == nil {
		r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, uintptr(lParam))
		return r
	}
	switch msg {
	case WM_ERASEBKGND:
		if s.app.theme.brush != 0 {
			var rc RECT
			procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
			procFillRect.Call(wParam, uintptr(unsafe.Pointer(&rc)), uintptr(s.app.theme.brush))
			return 1
		}
	case WM_CTLCOLORSTATIC, WM_CTLCOLORBTN, WM_CTLCOLOREDIT, WM_CTLCOLORLISTBOX:
		if s.app.theme.brush != 0 {
			procSetTextColor.Call(wParam, uintptr(s.app.theme.text))
			procSetBkColor.Call(wParam, uintptr(s.app.theme.bg))
			procSetBkMode.Call(wParam, TRANSPARENT)
			return uintptr(s.app.theme.brush)
		}
	case WM_COMMAND:
		id := int(loword(wParam))
		code := hiword(wParam)
		if code == BN_CLICKED {
			switch id {
			case idAddFolder:
				s.addFolder()
			case idRemoveFolder:
				s.removeFolder()
			case idAddFolderPath:
				s.addTypedFolder()
			case idAddExclude:
				addToList(s.excludeList, s.excludeText, windowText(s.excludeText))
			case idRemoveExclude:
				removeSelected(s.excludeList)
			case idBrowseLog:
				s.browseLog()
			case idStartAtLogin:
				s.updateOpenAtLoginEnabled()
			case IDOK:
				s.save()
			case IDCANCEL:
				s.close()
			}
		}
		return 0
	case WM_SETTINGCHANGE, WM_THEMECHANGED:
		s.app.applyTheme(false)
		s.applyTheme()
		return 0
	case WM_DPICHANGED:
		newDPI := uint32(loword(wParam))
		s.dpiChanged(newDPI, (*RECT)(lParam))
		return 0
	case WM_CLOSE:
		s.close()
		return 0
	case WM_DESTROY:
		s.detachHints()
		if s.font != 0 {
			deleteObject(uintptr(s.font))
			s.font = 0
		}
		owner := s.app.hwnd
		s.hwnd = 0
		settingsUI = nil
		procEnableWindow.Call(uintptr(owner), 1)
		procSetForegroundWindow.Call(uintptr(owner))
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, uintptr(lParam))
	return r
}
