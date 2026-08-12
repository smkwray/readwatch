//go:build windows

package main

import (
	"context"
	"fmt"
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
	logLabel     HWND
	logPath      HWND
	browseBtn    HWND
	formatLabel  HWND
	formatCombo  HWND
	includeDirs  HWND
	startLogin   HWND
	openLogin    HWND
	saveBtn      HWND
	cancelBtn    HWND

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
	cfg := u.state.Config
	cfg.Folders = append([]string(nil), cfg.Folders...)
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
	height := s.scale(360)
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
	s.addBtn = createControl("BUTTON", "Add…", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, idAddFolder)
	s.removeBtn = createControl("BUTTON", "Remove", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, idRemoveFolder)
	s.logLabel = createControl("STATIC", "Log file", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE, 0, s.hwnd, 0)
	s.logPath = createControl("EDIT", s.cfg.LogPath, WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_AUTOHSCROLL, 0, s.hwnd, idLogPath)
	s.browseBtn = createControl("BUTTON", "Browse…", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, s.hwnd, idBrowseLog)
	s.formatLabel = createControl("STATIC", "Format", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE, 0, s.hwnd, 0)
	s.formatCombo = createControl("COMBOBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_VSCROLL|CBS_DROPDOWNLIST, 0, s.hwnd, idLogFormat)
	s.includeDirs = createControl("BUTTON", "Include folder-listing events", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 0, s.hwnd, idIncludeFolders)
	s.startLogin = createControl("BUTTON", "Show tray icon at sign-in", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 0, s.hwnd, idStartAtLogin)
	s.openLogin = createControl("BUTTON", "Open window at sign-in", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, 0, s.hwnd, idOpenAtLogin)
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
	for _, folder := range s.cfg.Folders {
		sendMessage(s.folderList, LB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16Ptr(folder))))
	}
	if len(s.cfg.Folders) > 0 {
		sendMessage(s.folderList, LB_SETCURSEL, 0, 0)
	}
	s.updateOpenAtLoginEnabled()
}

func (s *SettingsUI) controls() []HWND {
	return []HWND{
		s.foldersLabel, s.folderList, s.addBtn, s.removeBtn,
		s.logLabel, s.logPath, s.browseBtn, s.formatLabel, s.formatCombo,
		s.includeDirs, s.startLogin, s.openLogin, s.saveBtn, s.cancelBtn,
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

	procMoveWindow.Call(uintptr(s.foldersLabel), uintptr(m), uintptr(s.scale(8)), uintptr(w-m*3-buttonW), uintptr(labelH), 1)
	procMoveWindow.Call(uintptr(s.addBtn), uintptr(w-m-buttonW), uintptr(s.scale(7)), uintptr(buttonW), uintptr(buttonH), 1)
	listTop := s.scale(35)
	listH := s.scale(82)
	procMoveWindow.Call(uintptr(s.folderList), uintptr(m), uintptr(listTop), uintptr(w-m*3-buttonW), uintptr(listH), 1)
	procMoveWindow.Call(uintptr(s.removeBtn), uintptr(w-m-buttonW), uintptr(listTop), uintptr(buttonW), uintptr(buttonH), 1)

	logLabelY := s.scale(127)
	procMoveWindow.Call(uintptr(s.logLabel), uintptr(m), uintptr(logLabelY), uintptr(w-m*3-buttonW), uintptr(labelH), 1)
	procMoveWindow.Call(uintptr(s.browseBtn), uintptr(w-m-buttonW), uintptr(logLabelY-s.scale(1)), uintptr(buttonW), uintptr(buttonH), 1)
	logY := s.scale(151)
	procMoveWindow.Call(uintptr(s.logPath), uintptr(m), uintptr(logY), uintptr(w-2*m), uintptr(fieldH), 1)

	formatY := s.scale(187)
	formatLabelW := s.scale(46)
	comboW := s.scale(148)
	procMoveWindow.Call(uintptr(s.formatLabel), uintptr(m), uintptr(formatY), uintptr(formatLabelW), uintptr(fieldH), 1)
	procMoveWindow.Call(uintptr(s.formatCombo), uintptr(m+formatLabelW+gap), uintptr(formatY), uintptr(comboW), uintptr(s.scale(180)), 1)
	includeX := m + formatLabelW + gap + comboW + s.scale(15)
	procMoveWindow.Call(uintptr(s.includeDirs), uintptr(includeX), uintptr(formatY), uintptr(w-includeX-m), uintptr(fieldH), 1)

	procMoveWindow.Call(uintptr(s.startLogin), uintptr(m), uintptr(s.scale(222)), uintptr(w-2*m), uintptr(fieldH), 1)
	procMoveWindow.Call(uintptr(s.openLogin), uintptr(m+s.scale(20)), uintptr(s.scale(248)), uintptr(w-2*m-s.scale(20)), uintptr(fieldH), 1)

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
	for _, h := range []HWND{s.folderList, s.logPath, s.formatCombo, s.addBtn, s.removeBtn, s.browseBtn, s.includeDirs, s.startLogin, s.openLogin, s.saveBtn, s.cancelBtn} {
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
	cfg, err := s.collect()
	if err != nil {
		messageBox(s.hwnd, err.Error(), appName, MB_OK|MB_ICONWARNING)
		return
	}
	if !s.app.applySettings(cfg) {
		return
	}
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
	if !u.commandBusy.CompareAndSwap(false, true) {
		return false
	}
	procEnableWindow.Call(uintptr(u.startBtn), 0)
	procEnableWindow.Call(uintptr(u.settingsBtn), 0)
	oldStart := u.state.Config.StartAtLogin
	oldOpen := u.state.Config.OpenAtLogin
	go func() {
		defer u.commandBusy.Store(false)
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
