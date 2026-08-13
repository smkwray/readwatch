//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"readwatch/internal/model"
	"readwatch/internal/protocol"
	"readwatch/internal/settings"
)

const (
	wmAppEvents   = WM_APP + 1
	wmAppState    = WM_APP + 2
	wmAppError    = WM_APP + 3
	wmAppActivate = WM_APP + 4
	wmAppTray     = WM_APP + 5
	wmAppExit     = WM_APP + 6
	wmAppStatus   = WM_APP + 7

	idStart    = 101
	idSettings = 102
	idOpenLog  = 103
	idClear    = 104
	idExit     = 105

	rowExcludeName = 301
	rowExcludePath = 302

	trayShow     = 201
	trayToggle   = 202
	trayOpenLog  = 203
	traySettings = 204
	trayExit     = 205

	trayIconID = 1
)

var (
	mainWindowClass     = "ReadWatch.MainWindow"
	mainWndProcPtr      = syscall.NewCallback(mainWindowProc)
	listSubclassProcPtr = syscall.NewCallback(listSubclassProc)
	mainUI              *AppUI
)

// listSubclassProc catches the header's NM_CUSTOMDRAW, which the list view
// receives as the header's parent and never forwards, and the pointer messages
// that drive the hover hint over clipped cells.
func listSubclassProc(hwnd uintptr, msg uint32, wParam uintptr, lParam unsafe.Pointer) uintptr {
	u := mainUI
	if u != nil && msg == WM_NOTIFY && u.header != 0 {
		hdr := (*NMHDR)(lParam)
		if hdr.HwndFrom == u.header && hdr.Code == NM_CUSTOMDRAW {
			return u.drawHeader((*NMCUSTOMDRAW)(lParam))
		}
	}
	if u != nil {
		switch msg {
		case WM_MOUSEMOVE:
			u.hintMouseMove(mouseX(lParam), mouseY(lParam))
		case WM_MOUSEHOVER:
			u.hintShow(mouseX(lParam), mouseY(lParam))
		case WM_MOUSELEAVE, WM_MOUSEWHEEL, WM_LBUTTONDOWN, WM_RBUTTONDOWN:
			u.hintClear()
		}
	}
	if u != nil && u.origListProc != 0 {
		r, _, _ := procCallWindowProcW.Call(u.origListProc, hwnd, uintptr(msg), wParam, uintptr(lParam))
		return r
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, uintptr(lParam))
	return r
}

type eventRing struct {
	buf   []model.Event
	start int
	count int
}

func newEventRing(capacity int) *eventRing {
	if capacity < 1 {
		capacity = 1000
	}
	return &eventRing{buf: make([]model.Event, capacity)}
}

func (r *eventRing) Cap() int { return len(r.buf) }
func (r *eventRing) Len() int { return r.count }

func (r *eventRing) Add(e model.Event) {
	if len(r.buf) == 0 {
		return
	}
	if r.count < len(r.buf) {
		idx := (r.start + r.count) % len(r.buf)
		r.buf[idx] = e
		r.count++
		return
	}
	r.buf[r.start] = e
	r.start = (r.start + 1) % len(r.buf)
}

func (r *eventRing) Newest(index int) (model.Event, bool) {
	if index < 0 || index >= r.count || len(r.buf) == 0 {
		return model.Event{}, false
	}
	idx := (r.start + r.count - 1 - index) % len(r.buf)
	if idx < 0 {
		idx += len(r.buf)
	}
	return r.buf[idx], true
}

func (r *eventRing) Clear() {
	for i := range r.buf {
		r.buf[i] = model.Event{}
	}
	r.start = 0
	r.count = 0
}

func (r *eventRing) Resize(capacity int) {
	if capacity < 1 || capacity == len(r.buf) {
		return
	}
	n := r.count
	if n > capacity {
		n = capacity
	}
	newBuf := make([]model.Event, capacity)
	for i := n - 1; i >= 0; i-- {
		e, _ := r.Newest(i)
		newBuf[n-1-i] = e
	}
	r.buf = newBuf
	r.start = 0
	r.count = n
}

type uiTheme struct {
	dark       bool
	bg         uint32
	surface    uint32
	text       uint32
	muted      uint32
	listBg     uint32
	headerBg   uint32
	headerText uint32
	line       uint32
	brush      HBRUSH
}

type AppUI struct {
	hwnd         HWND
	list         HWND
	header       HWND
	origListProc uintptr
	columns      []string
	status       HWND
	startBtn     HWND
	settingsBtn  HWND
	summary      HWND
	openBtn      HWND
	clearBtn     HWND
	exitBtn      HWND
	font         HFONT
	icon         HICON
	iconSmall    HICON
	theme        uiTheme
	dpi          uint32
	hint         *hintTip
	hover        hintHover

	ownerSID string
	startup  bool

	clientMu sync.RWMutex
	client   *IPCClient

	stateMu      sync.Mutex
	pendingState *protocol.State
	statePosted  atomic.Bool
	state        protocol.State

	eventMu      sync.Mutex
	pendingEvent []model.Event
	eventPosted  atomic.Bool
	ring         *eventRing
	totalEvents  uint64
	liveDropped  atomic.Uint64
	lastDispText []uint16
	// The service's counters run from when monitoring started; these baselines
	// are what Clear resets them to, so the summary always describes the rows
	// that are actually on screen.
	baseSuppressed  uint64
	baseLogDropped  uint64
	baseLiveDropped uint64

	errMu        sync.Mutex
	pendingError string
	errPosted    atomic.Bool

	activation        HANDLE
	exitEvent         HANDLE
	mutex             HANDLE
	trayAdded         bool
	taskbarCreatedMsg uint32
	exiting           atomic.Bool
	commandBusy       atomic.Bool
	// pending is the command in flight, and only the UI thread touches it: the
	// status line says what is happening while it runs.
	pending          string
	alwaysOnTop      bool
	startupDecided   bool
	firstRunPrompted bool
}

func RunUI(startup bool) error {
	ownerSID, err := currentUserSID()
	if err != nil {
		return err
	}
	mutex, exists, err := acquireInstanceMutex(ownerSID)
	if err != nil {
		return err
	}
	if exists {
		closeHandle(mutex)
		signalActivation(ownerSID)
		return nil
	}

	procSetProcessDpiAwarenessContext.Call(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
	// ICC_BAR_CLASSES registers the tooltip class the hover hints need.
	icc := INITCOMMONCONTROLSEX{DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})), DwICC: ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))

	u := &AppUI{ownerSID: ownerSID, startup: startup, mutex: mutex, ring: newEventRing(1000)}
	mainUI = u
	if err := u.createWindow(); err != nil {
		closeHandle(mutex)
		return err
	}
	defer func() { mainUI = nil }()

	activation, err := createActivationEvent(ownerSID)
	if err == nil {
		u.activation = activation
		go u.activationLoop()
	}
	exitEvent, err := createExitEvent(ownerSID)
	if err == nil {
		u.exitEvent = exitEvent
		go u.exitLoop()
	}
	u.addTrayIcon()
	u.startConnectionLoop()

	if !startup {
		procShowWindow.Call(uintptr(u.hwnd), SW_SHOW)
		procUpdateWindow.Call(uintptr(u.hwnd))
	}

	var msg MSG
	for {
		r, _, e := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) == -1 {
			return winErr("GetMessage", e)
		}
		if r == 0 {
			break
		}
		if settingsUI != nil && settingsUI.hwnd != 0 {
			handled, _, _ := procIsDialogMessageW.Call(uintptr(settingsUI.hwnd), uintptr(unsafe.Pointer(&msg)))
			if handled != 0 {
				continue
			}
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
	return nil
}

func (u *AppUI) createWindow() error {
	instance, _, _ := procGetModuleHandleW.Call(0)
	u.icon = loadIconFile(paths().Icon, 32, 32)
	u.iconSmall = loadIconFile(paths().Icon, 16, 16)
	if u.icon == 0 {
		r, _, _ := procLoadIconW.Call(0, IDI_APPLICATION)
		u.icon = HICON(r)
	}
	if u.iconSmall == 0 {
		u.iconSmall = u.icon
	}
	cursor, _, _ := procLoadCursorW.Call(0, IDC_ARROW)
	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS,
		LpfnWndProc:   mainWndProcPtr,
		HInstance:     HINSTANCE(instance),
		HIcon:         u.icon,
		HCursor:       HCURSOR(cursor),
		LpszClassName: utf16Ptr(mainWindowClass),
		HIconSm:       u.iconSmall,
	}
	atom, _, e := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		if errno, ok := e.(syscall.Errno); !ok || errno != ERROR_CLASS_ALREADY_EXISTS {
			return winErr("RegisterClassEx", e)
		}
	}
	style := uintptr(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_CLIPCHILDREN)
	initialDPI := uint32(96)
	if dpi, _, _ := procGetDpiForSystem.Call(); dpi != 0 {
		initialDPI = uint32(dpi)
	}
	initialW := uintptr(int64(560) * int64(initialDPI) / 96)
	initialH := uintptr(int64(320) * int64(initialDPI) / 96)
	hwnd, _, e := procCreateWindowExW.Call(
		WS_EX_APPWINDOW,
		uintptr(unsafe.Pointer(utf16Ptr(mainWindowClass))),
		uintptr(unsafe.Pointer(utf16Ptr(appName))),
		style,
		uintptr(0x80000000), uintptr(0x80000000), initialW, initialH,
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return winErr("CreateWindowEx", e)
	}
	u.hwnd = HWND(hwnd)
	if registered, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(utf16Ptr("TaskbarCreated")))); registered != 0 {
		u.taskbarCreatedMsg = uint32(registered)
	}
	dpi, _, _ := procGetDpiForWindow.Call(hwnd)
	if dpi == 0 {
		dpi = 96
	}
	u.dpi = uint32(dpi)
	u.createControls()
	u.applyTheme(true)
	u.layout()
	u.alwaysOnTop = alwaysOnTopPreference()
	u.applyAlwaysOnTop()
	return nil
}

// setAlwaysOnTop is a viewer preference, not part of the watched configuration:
// it needs no elevation and no running service, so it is applied here and kept
// in the user's own registry hive rather than sent to the service.
func (u *AppUI) setAlwaysOnTop(on bool) {
	if u.alwaysOnTop == on {
		return
	}
	u.alwaysOnTop = on
	u.applyAlwaysOnTop()
	if err := setAlwaysOnTopPreference(on); err != nil {
		u.queueError(err)
	}
}

func (u *AppUI) applyAlwaysOnTop() {
	after := HWND_NOTOPMOST
	if u.alwaysOnTop {
		after = HWND_TOPMOST
	}
	procSetWindowPos.Call(uintptr(u.hwnd), after, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE)
}

func (u *AppUI) createControls() {
	u.font = createUIFont(u.dpi)
	u.status = createControl("STATIC", "Service connecting…", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE, 0, u.hwnd, 0)
	u.startBtn = createControl("BUTTON", "Start", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, u.hwnd, idStart)
	u.settingsBtn = createControl("BUTTON", "Settings", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, u.hwnd, idSettings)
	u.list = createControl("SysListView32", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS|LVS_OWNERDATA|LVS_NOSORTHEADER, WS_EX_CLIENTEDGE, u.hwnd, 0)
	// No LVS_EX_LABELTIP: it unfolds the first column only, and the hover hint
	// below covers every column including Path, which is the one that clips.
	sendMessage(u.list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	for i, c := range []struct {
		name string
		w    int32
	}{{"Time", 88}, {"Process", 126}, {"PID", 54}, {"Path", 280}} {
		text := syscall.StringToUTF16(c.name)
		col := LVCOLUMNW{Mask: LVCF_TEXT | LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM, Fmt: LVCFMT_LEFT, Cx: u.scale(c.w), PszText: &text[0], ISubItem: int32(i)}
		sendMessage(u.list, LVM_INSERTCOLUMNW, uintptr(i), uintptr(unsafe.Pointer(&col)))
		runtime.KeepAlive(text)
		u.columns = append(u.columns, c.name)
	}
	// The header is its own control. Custom-drawing it needs the titles, and
	// keeping them here avoids an HDITEMW round trip on every paint.
	u.header = HWND(sendMessage(u.list, LVM_GETHEADER, 0, 0))
	// The header's parent is the list view, not this window, so its
	// NM_CUSTOMDRAW never reaches mainWindowProc. Subclass the list to intercept
	// it - without this the header keeps the theme's own (dark-on-dark) text.
	if prev, _, _ := procSetWindowLongPtrW.Call(uintptr(u.list), GWLP_WNDPROC, listSubclassProcPtr); prev != 0 {
		u.origListProc = prev
	}
	u.hover.reset()
	u.hint = newHintTip(u.hwnd, u.scale(560))
	u.hint.attach(u.hwnd, u.list)
	u.summary = createControl("STATIC", "0 folders · 0 events", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_CENTERIMAGE, 0, u.hwnd, 0)
	u.openBtn = createControl("BUTTON", "Open log", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, u.hwnd, idOpenLog)
	u.clearBtn = createControl("BUTTON", "Clear", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, u.hwnd, idClear)
	// Closing the window only hides it to the tray, so without this the only way
	// out of the app is the tray menu.
	u.exitBtn = createControl("BUTTON", "Exit", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, u.hwnd, idExit)
	for _, h := range []HWND{u.status, u.startBtn, u.settingsBtn, u.list, u.summary, u.openBtn, u.clearBtn, u.exitBtn} {
		sendMessage(h, WM_SETFONT, uintptr(u.font), 1)
	}
}

func createControl(class, text string, style uintptr, ex uintptr, parent HWND, id int) HWND {
	instance, _, _ := procGetModuleHandleW.Call(0)
	h, _, _ := procCreateWindowExW.Call(
		ex,
		uintptr(unsafe.Pointer(utf16Ptr(class))),
		uintptr(unsafe.Pointer(utf16Ptr(text))),
		style,
		0, 0, 10, 10,
		uintptr(parent), uintptr(id), instance, 0,
	)
	return HWND(h)
}

func createUIFont(dpi uint32) HFONT {
	height := -int32((9*int(dpi) + 36) / 72)
	r, _, _ := procCreateFontW.Call(
		uintptr(height), 0, 0, 0, 400, 0, 0, 0,
		1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(utf16Ptr("Segoe UI"))),
	)
	return HFONT(r)
}

func loadIconFile(path string, cx, cy int32) HICON {
	if path == "" {
		return 0
	}
	r, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(utf16Ptr(path))), IMAGE_ICON, uintptr(cx), uintptr(cy), LR_LOADFROMFILE)
	return HICON(r)
}

func (u *AppUI) scale(v int32) int32 {
	return int32(int64(v) * int64(u.dpi) / 96)
}

func (u *AppUI) layout() {
	if u.hwnd == 0 {
		return
	}
	var rc RECT
	procGetClientRect.Call(uintptr(u.hwnd), uintptr(unsafe.Pointer(&rc)))
	w := rc.Right - rc.Left
	h := rc.Bottom - rc.Top
	m := u.scale(10)
	topH := u.scale(32)
	bottomH := u.scale(32)
	gap := u.scale(7)
	buttonH := u.scale(25)
	startW := u.scale(64)
	settingsW := u.scale(72)
	openW := u.scale(70)
	clearW := u.scale(54)
	exitW := u.scale(54)
	procMoveWindow.Call(uintptr(u.status), uintptr(m), uintptr(m), uintptr(w-m*3-startW-settingsW-gap), uintptr(buttonH), 1)
	procMoveWindow.Call(uintptr(u.startBtn), uintptr(w-m-settingsW-gap-startW), uintptr(m), uintptr(startW), uintptr(buttonH), 1)
	procMoveWindow.Call(uintptr(u.settingsBtn), uintptr(w-m-settingsW), uintptr(m), uintptr(settingsW), uintptr(buttonH), 1)
	listTop := m + topH
	listH := h - listTop - bottomH - m
	if listH < u.scale(80) {
		listH = u.scale(80)
	}
	procMoveWindow.Call(uintptr(u.list), uintptr(m), uintptr(listTop), uintptr(w-2*m), uintptr(listH), 1)
	bottomY := listTop + listH + u.scale(4)
	rightRow := openW + gap + clearW + gap + exitW
	procMoveWindow.Call(uintptr(u.summary), uintptr(m), uintptr(bottomY), uintptr(w-2*m-rightRow-gap), uintptr(buttonH), 1)
	procMoveWindow.Call(uintptr(u.openBtn), uintptr(w-m-rightRow), uintptr(bottomY), uintptr(openW), uintptr(buttonH), 1)
	procMoveWindow.Call(uintptr(u.clearBtn), uintptr(w-m-clearW-gap-exitW), uintptr(bottomY), uintptr(clearW), uintptr(buttonH), 1)
	procMoveWindow.Call(uintptr(u.exitBtn), uintptr(w-m-exitW), uintptr(bottomY), uintptr(exitW), uintptr(buttonH), 1)

	pathWidth := w - 2*m - u.scale(88+126+54) - u.scale(20)
	if pathWidth < u.scale(120) {
		pathWidth = u.scale(120)
	}
	sendMessage(u.list, LVM_SETCOLUMNWIDTH, 0, uintptr(u.scale(88)))
	sendMessage(u.list, LVM_SETCOLUMNWIDTH, 1, uintptr(u.scale(126)))
	sendMessage(u.list, LVM_SETCOLUMNWIDTH, 2, uintptr(u.scale(54)))
	sendMessage(u.list, LVM_SETCOLUMNWIDTH, 3, uintptr(pathWidth))
}

func (u *AppUI) dpiChanged(newDPI uint32, suggested *RECT) {
	if newDPI == 0 {
		return
	}
	u.dpi = newDPI
	if suggested != nil {
		procSetWindowPos.Call(
			uintptr(u.hwnd), 0,
			uintptr(int64(suggested.Left)), uintptr(int64(suggested.Top)),
			uintptr(suggested.Right-suggested.Left), uintptr(suggested.Bottom-suggested.Top),
			SWP_NOZORDER|SWP_NOACTIVATE,
		)
	}
	oldFont := u.font
	u.font = createUIFont(u.dpi)
	for _, h := range []HWND{u.status, u.startBtn, u.settingsBtn, u.list, u.summary, u.openBtn, u.clearBtn} {
		sendMessage(h, WM_SETFONT, uintptr(u.font), 1)
	}
	if oldFont != 0 {
		deleteObject(uintptr(oldFont))
	}
	u.layout()
}

func (u *AppUI) applyTheme(force bool) {
	dark := systemDarkMode()
	if !force && dark == u.theme.dark {
		return
	}
	if u.theme.brush != 0 {
		deleteObject(uintptr(u.theme.brush))
	}
	if dark {
		// Three steps of depth so the list reads as a recessed panel under its
		// own header, rather than one flat sheet: window 32, header 38, list 25.
		u.theme = uiTheme{
			dark: true,
			bg:   rgb(32, 32, 32), surface: rgb(38, 38, 38),
			text: rgb(240, 240, 240), muted: rgb(154, 154, 154),
			listBg: rgb(25, 25, 25), headerBg: rgb(38, 38, 38),
			headerText: rgb(200, 200, 200), line: rgb(56, 56, 56),
		}
	} else {
		bg, _, _ := procGetSysColor.Call(COLOR_WINDOW)
		text, _, _ := procGetSysColor.Call(COLOR_WINDOWTEXT)
		surface, _, _ := procGetSysColor.Call(COLOR_BTNFACE)
		u.theme = uiTheme{
			dark: false,
			bg:   uint32(bg), surface: uint32(surface), text: uint32(text), muted: uint32(text),
			listBg: uint32(bg), headerBg: uint32(surface), headerText: uint32(text), line: uint32(surface),
		}
	}
	brush, _, _ := procCreateSolidBrush.Call(uintptr(u.theme.bg))
	u.theme.brush = HBRUSH(brush)
	value := int32(0)
	if dark {
		value = 1
	}
	procDwmSetWindowAttribute.Call(uintptr(u.hwnd), DWMWA_USE_IMMERSIVE_DARK_MODE, uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value))
	corner := uint32(DWMWCP_ROUND)
	procDwmSetWindowAttribute.Call(uintptr(u.hwnd), DWMWA_WINDOW_CORNER_PREFERENCE, uintptr(unsafe.Pointer(&corner)), unsafe.Sizeof(corner))
	themeName := "Explorer"
	if dark {
		themeName = "DarkMode_Explorer"
	}
	for _, h := range []HWND{u.list, u.startBtn, u.settingsBtn, u.openBtn, u.clearBtn, u.exitBtn} {
		if h != 0 {
			procSetWindowTheme.Call(uintptr(h), uintptr(unsafe.Pointer(utf16Ptr(themeName))), 0)
		}
	}
	if u.header != 0 {
		headerTheme := "ItemsView"
		if dark {
			headerTheme = "DarkMode_ItemsView"
		}
		procSetWindowTheme.Call(uintptr(u.header), uintptr(unsafe.Pointer(utf16Ptr(headerTheme))), 0)
	}
	sendMessage(u.list, LVM_SETBKCOLOR, 0, uintptr(u.theme.listBg))
	sendMessage(u.list, LVM_SETTEXTBKCOLOR, 0, uintptr(u.theme.listBg))
	sendMessage(u.list, LVM_SETTEXTCOLOR, 0, uintptr(u.theme.text))
	procInvalidateRect.Call(uintptr(u.hwnd), 0, 1)
	procInvalidateRect.Call(uintptr(u.list), 0, 1)
	if u.header != 0 {
		procInvalidateRect.Call(uintptr(u.header), 0, 1)
	}
}

func (u *AppUI) activationLoop() {
	for !u.exiting.Load() {
		r, _, _ := procWaitForSingleObject.Call(uintptr(u.activation), INFINITE)
		if r != WAIT_OBJECT_0 || u.exiting.Load() {
			return
		}
		procResetEvent.Call(uintptr(u.activation))
		postMessage(u.hwnd, wmAppActivate, 0, 0)
	}
}

func (u *AppUI) exitLoop() {
	for !u.exiting.Load() {
		r, _, _ := procWaitForSingleObject.Call(uintptr(u.exitEvent), INFINITE)
		if r != WAIT_OBJECT_0 || u.exiting.Load() {
			return
		}
		procResetEvent.Call(uintptr(u.exitEvent))
		postMessage(u.hwnd, wmAppExit, 0, 0)
		return
	}
}

func (u *AppUI) startConnectionLoop() {
	go func() {
		delay := 250 * time.Millisecond
		for !u.exiting.Load() {
			// The service is demand-start, so at viewer launch there is nothing
			// to connect to. Everything the window displays - configuration,
			// folders, status - arrives over this pipe, so a viewer with no
			// service is inert: it cannot even reach Settings to add a folder.
			// The service's lifetime is therefore the viewer's lifetime; exiting
			// stops it again in shutdown(). Idempotent, so retrying on each
			// reconnect attempt also recovers a service that died.
			if !u.exiting.Load() {
				if err := startInstalledService(); err != nil {
					u.queueError(err)
				}
			}
			client, err := ConnectIPC(u.ownerSID, 2*time.Second, u.queueState, u.queueEvent, func(err error) {
				if err != nil && !u.exiting.Load() {
					u.queueDisconnected()
				}
			})
			if err != nil {
				u.queueDisconnected()
				time.Sleep(delay)
				if u.exiting.Load() {
					return
				}
				if delay < 5*time.Second {
					delay *= 2
				}
				continue
			}
			delay = 250 * time.Millisecond
			u.clientMu.Lock()
			u.client = client
			u.clientMu.Unlock()
			<-client.done
			u.clientMu.Lock()
			if u.client == client {
				u.client = nil
			}
			u.clientMu.Unlock()
			if !u.exiting.Load() {
				u.queueDisconnected()
				time.Sleep(250 * time.Millisecond)
			}
		}
	}()
}

func (u *AppUI) queueDisconnected() {
	u.queueState(protocol.State{ServiceReady: false})
}

func (u *AppUI) queueState(state protocol.State) {
	u.stateMu.Lock()
	u.pendingState = &state
	u.stateMu.Unlock()
	if u.statePosted.CompareAndSwap(false, true) {
		postMessage(u.hwnd, wmAppState, 0, 0)
	}
}

func (u *AppUI) queueEvent(event model.Event) {
	u.eventMu.Lock()
	if len(u.pendingEvent) >= 2048 {
		u.eventMu.Unlock()
		u.liveDropped.Add(1)
		return
	}
	u.pendingEvent = append(u.pendingEvent, event)
	u.eventMu.Unlock()
	if u.eventPosted.CompareAndSwap(false, true) {
		postMessage(u.hwnd, wmAppEvents, 0, 0)
	}
}

func (u *AppUI) queueError(err error) {
	if err == nil {
		return
	}
	u.errMu.Lock()
	u.pendingError = err.Error()
	u.errMu.Unlock()
	if u.errPosted.CompareAndSwap(false, true) {
		postMessage(u.hwnd, wmAppError, 0, 0)
	}
}

func (u *AppUI) drainState() {
	u.stateMu.Lock()
	state := u.pendingState
	u.pendingState = nil
	u.stateMu.Unlock()
	u.statePosted.Store(false)
	if state == nil {
		return
	}
	if !state.ServiceReady && state.Config.LogPath == "" {
		state.Config = u.state.Config
	}
	u.state = *state
	if state.Config.MaxRows > 0 && state.Config.MaxRows != u.ring.Cap() {
		u.ring.Resize(state.Config.MaxRows)
		sendMessage(u.list, LVM_SETITEMCOUNT, uintptr(u.ring.Len()), LVSICF_NOSCROLL)
	}
	u.updateStatus()
	if u.startup && !u.startupDecided && state.ServiceReady {
		u.startupDecided = true
		if state.Config.OpenAtLogin {
			u.show()
		}
	}
	if !u.startup && !u.firstRunPrompted && state.ServiceReady && len(state.Config.Folders) == 0 {
		u.firstRunPrompted = true
		u.openSettings()
	}
	// A state that arrived after the read above but before the flag was cleared
	// has no message of its own, and nothing else would post one: the window
	// would keep showing the previous state until some later update happened to
	// come along. drainEvents has always re-checked; this did not.
	u.stateMu.Lock()
	more := u.pendingState != nil
	u.stateMu.Unlock()
	if more && u.statePosted.CompareAndSwap(false, true) {
		postMessage(u.hwnd, wmAppState, 0, 0)
	}
}

func (u *AppUI) drainEvents() {
	u.eventMu.Lock()
	events := u.pendingEvent
	u.pendingEvent = nil
	u.eventMu.Unlock()
	u.eventPosted.Store(false)
	for _, event := range events {
		u.ring.Add(event)
		u.totalEvents++
	}
	if len(events) > 0 {
		sendMessage(u.list, LVM_SETITEMCOUNT, uintptr(u.ring.Len()), LVSICF_NOSCROLL)
		procInvalidateRect.Call(uintptr(u.list), 0, 0)
		u.updateSummary()
		// Newest first, so every arrival pushes the rows down past a resting
		// pointer and any visible hint now describes a different row.
		u.hintClear()
	}
	u.eventMu.Lock()
	more := len(u.pendingEvent) > 0
	u.eventMu.Unlock()
	if more && u.eventPosted.CompareAndSwap(false, true) {
		postMessage(u.hwnd, wmAppEvents, 0, 0)
	}
}

func (u *AppUI) drainError() {
	u.errMu.Lock()
	text := u.pendingError
	u.pendingError = ""
	u.errMu.Unlock()
	u.errPosted.Store(false)
	if text != "" {
		messageBox(u.hwnd, text, appName, MB_OK|MB_ICONERROR)
	}
}

// cellText is the single source of what a cell says: the list view asks for it
// on paint, the hover hint asks for it to decide whether it was clipped.
func (u *AppUI) cellText(index, column int) string {
	e, ok := u.ring.Newest(index)
	if !ok {
		return ""
	}
	switch column {
	case 0:
		return e.Time.Local().Format("15:04:05.000")
	case 1:
		return e.Process
	case 2:
		return strconv.FormatUint(uint64(e.PID), 10)
	case 3:
		return e.Path
	}
	return ""
}

func (u *AppUI) updateStatus() {
	state := u.state
	pending := u.pendingLabel()
	switch {
	case pending != "":
		setWindowText(u.status, pending)
	case !state.ServiceReady:
		// Not connected is an ordinary state now, not a fault: with a
		// demand-start service the viewer briefly has no peer at launch, and
		// after a failed start this button is the only way back. Disabling it
		// here left the window permanently inert - no Start, no Settings.
		setWindowText(u.status, "○  Connecting…")
		setWindowText(u.startBtn, "Start")
	case state.Running:
		setWindowText(u.status, "●  Monitoring")
		setWindowText(u.startBtn, "Stop")
	default:
		setWindowText(u.status, "○  Stopped")
		setWindowText(u.startBtn, "Start")
	}
	// A command in flight owns both buttons. They used to be disabled by the
	// caller and re-enabled here by the next state broadcast, which arrives
	// while the command is still running: the button came back to life
	// mid-command and the click it then accepted was silently discarded.
	idle := pending == ""
	procEnableWindow.Call(uintptr(u.startBtn), boolToUintptr(idle))
	procEnableWindow.Call(uintptr(u.settingsBtn), boolToUintptr(idle && state.ServiceReady))
	procEnableWindow.Call(uintptr(u.openBtn), boolToUintptr(state.Config.LogPath != ""))
	u.updateSummary()
	u.updateTrayTip()
	if state.LastError != "" && idle {
		setWindowText(u.status, "⚠  "+state.LastError)
	}
}

// pendingLabel names the command in flight. Start and Stop drop it the moment
// the service reports the state they were heading for, which is what keeps
// "Starting…" a transition rather than a label outliving its transition: the
// new state usually broadcasts before the command call returns. The marker is
// the service's actual state, not the requested one - the dot goes solid when
// monitoring is really on.
func (u *AppUI) pendingLabel() string {
	switch u.pending {
	case protocol.CmdStart:
		if !u.state.Running {
			return "○  Starting…"
		}
	case protocol.CmdStop:
		if u.state.Running {
			return "●  Stopping…"
		}
	case protocol.CmdApply:
		// Apply re-applies the audit rule to every watched folder, the slowest
		// thing this window asks for and previously the least visible.
		dot := "○"
		if u.state.Running {
			dot = "●"
		}
		return dot + "  Applying changes…"
	}
	return ""
}

// beginCommand marks a command in flight and hands the status line and buttons
// to updateStatus for the duration.
func (u *AppUI) beginCommand(command string) bool {
	if !u.commandBusy.CompareAndSwap(false, true) {
		return false
	}
	u.pending = command
	u.updateStatus()
	return true
}

// endCommand runs on the command's own goroutine, so it tells the UI thread by
// message rather than touching the window.
func (u *AppUI) endCommand() {
	u.commandBusy.Store(false)
	postMessage(u.hwnd, wmAppStatus, 0, 0)
}

func boolToUintptr(v bool) uintptr {
	if v {
		return 1
	}
	return 0
}

func (u *AppUI) updateSummary() {
	folders := len(u.state.Config.Folders)
	text := fmt.Sprintf("%d %s · %d events", folders, plural(folders, "folder", "folders"), u.totalEvents)
	if dropped := since(u.state.LogDropped, &u.baseLogDropped); dropped > 0 {
		text += fmt.Sprintf(" · %d log events dropped", dropped)
	}
	if dropped := since(u.state.LiveDropped+u.liveDropped.Load(), &u.baseLiveDropped); dropped > 0 {
		text += fmt.Sprintf(" · %d live updates dropped", dropped)
	}
	// Suppressed reads are never silently hidden: the count is the user's
	// evidence that filtering is not concealing a reader they care about. It
	// counts reads, not processes, so it says so - "428 excluded" next to four
	// exclusion entries reads like a broken number.
	if suppressed := since(u.state.Suppressed, &u.baseSuppressed); suppressed > 0 {
		text += fmt.Sprintf(" · %d reads excluded", suppressed)
	}
	setWindowText(u.summary, text)
}

// since reports a service counter relative to the last Clear, so every number
// in the summary describes the same span as the rows on screen. The service
// zeroes these when monitoring restarts, so a value under the baseline means
// the baseline is stale, not that the count went backwards.
func since(current uint64, base *uint64) uint64 {
	if current < *base {
		*base = 0
	}
	return current - *base
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func (u *AppUI) runCommand(command string, cfg *settings.PublicConfig) {
	if !u.beginCommand(command) {
		return
	}
	go func() {
		defer u.endCommand()
		u.clientMu.RLock()
		client := u.client
		u.clientMu.RUnlock()
		if client == nil {
			// The service is demand-start, so nothing is listening until
			// monitoring is wanted. Only Start may bring it up; every other
			// command needs a service that is already running.
			if command != protocol.CmdStart {
				u.queueError(fmt.Errorf("ReadWatch service is not connected"))
				return
			}
			var err error
			if client, err = u.startServiceAndAttach(20 * time.Second); err != nil {
				u.queueError(err)
				return
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := client.Command(ctx, command, cfg)
		cancel()
		if err != nil {
			u.queueError(err)
		}
	}()
}

// startServiceAndAttach starts the demand-start service and waits for the
// existing reconnect loop to establish the pipe. It needs no elevation: the
// service DACL applied at install grants the installing account SERVICE_START.
func (u *AppUI) startServiceAndAttach(timeout time.Duration) (*IPCClient, error) {
	if err := startInstalledService(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if u.exiting.Load() {
			return nil, fmt.Errorf("ReadWatch is exiting")
		}
		u.clientMu.RLock()
		client := u.client
		u.clientMu.RUnlock()
		if client != nil {
			return client, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("the ReadWatch service started but did not accept a connection")
}

func (u *AppUI) toggleMonitoring() {
	if u.state.Running {
		u.runCommand(protocol.CmdStop, nil)
	} else {
		u.runCommand(protocol.CmdStart, nil)
	}
}

func (u *AppUI) openLog() {
	path := u.state.Config.LogPath
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err != nil {
		path = filepathDir(path)
	}
	if err := shellOpen(path); err != nil {
		u.queueError(err)
	}
}

func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			if i == 2 && len(path) >= 3 && path[1] == ':' {
				return path[:3]
			}
			return path[:i]
		}
	}
	return path
}

func (u *AppUI) clearView() {
	u.ring.Clear()
	u.totalEvents = 0
	u.baseSuppressed = u.state.Suppressed
	u.baseLogDropped = u.state.LogDropped
	u.baseLiveDropped = u.state.LiveDropped + u.liveDropped.Load()
	sendMessage(u.list, LVM_SETITEMCOUNT, 0, LVSICF_NOSCROLL)
	procInvalidateRect.Call(uintptr(u.list), 0, 1)
	u.updateSummary()
	u.hintClear()
}

func (u *AppUI) show() {
	procShowWindow.Call(uintptr(u.hwnd), SW_RESTORE)
	procSetForegroundWindow.Call(uintptr(u.hwnd))
	procSetActiveWindow.Call(uintptr(u.hwnd))
}

func (u *AppUI) hide() {
	u.hintClear()
	procShowWindow.Call(uintptr(u.hwnd), SW_HIDE)
}

func (u *AppUI) addTrayIcon() {
	if u.trayAdded || u.hwnd == 0 {
		return
	}
	nid := NOTIFYICONDATAW{CbSize: uint32(unsafe.Sizeof(NOTIFYICONDATAW{})), HWnd: u.hwnd, UID: trayIconID, UFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP, UCallbackMessage: wmAppTray, HIcon: u.iconSmall}
	copyUTF16(nid.SzTip[:], "ReadWatch")
	r, _, _ := procShellNotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
	u.trayAdded = r != 0
	if u.trayAdded {
		version := NOTIFYICONDATAW{CbSize: uint32(unsafe.Sizeof(NOTIFYICONDATAW{})), HWnd: u.hwnd, UID: trayIconID, UVersion: NOTIFYICON_VERSION_4}
		procShellNotifyIconW.Call(NIM_SETVERSION, uintptr(unsafe.Pointer(&version)))
	}
}

func (u *AppUI) removeTrayIcon() {
	if !u.trayAdded {
		return
	}
	nid := NOTIFYICONDATAW{CbSize: uint32(unsafe.Sizeof(NOTIFYICONDATAW{})), HWnd: u.hwnd, UID: trayIconID}
	procShellNotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
	u.trayAdded = false
}

func (u *AppUI) updateTrayTip() {
	if !u.trayAdded {
		return
	}
	tip := "ReadWatch — Stopped"
	if !u.state.ServiceReady {
		tip = "ReadWatch — Service unavailable"
	} else if u.state.Running {
		tip = "ReadWatch — Monitoring"
	}
	nid := NOTIFYICONDATAW{CbSize: uint32(unsafe.Sizeof(NOTIFYICONDATAW{})), HWnd: u.hwnd, UID: trayIconID, UFlags: NIF_TIP | NIF_ICON, HIcon: u.iconSmall}
	copyUTF16(nid.SzTip[:], tip)
	procShellNotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
}

// showRowMenu offers to suppress the reader on the row that was right-clicked.
// Acting on the noise actually in front of you beats hunting for the process
// name in Settings, which is where most of these exclusions come from.
// drawHeader paints the list-view header. SysHeader32 ignores the dark theme on
// current Windows builds and keeps painting itself light, including the blank
// strip to the right of the last column, so the whole thing is drawn by hand.
func (u *AppUI) drawHeader(cd *NMCUSTOMDRAW) uintptr {
	switch cd.DwDrawStage {
	case CDDS_PREPAINT:
		// Fill the entire header first: this is what kills the light sliver past
		// the final column, which per-item drawing never reaches.
		var rc RECT
		procGetClientRect.Call(uintptr(u.header), uintptr(unsafe.Pointer(&rc)))
		u.fillRect(cd.Hdc, rc, u.theme.headerBg)
		bottom := RECT{Left: rc.Left, Top: rc.Bottom - 1, Right: rc.Right, Bottom: rc.Bottom}
		u.fillRect(cd.Hdc, bottom, u.theme.line)
		return CDRF_NOTIFYITEMDRAW
	case CDDS_ITEMPREPAINT:
		index := int(cd.DwItemSpec)
		if index < 0 || index >= len(u.columns) {
			return CDRF_DODEFAULT
		}
		rc := cd.Rc
		u.fillRect(cd.Hdc, RECT{Left: rc.Left, Top: rc.Top, Right: rc.Right, Bottom: rc.Bottom - 1}, u.theme.headerBg)
		// Column separator, inset vertically so it reads as a hairline rather
		// than a hard grid.
		if index > 0 {
			sep := RECT{Left: rc.Left, Top: rc.Top + u.scale(6), Right: rc.Left + 1, Bottom: rc.Bottom - u.scale(7)}
			u.fillRect(cd.Hdc, sep, u.theme.line)
		}
		procSetBkMode.Call(uintptr(cd.Hdc), TRANSPARENT)
		procSetTextColor.Call(uintptr(cd.Hdc), uintptr(u.theme.headerText))
		old, _, _ := procSelectObject.Call(uintptr(cd.Hdc), uintptr(u.font))
		text := RECT{Left: rc.Left + u.scale(8), Top: rc.Top, Right: rc.Right - u.scale(6), Bottom: rc.Bottom - 1}
		label := syscall.StringToUTF16(u.columns[index])
		procDrawTextW.Call(uintptr(cd.Hdc), uintptr(unsafe.Pointer(&label[0])), ^uintptr(0),
			uintptr(unsafe.Pointer(&text)), DT_LEFT|DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS)
		runtime.KeepAlive(label)
		if old != 0 {
			procSelectObject.Call(uintptr(cd.Hdc), old)
		}
		return CDRF_SKIPDEFAULT
	}
	return CDRF_DODEFAULT
}

func (u *AppUI) fillRect(hdc HDC, rc RECT, color uint32) {
	brush, _, _ := procCreateSolidBrush.Call(uintptr(color))
	if brush == 0 {
		return
	}
	procFillRect.Call(uintptr(hdc), uintptr(unsafe.Pointer(&rc)), brush)
	deleteObject(brush)
}

func (u *AppUI) showRowMenu(row int) {
	if row < 0 {
		return
	}
	e, ok := u.ring.Newest(row)
	if !ok || e.Process == "" {
		return
	}
	if !u.state.ServiceReady {
		return
	}
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	appendMenu(menu, MF_STRING, rowExcludeName, "Exclude "+e.Process)
	if e.ProcessPath != "" {
		appendMenu(menu, MF_STRING, rowExcludePath, "Exclude only this exact path")
	}
	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(uintptr(u.hwnd))
	cmd, _, _ := procTrackPopupMenu.Call(menu, TPM_RIGHTBUTTON|TPM_RETURNCMD, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(u.hwnd), 0)
	switch int(cmd) {
	case rowExcludeName:
		u.addExclusion(e.Process)
	case rowExcludePath:
		u.addExclusion(e.ProcessPath)
	}
}

// addExclusion sends the whole config back through the normal apply path, so
// the service stays the single owner of configuration state.
func (u *AppUI) addExclusion(entry string) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return
	}
	cfg := u.state.Config
	for _, existing := range cfg.ExcludedProcesses {
		if strings.EqualFold(strings.TrimSpace(existing), entry) {
			return
		}
	}
	cfg.ExcludedProcesses = append(append([]string(nil), cfg.ExcludedProcesses...), entry)
	u.runCommand(protocol.CmdApply, &cfg)
}

func (u *AppUI) showTrayMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	appendMenu(menu, MF_STRING, trayShow, "Show ReadWatch")
	toggle := "Start monitoring"
	if u.state.Running {
		toggle = "Stop monitoring"
	}
	// The two entries a command in flight would refuse are grayed rather than
	// left live and silently ignored, matching the buttons in the window.
	busy := uintptr(MF_STRING)
	if u.commandBusy.Load() {
		busy |= MF_GRAYED
	}
	appendMenu(menu, busy, trayToggle, toggle)
	appendMenu(menu, MF_STRING, trayOpenLog, "Open log")
	appendMenu(menu, busy, traySettings, "Settings")
	procAppendMenuW.Call(menu, MF_SEPARATOR, 0, 0)
	appendMenu(menu, MF_STRING, trayExit, "Exit viewer")
	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(uintptr(u.hwnd))
	cmd, _, _ := procTrackPopupMenu.Call(menu, TPM_RIGHTBUTTON|TPM_RETURNCMD, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(u.hwnd), 0)
	switch int(cmd) {
	case trayShow:
		u.show()
	case trayToggle:
		u.toggleMonitoring()
	case trayOpenLog:
		u.openLog()
	case traySettings:
		u.openSettings()
	case trayExit:
		u.exiting.Store(true)
		procDestroyWindow.Call(uintptr(u.hwnd))
	}
}

func appendMenu(menu uintptr, flags uintptr, id int, text string) {
	procAppendMenuW.Call(menu, flags, uintptr(id), uintptr(unsafe.Pointer(utf16Ptr(text))))
}

func (u *AppUI) shutdown() {
	u.exiting.Store(true)
	u.removeTrayIcon()
	u.clientMu.Lock()
	if u.client != nil {
		u.client.Close()
		u.client = nil
	}
	u.clientMu.Unlock()
	// Exiting the app leaves nothing privileged running. Stop
	// the service here, after the pipe is released so it is not torn down under
	// a live client. This is synchronous because the process is about to exit -
	// a goroutine would be killed before SCM finished. The configured Enabled
	// flag is untouched, so relaunching resumes monitoring.
	if err := stopInstalledService(5 * time.Second); err != nil {
		writeServiceDiagnostic(err)
	}
	// Wake the wait goroutines and let process teardown close these handles.
	// Closing a handle while another thread is inside WaitForSingleObject has
	// undefined behavior on Windows.
	if u.activation != 0 {
		procSetEvent.Call(uintptr(u.activation))
		u.activation = 0
	}
	if u.exitEvent != 0 {
		procSetEvent.Call(uintptr(u.exitEvent))
		u.exitEvent = 0
	}
	if u.mutex != 0 {
		closeHandle(u.mutex)
		u.mutex = 0
	}
	if u.font != 0 {
		deleteObject(uintptr(u.font))
		u.font = 0
	}
	if u.theme.brush != 0 {
		deleteObject(uintptr(u.theme.brush))
		u.theme.brush = 0
	}
}

func mainWindowProc(hwnd uintptr, msg uint32, wParam uintptr, lParam unsafe.Pointer) uintptr {
	u := mainUI
	if u == nil {
		r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, uintptr(lParam))
		return r
	}
	if u.taskbarCreatedMsg != 0 && msg == u.taskbarCreatedMsg {
		u.trayAdded = false
		u.addTrayIcon()
		return 0
	}
	switch msg {
	case WM_SIZE:
		if uint32(wParam) == SIZE_MINIMIZED {
			u.hide()
			return 0
		}
		u.layout()
		return 0
	case WM_GETMINMAXINFO:
		mmi := (*MINMAXINFO)(lParam)
		mmi.PtMinTrackSize = POINT{X: u.scale(480), Y: u.scale(260)}
		return 0
	case WM_ERASEBKGND:
		if u.theme.brush != 0 {
			var rc RECT
			procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
			procFillRect.Call(wParam, uintptr(unsafe.Pointer(&rc)), uintptr(u.theme.brush))
			return 1
		}
	case WM_CTLCOLORSTATIC, WM_CTLCOLORBTN, WM_CTLCOLOREDIT, WM_CTLCOLORLISTBOX:
		if u.theme.brush != 0 {
			procSetTextColor.Call(wParam, uintptr(u.theme.text))
			procSetBkColor.Call(wParam, uintptr(u.theme.bg))
			procSetBkMode.Call(wParam, TRANSPARENT)
			return uintptr(u.theme.brush)
		}
	case WM_COMMAND:
		id := int(loword(wParam))
		code := hiword(wParam)
		if code == BN_CLICKED {
			switch id {
			case idStart:
				u.toggleMonitoring()
			case idSettings:
				u.openSettings()
			case idOpenLog:
				u.openLog()
			case idClear:
				u.clearView()
			case idExit:
				u.exiting.Store(true)
				procDestroyWindow.Call(uintptr(u.hwnd))
			}
		}
		return 0
	case WM_NOTIFY:
		hdr := (*NMHDR)(lParam)
		if hdr.HwndFrom == u.list && hdr.Code == NM_RCLICK {
			u.showRowMenu(int((*NMITEMACTIVATE)(lParam).IItem))
			return 1
		}
		if hdr.HwndFrom == u.list && hdr.Code == LVN_GETDISPINFOW {
			di := (*NMLVDISPINFOW)(lParam)
			if di.Item.Mask&LVIF_TEXT != 0 {
				u.lastDispText = syscall.StringToUTF16(u.cellText(int(di.Item.IItem), int(di.Item.ISubItem)))
				di.Item.PszText = &u.lastDispText[0]
			}
			return 0
		}
	case WM_DPICHANGED:
		u.dpiChanged(uint32(loword(wParam)), (*RECT)(lParam))
		return 0
	case WM_SETTINGCHANGE, WM_THEMECHANGED:
		u.applyTheme(false)
		return 0
	case WM_CLOSE:
		if !u.exiting.Load() {
			u.hide()
			return 0
		}
	case WM_DESTROY:
		u.shutdown()
		procPostQuitMessage.Call(0)
		return 0
	case wmAppEvents:
		u.drainEvents()
		return 0
	case wmAppState:
		u.drainState()
		return 0
	case wmAppError:
		u.drainError()
		u.updateStatus()
		return 0
	case wmAppStatus:
		// Only clear the label if nothing has started since: a tray toggle can
		// begin the next command before this message is drained.
		if !u.commandBusy.Load() {
			u.pending = ""
		}
		u.updateStatus()
		return 0
	case wmAppActivate:
		u.show()
		return 0
	case wmAppExit:
		u.exiting.Store(true)
		procDestroyWindow.Call(uintptr(u.hwnd))
		return 0
	case wmAppTray:
		switch uint32(loword(uintptr(lParam))) {
		case WM_LBUTTONUP, WM_LBUTTONDBLCLK, NIN_SELECT, NIN_KEYSELECT:
			u.show()
		case WM_RBUTTONUP, WM_CONTEXTMENU:
			u.showTrayMenu()
		}
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, uintptr(lParam))
	return r
}
