//go:build windows

package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

// The Path column is the reason this window exists and it rarely fits, so text
// the control had to clip needs somewhere to go. One tracking tooltip serves
// every control that clips: the event list's cells and the Settings list boxes.
// Tracking mode rather than TTF_SUBCLASS because the list view is already
// subclassed and runs its own internal tooltip - driving show and hide from
// messages we handle anyway keeps exactly one mechanism in play.
type hintTip struct {
	tip    HWND
	owner  HWND
	target HWND
	buf    []uint16
}

// hintHoverMS is how long the pointer must settle before a hint appears. Long
// enough that dragging the pointer down a column of long paths stays quiet.
const hintHoverMS = 400

func newHintTip(owner HWND, maxWidth int32) *hintTip {
	instance, _, _ := procGetModuleHandleW.Call(0)
	h, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr(TOOLTIPS_CLASS))),
		0,
		WS_POPUP|TTS_NOPREFIX|TTS_ALWAYSTIP,
		0, 0, 0, 0,
		uintptr(owner), 0, instance, 0,
	)
	if h == 0 {
		return nil
	}
	t := &hintTip{tip: HWND(h)}
	// Without a maximum a long path becomes one tooltip wider than the screen.
	sendMessage(t.tip, TTM_SETMAXTIPWIDTH, 0, uintptr(maxWidth))
	return t
}

func (t *hintTip) toolInfo(owner, target HWND, text *uint16) TOOLINFOW {
	return TOOLINFOW{
		CbSize:   uint32(unsafe.Sizeof(TOOLINFOW{})),
		UFlags:   TTF_IDISHWND | TTF_TRACK | TTF_ABSOLUTE,
		Hwnd:     owner,
		UId:      uintptr(target),
		LpszText: text,
	}
}

func (t *hintTip) attach(owner, target HWND) {
	if t == nil || t.tip == 0 || target == 0 {
		return
	}
	ti := t.toolInfo(owner, target, nil)
	sendMessage(t.tip, TTM_ADDTOOLW, 0, uintptr(unsafe.Pointer(&ti)))
}

func (t *hintTip) detach(owner, target HWND) {
	if t == nil || t.tip == 0 || target == 0 {
		return
	}
	if t.target == target {
		t.hide()
	}
	ti := t.toolInfo(owner, target, nil)
	sendMessage(t.tip, TTM_DELTOOLW, 0, uintptr(unsafe.Pointer(&ti)))
}

// show places the hint below and right of the pointer. A tip drawn under the
// pointer takes the mouse off the control it describes, which fires
// WM_MOUSELEAVE, which hides the tip: a flicker loop.
func (t *hintTip) show(owner, target HWND, text string, x, y int32) {
	if t == nil || t.tip == 0 || text == "" {
		return
	}
	t.buf = syscall.StringToUTF16(text)
	ti := t.toolInfo(owner, target, &t.buf[0])
	sendMessage(t.tip, TTM_UPDATETIPTEXTW, 0, uintptr(unsafe.Pointer(&ti)))
	sendMessage(t.tip, TTM_TRACKPOSITION, 0, makelparam(x, y))
	sendMessage(t.tip, TTM_TRACKACTIVATE, 1, uintptr(unsafe.Pointer(&ti)))
	runtime.KeepAlive(t.buf)
	t.owner, t.target = owner, target
}

func (t *hintTip) hide() {
	if t == nil || t.tip == 0 || t.target == 0 {
		return
	}
	ti := t.toolInfo(t.owner, t.target, nil)
	sendMessage(t.tip, TTM_TRACKACTIVATE, 0, uintptr(unsafe.Pointer(&ti)))
	t.owner, t.target = 0, 0
}

// hintHover is the per-control hover state: which cell the pointer is over, and
// whether the hover notification that shows the hint is already armed.
type hintHover struct {
	item  int32
	sub   int32
	armed bool
}

func (h *hintHover) reset() { h.item, h.sub, h.armed = -1, -1, false }

// moved reports whether the pointer changed cell, which is when a visible hint
// has gone stale.
func (h *hintHover) moved(item, sub int32) bool {
	if item == h.item && sub == h.sub {
		return false
	}
	h.item, h.sub = item, sub
	return true
}

// arm asks for one WM_MOUSEHOVER once the pointer settles, plus the
// WM_MOUSELEAVE that says to take the hint down again.
func (h *hintHover) arm(target HWND) {
	if h.armed {
		return
	}
	tme := TRACKMOUSEEVENT{
		CbSize:      uint32(unsafe.Sizeof(TRACKMOUSEEVENT{})),
		DwFlags:     TME_LEAVE | TME_HOVER,
		HwndTrack:   target,
		DwHoverTime: hintHoverMS,
	}
	if r, _, _ := procTrackMouseEvent.Call(uintptr(unsafe.Pointer(&tme))); r != 0 {
		h.armed = true
	}
}

func textWidth(hwnd HWND, font HFONT, text string) int32 {
	if text == "" {
		return 0
	}
	hdc, _, _ := procGetDC.Call(uintptr(hwnd))
	if hdc == 0 {
		return 0
	}
	defer procReleaseDC.Call(uintptr(hwnd), hdc)
	old := uintptr(0)
	if font != 0 {
		old, _, _ = procSelectObject.Call(hdc, uintptr(font))
	}
	buf := syscall.StringToUTF16(text)
	var size SIZE
	procGetTextExtentPoint32W.Call(hdc, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)-1), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(buf)
	if old != 0 {
		procSelectObject.Call(hdc, old)
	}
	return size.Cx
}

func cursorHintPosition(dpi uint32) (int32, int32) {
	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	scale := func(v int32) int32 { return int32(int64(v) * int64(dpi) / 96) }
	return pt.X + scale(16), pt.Y + scale(24)
}

// mouseX and mouseY unpack a mouse message's client coordinates, which are
// signed: the pointer can be left of or above the client area while captured.
func mouseX(lParam unsafe.Pointer) int32 { return int32(int16(loword(uintptr(lParam)))) }
func mouseY(lParam unsafe.Pointer) int32 { return int32(int16(hiword(uintptr(lParam)))) }

func (u *AppUI) hintCellAt(x, y int32) (int32, int32) {
	hit := LVHITTESTINFO{Pt: POINT{X: x, Y: y}}
	if r := sendMessage(u.list, LVM_SUBITEMHITTEST, 0, uintptr(unsafe.Pointer(&hit))); int32(r) >= 0 {
		return hit.IItem, hit.ISubItem
	}
	return -1, -1
}

func (u *AppUI) hintMouseMove(x, y int32) {
	item, sub := u.hintCellAt(x, y)
	if u.hover.moved(item, sub) {
		u.hint.hide()
	}
	u.hover.arm(u.list)
}

// hintShow runs on WM_MOUSEHOVER, which carries its own pointer position. The
// cell is resolved from that rather than from the last move: rows shift under a
// resting pointer every time an event arrives.
func (u *AppUI) hintShow(x, y int32) {
	u.hover.armed = false
	item, sub := u.hintCellAt(x, y)
	u.hover.moved(item, sub)
	if item < 0 {
		return
	}
	text := u.cellText(int(item), int(sub))
	// Only what the control had to clip: a hint over text you can already read
	// is noise.
	if text == "" || textWidth(u.list, u.font, text) <= u.cellTextWidth(sub) {
		return
	}
	tipX, tipY := cursorHintPosition(u.dpi)
	u.hint.show(u.hwnd, u.list, text, tipX, tipY)
}

// cellTextWidth is the room a cell has for text: the column, less the list
// view's own left and right padding.
func (u *AppUI) cellTextWidth(column int32) int32 {
	return int32(sendMessage(u.list, LVM_GETCOLUMNWIDTH, uintptr(column), 0)) - u.scale(12)
}

func (u *AppUI) hintClear() {
	u.hint.hide()
	u.hover.reset()
}

// listBoxOrigProc is the stock LISTBOX procedure, shared because both Settings
// list boxes are the same class. Held outside SettingsUI so a message arriving
// after the window is gone still reaches the right proc.
var (
	listBoxOrigProc        uintptr
	listBoxSubclassProcPtr = syscall.NewCallback(listBoxSubclassProc)
)

func listBoxSubclassProc(hwnd uintptr, msg uint32, wParam uintptr, lParam unsafe.Pointer) uintptr {
	if s := settingsUI; s != nil && s.hwnd != 0 {
		switch msg {
		case WM_MOUSEMOVE:
			s.hintMouseMove(HWND(hwnd), mouseX(lParam), mouseY(lParam))
		case WM_MOUSEHOVER:
			s.hintShow(HWND(hwnd), mouseX(lParam), mouseY(lParam))
		case WM_MOUSELEAVE, WM_MOUSEWHEEL, WM_LBUTTONDOWN, WM_RBUTTONDOWN:
			s.hintClear()
		}
	}
	if listBoxOrigProc != 0 {
		r, _, _ := procCallWindowProcW.Call(listBoxOrigProc, hwnd, uintptr(msg), wParam, uintptr(lParam))
		return r
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, uintptr(lParam))
	return r
}

// attachHints gives both Settings list boxes the same hover hint as the event
// list: a watched folder path is exactly the kind of string that does not fit.
func (s *SettingsUI) attachHints() {
	s.hover.reset()
	for _, list := range []HWND{s.folderList, s.excludeList} {
		s.app.hint.attach(s.hwnd, list)
		if prev, _, _ := procSetWindowLongPtrW.Call(uintptr(list), GWLP_WNDPROC, listBoxSubclassProcPtr); prev != 0 {
			listBoxOrigProc = prev
		}
	}
}

func (s *SettingsUI) detachHints() {
	for _, list := range []HWND{s.folderList, s.excludeList} {
		s.app.hint.detach(s.hwnd, list)
	}
}

// hintItemAt resolves a pointer position to a list-box entry. LB_ITEMFROMPOINT
// answers with the nearest item, so empty space below the last entry still
// reports one; the item's own rectangle settles it.
func (s *SettingsUI) hintItemAt(list HWND, x, y int32) int32 {
	r := sendMessage(list, LB_ITEMFROMPOINT, 0, makelparam(x, y))
	if hiword(r) != 0 {
		return -1
	}
	index := int32(int16(loword(r)))
	var rc RECT
	if ok := sendMessage(list, LB_GETITEMRECT, uintptr(index), uintptr(unsafe.Pointer(&rc))); int32(ok) == LB_ERR {
		return -1
	}
	if y < rc.Top || y >= rc.Bottom {
		return -1
	}
	return index
}

func (s *SettingsUI) hintMouseMove(list HWND, x, y int32) {
	if s.hover.moved(s.hintItemAt(list, x, y), 0) {
		s.app.hint.hide()
	}
	s.hover.arm(list)
}

func (s *SettingsUI) hintShow(list HWND, x, y int32) {
	s.hover.armed = false
	item := s.hintItemAt(list, x, y)
	s.hover.moved(item, 0)
	if item < 0 {
		return
	}
	text, ok := listBoxText(list, int(item))
	if !ok || text == "" {
		return
	}
	var rc RECT
	procGetClientRect.Call(uintptr(list), uintptr(unsafe.Pointer(&rc)))
	if textWidth(list, s.font, text) <= rc.Right-rc.Left-s.scale(8) {
		return
	}
	tipX, tipY := cursorHintPosition(s.dpi)
	s.app.hint.show(s.hwnd, list, text, tipX, tipY)
}

func (s *SettingsUI) hintClear() {
	s.app.hint.hide()
	s.hover.reset()
}
