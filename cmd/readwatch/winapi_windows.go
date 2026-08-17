//go:build windows

package main

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

type (
	HWND                  uintptr
	HINSTANCE             uintptr
	HICON                 uintptr
	HCURSOR               uintptr
	HBRUSH                uintptr
	HMENU                 uintptr
	HDC                   uintptr
	HFONT                 uintptr
	HPEN                  uintptr
	HGDIOBJ               uintptr
	HANDLE                uintptr
	SC_HANDLE             uintptr
	SERVICE_STATUS_HANDLE uintptr
)

type POINT struct{ X, Y int32 }
type SIZE struct{ Cx, Cy int32 }
type RECT struct{ Left, Top, Right, Bottom int32 }

// MONITORINFO carries the work area - the monitor less the taskbar and any
// other appbar - which is what a popup has to stay inside.
type MONITORINFO struct {
	CbSize    uint32
	RcMonitor RECT
	RcWork    RECT
	DwFlags   uint32
}
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     HINSTANCE
	HIcon         HICON
	HCursor       HCURSOR
	HbrBackground HBRUSH
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       HICON
}

type MSG struct {
	HWnd     HWND
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       POINT
	LPrivate uint32
}

type PAINTSTRUCT struct {
	Hdc         HDC
	Erase       int32
	RcPaint     RECT
	Restore     int32
	IncUpdate   int32
	RGBReserved [32]byte
}

type MINMAXINFO struct {
	PtReserved     POINT
	PtMaxSize      POINT
	PtMaxPosition  POINT
	PtMinTrackSize POINT
	PtMaxTrackSize POINT
}

type NMHDR struct {
	HwndFrom HWND
	IDFrom   uintptr
	Code     int32
}

type NMLISTVIEW struct {
	Hdr       NMHDR
	IItem     int32
	ISubItem  int32
	UNewState uint32
	UOldState uint32
	UChanged  uint32
	PtAction  POINT
	LParam    uintptr
}

type NMLVDISPINFOW struct {
	Hdr  NMHDR
	Item LVITEMW
}

// NMCUSTOMDRAW is the header's draw callback. The list-view header is a
// separate SysHeader32 control that ignores DarkMode_Explorer and keeps
// painting itself light, so it has to be drawn by hand.
type NMCUSTOMDRAW struct {
	Hdr         NMHDR
	DwDrawStage uint32
	Hdc         HDC
	Rc          RECT
	DwItemSpec  uintptr
	UItemState  int32
	LItemlParam uintptr
}

// NMITEMACTIVATE carries the row under the cursor for NM_RCLICK, which is how
// the event list offers "exclude this process" on the row you actually clicked.
type NMITEMACTIVATE struct {
	Hdr      NMHDR
	IItem    int32
	ISubItem int32
	NewState uint32
	OldState uint32
	Changed  uint32
	PtAction POINT
	LParam   uintptr
	KeyFlags uint32
}

type INITCOMMONCONTROLSEX struct {
	DwSize uint32
	DwICC  uint32
}

// LVHITTESTINFO resolves a pointer position to a cell, which is what the hover
// hint needs: the row alone is not enough, the column decides which text was
// clipped.
type LVHITTESTINFO struct {
	Pt       POINT
	Flags    uint32
	IItem    int32
	ISubItem int32
	IGroup   int32
}

type TOOLINFOW struct {
	CbSize     uint32
	UFlags     uint32
	Hwnd       HWND
	UId        uintptr
	Rect       RECT
	Hinst      HINSTANCE
	LpszText   *uint16
	LParam     uintptr
	LpReserved uintptr
}

type TRACKMOUSEEVENT struct {
	CbSize      uint32
	DwFlags     uint32
	HwndTrack   HWND
	DwHoverTime uint32
}

// DEV_BROADCAST_HDR is the common prefix of every WM_DEVICECHANGE payload. Only
// the device type is read: which volume arrived does not matter, because the
// answer is always "ask the service to look again".
type DEV_BROADCAST_HDR struct {
	DbchSize       uint32
	DbchDeviceType uint32
	DbchReserved   uint32
}

type LVITEMW struct {
	Mask       uint32
	IItem      int32
	ISubItem   int32
	State      uint32
	StateMask  uint32
	PszText    *uint16
	CchTextMax int32
	IImage     int32
	LParam     uintptr
	IIndent    int32
	IGroupID   int32
	CColumns   uint32
	PuColumns  *uint32
	PiColFmt   *int32
	IGroup     int32
}

type LVCOLUMNW struct {
	Mask       uint32
	Fmt        int32
	Cx         int32
	PszText    *uint16
	CchTextMax int32
	ISubItem   int32
	IImage     int32
	IOrder     int32
	CxMin      int32
	CxDefault  int32
	CxIdeal    int32
}

type NOTIFYICONDATAW struct {
	CbSize           uint32
	HWnd             HWND
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            HICON
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         GUID
	HBalloonIcon     HICON
}

type SECURITY_ATTRIBUTES struct {
	Length             uint32
	SecurityDescriptor uintptr
	InheritHandle      int32
}

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUIDAndAttributes struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUIDAndAttributes
}

type TOKEN_ELEVATION struct{ TokenIsElevated uint32 }
type SIDAndAttributes struct {
	Sid        uintptr
	Attributes uint32
}
type TOKEN_USER struct{ User SIDAndAttributes }

type TRUSTEEW struct {
	PMultipleTrustee         uintptr
	MultipleTrusteeOperation uint32
	TrusteeForm              uint32
	TrusteeType              uint32
	_                        uint32
	Name                     uintptr
}

type EXPLICITACCESSW struct {
	AccessPermissions uint32
	AccessMode        uint32
	Inheritance       uint32
	_                 uint32
	Trustee           TRUSTEEW
}

type AUDITPOLICYINFORMATION struct {
	AuditSubCategoryGUID GUID
	AuditingInformation  uint32
	AuditCategoryGUID    GUID
}

type HIGHCONTRASTW struct {
	CbSize            uint32
	DwFlags           uint32
	LpszDefaultScheme *uint16
}

type SERVICE_STATUS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type SERVICE_STATUS_PROCESS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessID               uint32
	ServiceFlags            uint32
}

type SERVICE_TABLE_ENTRYW struct {
	ServiceName *uint16
	ServiceProc uintptr
}

type OVERLAPPED struct {
	Internal     uintptr
	InternalHigh uintptr
	Offset       uint32
	OffsetHigh   uint32
	HEvent       HANDLE
}

// FILE_ID_INFO is the identity that outlives a pathname: the volume plus a
// 128-bit file identifier. Renaming a folder does not change it; substituting a
// different folder at the same path does.
type FILE_ID_INFO struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type FILE_ATTRIBUTE_TAG_INFO struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type BY_HANDLE_FILE_INFORMATION struct {
	FileAttributes     uint32
	CreationTime       FILETIME
	LastAccessTime     FILETIME
	LastWriteTime      FILETIME
	VolumeSerialNumber uint32
	FileSizeHigh       uint32
	FileSizeLow        uint32
	NumberOfLinks      uint32
	FileIndexHigh      uint32
	FileIndexLow       uint32
}

type FILETIME struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func (f FILETIME) Uint64() uint64 {
	return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)
}

// FILE_ID_DESCRIPTOR is a union: FileIdTypeIndex reads the first 8 bytes,
// FileIdTypeExtended all 16. Sized for the largest member so both fit.
type FILE_ID_DESCRIPTOR struct {
	DwSize uint32
	Type   uint32
	ID     [16]byte
}

type SERVICE_DESCRIPTIONW struct{ Description *uint16 }
type WIN32_FIND_DATAW struct {
	FileAttributes     uint32
	CreationTimeLow    uint32
	CreationTimeHigh   uint32
	LastAccessTimeLow  uint32
	LastAccessTimeHigh uint32
	LastWriteTimeLow   uint32
	LastWriteTimeHigh  uint32
	FileSizeHigh       uint32
	FileSizeLow        uint32
	Reserved0          uint32
	Reserved1          uint32
	FileName           [260]uint16
	AlternateFileName  [14]uint16
	FileType           uint32
	CreatorType        uint32
	FinderFlags        uint16
}

const (
	CW_USEDEFAULT = int32(-2147483648)

	WM_CREATE          = 0x0001
	WM_DESTROY         = 0x0002
	WM_SIZE            = 0x0005
	WM_SETFOCUS        = 0x0007
	WM_PAINT           = 0x000F
	WM_CLOSE           = 0x0010
	WM_QUERYENDSESSION = 0x0011
	WM_ENDSESSION      = 0x0016
	WM_ERASEBKGND      = 0x0014
	WM_SETFONT         = 0x0030
	WM_GETFONT         = 0x0031
	WM_DRAWITEM        = 0x002B
	WM_COMMAND         = 0x0111
	WM_TIMER           = 0x0113
	WM_DEVICECHANGE    = 0x0219
	WM_NOTIFY          = 0x004E
	WM_CONTEXTMENU     = 0x007B
	WM_GETMINMAXINFO   = 0x0024
	WM_DPICHANGED      = 0x02E0
	WM_SETTINGCHANGE   = 0x001A
	WM_THEMECHANGED    = 0x031A
	WM_USER            = 0x0400
	WM_APP             = 0x8000
	WM_MOUSEMOVE       = 0x0200
	WM_LBUTTONDOWN     = 0x0201
	WM_LBUTTONUP       = 0x0202
	WM_LBUTTONDBLCLK   = 0x0203
	WM_RBUTTONDOWN     = 0x0204
	WM_RBUTTONUP       = 0x0205
	WM_MOUSEWHEEL      = 0x020A
	WM_MOUSEHOVER      = 0x02A1
	WM_MOUSELEAVE      = 0x02A3
	WM_KEYDOWN         = 0x0100
	WM_SYSCOMMAND      = 0x0112
	WM_CTLCOLOREDIT    = 0x0133
	WM_CTLCOLORLISTBOX = 0x0134
	WM_CTLCOLORBTN     = 0x0135
	WM_CTLCOLORSTATIC  = 0x0138

	// Volume arrival and departure. Windows broadcasts these to every top-level
	// window without any registration, which is why the viewer can notice a drive
	// appearing while it is hidden in the tray. DBT_DEVICEQUERYREMOVE is
	// deliberately not handled: it is only sent to windows that registered a
	// handle notification, and it does not cover a stick that is simply pulled.
	DBT_DEVICEARRIVAL        = 0x8000
	DBT_DEVICEREMOVECOMPLETE = 0x8004
	DBT_DEVTYP_VOLUME        = 2

	SC_MINIMIZE = 0xF020

	SW_HIDE        = 0
	SW_SHOWNORMAL  = 1
	SW_SHOW        = 5
	SW_MINIMIZE    = 6
	SW_RESTORE     = 9
	SW_SHOWDEFAULT = 10

	SIZE_MINIMIZED = 1

	WS_POPUP            = 0x80000000
	WS_OVERLAPPED       = 0x00000000
	WS_CAPTION          = 0x00C00000
	WS_SYSMENU          = 0x00080000
	WS_THICKFRAME       = 0x00040000
	WS_MINIMIZEBOX      = 0x00020000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_TABSTOP          = 0x00010000
	WS_CLIPCHILDREN     = 0x02000000
	WS_VSCROLL          = 0x00200000
	WS_HSCROLL          = 0x00100000
	WS_BORDER           = 0x00800000
	WS_DISABLED         = 0x08000000
	WS_GROUP            = 0x00020000
	WS_EX_DLGMODALFRAME = 0x00000001
	WS_EX_APPWINDOW     = 0x00040000
	WS_EX_CLIENTEDGE    = 0x00000200
	WS_EX_CONTROLPARENT = 0x00010000
	WS_EX_TOOLWINDOW    = 0x00000080

	BS_PUSHBUTTON    = 0x00000000
	BS_DEFPUSHBUTTON = 0x00000001
	BS_AUTOCHECKBOX  = 0x00000003
	BS_FLAT          = 0x00008000

	SS_LEFT        = 0x00000000
	SS_CENTER      = 0x00000001
	SS_CENTERIMAGE = 0x00000200
	SS_NOTIFY      = 0x00000100
	SS_ENDELLIPSIS = 0x00004000

	ES_AUTOHSCROLL = 0x0080
	ES_READONLY    = 0x0800

	LBS_NOTIFY           = 0x0001
	LBS_NOINTEGRALHEIGHT = 0x0100
	LBS_EXTENDEDSEL      = 0x0800

	CBS_DROPDOWNLIST = 0x0003

	LVS_REPORT           = 0x0001
	LVS_SINGLESEL        = 0x0004
	LVS_SHOWSELALWAYS    = 0x0008
	LVS_OWNERDATA        = 0x1000
	LVS_NOSORTHEADER     = 0x8000
	LVS_EX_FULLROWSELECT = 0x00000020
	LVS_EX_DOUBLEBUFFER  = 0x00010000
	LVS_EX_LABELTIP      = 0x00004000

	LVM_FIRST                    = 0x1000
	LVM_INSERTITEMW              = LVM_FIRST + 77
	LVM_SETITEMTEXTW             = LVM_FIRST + 116
	LVM_INSERTCOLUMNW            = LVM_FIRST + 97
	LVM_DELETEITEM               = LVM_FIRST + 8
	LVM_DELETEALLITEMS           = LVM_FIRST + 9
	LVM_GETITEMCOUNT             = LVM_FIRST + 4
	LVM_SETITEMCOUNT             = LVM_FIRST + 47
	LVM_SETEXTENDEDLISTVIEWSTYLE = LVM_FIRST + 54
	LVM_SETBKCOLOR               = LVM_FIRST + 1
	LVM_SETTEXTCOLOR             = LVM_FIRST + 36
	LVM_SETTEXTBKCOLOR           = LVM_FIRST + 38
	LVM_GETCOLUMNWIDTH           = LVM_FIRST + 29
	LVM_SETCOLUMNWIDTH           = LVM_FIRST + 30
	LVM_ENSUREVISIBLE            = LVM_FIRST + 19
	LVM_REDRAWITEMS              = LVM_FIRST + 21
	LVM_SUBITEMHITTEST           = LVM_FIRST + 57

	LVIF_TEXT                = 0x0001
	LVCF_FMT                 = 0x0001
	LVCF_WIDTH               = 0x0002
	LVCF_TEXT                = 0x0004
	LVCF_SUBITEM             = 0x0008
	LVCFMT_LEFT              = 0x0000
	LVSCW_AUTOSIZE_USEHEADER = -2
	LVN_FIRST                = -100
	LVN_GETDISPINFOW         = LVN_FIRST - 77
	NM_RCLICK                = -5
	NM_CUSTOMDRAW            = -12
	EM_SETCUEBANNER          = 0x1501
	LVM_GETHEADER            = LVM_FIRST + 31

	CDDS_PREPAINT       = 0x00000001
	CDDS_ITEMPREPAINT   = 0x00010001
	CDRF_DODEFAULT      = 0x00000000
	CDRF_SKIPDEFAULT    = 0x00000004
	CDRF_NOTIFYITEMDRAW = 0x00000020
	// -4, written this way so it converts to uintptr without tripping Go's
	// negative-constant conversion rule.
	GWLP_WNDPROC           = ^uintptr(3)
	LVN_ITEMCHANGED        = LVN_FIRST - 1
	LVSICF_NOINVALIDATEALL = 0x00000001
	LVSICF_NOSCROLL        = 0x00000002

	LB_ADDSTRING     = 0x0180
	LB_DELETESTRING  = 0x0182
	LB_GETITEMRECT   = 0x0198
	LB_ITEMFROMPOINT = 0x01A9
	LB_GETCOUNT      = 0x018B
	LB_GETCURSEL     = 0x0188
	LB_GETTEXT       = 0x0189
	LB_GETTEXTLEN    = 0x018A
	LB_RESETCONTENT  = 0x0184
	LB_SETCURSEL     = 0x0186
	LB_ERR           = -1

	CB_ADDSTRING = 0x0143
	CB_GETCURSEL = 0x0147
	CB_SETCURSEL = 0x014E

	BM_GETCHECK   = 0x00F0
	BM_SETCHECK   = 0x00F1
	BST_UNCHECKED = 0
	BST_CHECKED   = 1

	BN_CLICKED    = 0
	LBN_DBLCLK    = 2
	LBN_SELCHANGE = 1
	CBN_SELCHANGE = 1

	EN_CHANGE = 0x0300

	DT_LEFT         = 0x00000000
	DT_CENTER       = 0x00000001
	DT_RIGHT        = 0x00000002
	DT_VCENTER      = 0x00000004
	DT_SINGLELINE   = 0x00000020
	DT_END_ELLIPSIS = 0x00008000
	DT_NOPREFIX     = 0x00000800

	TRANSPARENT = 1

	COLOR_WINDOW     = 5
	COLOR_WINDOWTEXT = 8
	COLOR_BTNFACE    = 15
	COLOR_BTNTEXT    = 18

	HKEY_CURRENT_USER       = 0x80000001
	HKEY_LOCAL_MACHINE      = 0x80000002
	KEY_READ                = 0x20019
	KEY_WRITE               = 0x20006
	KEY_WOW64_64KEY         = 0x0100
	KEY_ALL_ACCESS          = 0xF003F
	REG_SZ                  = 1
	REG_DWORD               = 4
	REG_OPTION_NON_VOLATILE = 0

	IDC_ARROW       = 32512
	IDI_APPLICATION = 32512

	CS_HREDRAW = 0x0002
	CS_VREDRAW = 0x0001
	CS_DBLCLKS = 0x0008

	SWP_NOSIZE     = 0x0001
	SWP_NOMOVE     = 0x0002
	SWP_NOZORDER   = 0x0004
	SWP_NOACTIVATE = 0x0010

	// SetWindowPos takes these as HWND values, hence -1 and -2 as uintptr.
	HWND_TOPMOST   = ^uintptr(0)
	HWND_NOTOPMOST = ^uintptr(1)

	GWLP_USERDATA  = -21
	GWLP_HINSTANCE = -6

	MF_STRING       = 0x0000
	MF_SEPARATOR    = 0x0800
	MF_GRAYED       = 0x0001
	MF_CHECKED      = 0x0008
	TPM_RIGHTBUTTON = 0x0002
	TPM_RETURNCMD   = 0x0100

	NIM_ADD              = 0x00000000
	NIM_MODIFY           = 0x00000001
	NIM_DELETE           = 0x00000002
	NIM_SETVERSION       = 0x00000004
	NOTIFYICON_VERSION_4 = 4
	NIN_SELECT           = WM_USER
	NIN_KEYSELECT        = WM_USER + 1
	NIF_MESSAGE          = 0x00000001
	NIF_ICON             = 0x00000002
	NIF_TIP              = 0x00000004

	IMAGE_ICON      = 1
	LR_LOADFROMFILE = 0x00000010
	LR_DEFAULTSIZE  = 0x00000040

	MB_OK              = 0x00000000
	MB_ICONERROR       = 0x00000010
	MB_ICONINFORMATION = 0x00000040
	MB_ICONWARNING     = 0x00000030
	MB_YESNO           = 0x00000004
	MB_OKCANCEL        = 0x00000001
	MB_DEFBUTTON2      = 0x00000100
	IDOK               = 1
	IDCANCEL           = 2
	IDYES              = 6

	ICC_LISTVIEW_CLASSES = 0x00000001
	ICC_BAR_CLASSES      = 0x00000004
	ICC_STANDARD_CLASSES = 0x00004000

	// Hover hints for text the control had to clip.
	TOOLTIPS_CLASS     = "tooltips_class32"
	TTS_ALWAYSTIP      = 0x01
	TTS_NOPREFIX       = 0x02
	TTF_IDISHWND       = 0x0001
	TTF_TRACK          = 0x0020
	TTF_ABSOLUTE       = 0x0080
	TTM_TRACKACTIVATE  = WM_USER + 17
	TTM_TRACKPOSITION  = WM_USER + 18
	TTM_SETMAXTIPWIDTH = WM_USER + 24
	TTM_GETBUBBLESIZE  = WM_USER + 30
	TTM_ADDTOOLW       = WM_USER + 50
	TTM_DELTOOLW       = WM_USER + 51
	TTM_UPDATETIPTEXTW = WM_USER + 57
	TME_HOVER          = 0x00000001
	TME_LEAVE          = 0x00000002

	MONITOR_DEFAULTTONEAREST = 0x00000002

	DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = ^uintptr(3)
	DWMWA_USE_IMMERSIVE_DARK_MODE              = 20
	DWMWA_WINDOW_CORNER_PREFERENCE             = 33
	DWMWCP_ROUND                               = 2

	SPI_GETHIGHCONTRAST     = 0x0042
	SPI_GETNONCLIENTMETRICS = 0x0029
	HCF_HIGHCONTRASTON      = 0x00000001

	TOKEN_QUERY             = 0x0008
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TokenUser               = 1
	TokenElevation          = 20
	SE_PRIVILEGE_ENABLED    = 0x00000002

	ERROR_SUCCESS             = 0
	ERROR_FILE_NOT_FOUND      = 2
	ERROR_PATH_NOT_FOUND      = 3
	ERROR_ACCESS_DENIED       = 5
	ERROR_INVALID_HANDLE      = 6
	ERROR_BROKEN_PIPE         = 109
	ERROR_INSUFFICIENT_BUFFER = 122
	ERROR_ALREADY_EXISTS      = 183
	// RegisterClassEx reports a duplicate class as 1410, NOT 183. Guarding on
	// ERROR_ALREADY_EXISTS meant reopening Settings failed with
	// "RegisterClassEx(settings): Class already exists."
	ERROR_CLASS_ALREADY_EXISTS = 1410
	ERROR_PIPE_BUSY            = 231
	ERROR_NO_DATA              = 232
	ERROR_PIPE_CONNECTED       = 535
	ERROR_IO_PENDING           = 997
	ERROR_OPERATION_ABORTED    = 995
	FILE_FLAG_OVERLAPPED       = 0x40000000
	ERROR_CANCELLED            = 1223
	ERROR_NOT_ALL_ASSIGNED     = 1300
	ERROR_SHARING_VIOLATION    = 32
	ERROR_LOCK_VIOLATION       = 33
	ERROR_NOT_READY            = 21
	ERROR_DEV_NOT_EXIST        = 55
	// A drive that is not in the machine does not report itself as "not ready".
	// Measured on this host: both GetVolumeNameForVolumeMountPointW on a free
	// drive letter and CreateFileW on an unattached \\?\Volume{...} name fail
	// with ERROR_FILE_NOT_FOUND. The rest of these cover the media-shaped
	// variants - an empty card reader, an unformatted or offline volume.
	ERROR_INVALID_DRIVE        = 15
	ERROR_BAD_UNIT             = 20
	ERROR_INVALID_NAME         = 123
	ERROR_NO_SUCH_DEVICE       = 433
	ERROR_UNRECOGNIZED_VOLUME  = 1005
	ERROR_NO_MEDIA_IN_DRIVE    = 1112
	ERROR_DEVICE_NOT_CONNECTED = 1167

	SEM_FAILCRITICALERRORS = 0x0001

	DRIVE_UNKNOWN                 = 0
	DRIVE_NO_ROOT_DIR             = 1
	DRIVE_REMOVABLE               = 2
	DRIVE_FIXED                   = 3
	DRIVE_REMOTE                  = 4
	DRIVE_CDROM                   = 5
	DRIVE_RAMDISK                 = 6
	ERROR_SERVICE_EXISTS          = 1073
	ERROR_SERVICE_ALREADY_RUNNING = 1056
	ERROR_SERVICE_NOT_ACTIVE      = 1062
	ERROR_SERVICE_DOES_NOT_EXIST  = 1060

	EVENT_MODIFY_STATE = 0x0002
	SYNCHRONIZE        = 0x00100000
	INFINITE           = 0xFFFFFFFF
	WAIT_OBJECT_0      = 0
	WAIT_TIMEOUT       = 258
	WAIT_FAILED        = 0xFFFFFFFF

	CREATE_NO_WINDOW = 0x08000000

	GENERIC_READ                 = 0x80000000
	GENERIC_WRITE                = 0x40000000
	FILE_READ_DATA               = 0x0001
	FILE_LIST_DIRECTORY          = 0x0001
	FILE_APPEND_DATA             = 0x0004
	FILE_READ_ATTRIBUTES         = 0x0080
	FILE_TRAVERSE                = 0x0020
	ACCESS_SYSTEM_SECURITY       = 0x01000000
	READ_CONTROL                 = 0x00020000
	FILE_SHARE_READ              = 0x00000001
	FILE_SHARE_WRITE             = 0x00000002
	FILE_SHARE_DELETE            = 0x00000004
	CREATE_NEW                   = 1
	CREATE_ALWAYS                = 2
	OPEN_EXISTING                = 3
	OPEN_ALWAYS                  = 4
	FILE_ATTRIBUTE_NORMAL        = 0x00000080
	FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000
	FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
	FILE_ATTRIBUTE_DIRECTORY     = 0x10
	FILE_ATTRIBUTE_REPARSE_POINT = 0x400
	INVALID_FILE_ATTRIBUTES      = 0xFFFFFFFF
	INVALID_HANDLE_VALUE         = ^uintptr(0)

	// GetFileInformationByHandleEx classes. FileIdInfo carries the 128-bit
	// identifier ReFS needs; FileAttributeTagInfo is how a reparse point is
	// detected on an already-open handle.
	FileAttributeTagInfo = 9
	FileIdInfo           = 18

	// Volume capability flags. A volume that cannot keep ACLs or cannot open by
	// file ID cannot carry an audit rule ReadWatch could later find again.
	FILE_PERSISTENT_ACLS          = 0x00000008
	FILE_SUPPORTS_OPEN_BY_FILE_ID = 0x01000000

	VOLUME_NAME_GUID = 0x00000001

	// OpenFileById descriptor kinds: 64-bit index on NTFS, 128-bit on ReFS.
	FileIdTypeIndex    = 0
	FileIdTypeExtended = 2

	MOVEFILE_REPLACE_EXISTING   = 0x00000001
	MOVEFILE_WRITE_THROUGH      = 0x00000008
	MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004

	REPLACEFILE_IGNORE_MERGE_ERRORS = 0x00000002

	DUPLICATE_SAME_ACCESS = 0x00000002

	PIPE_ACCESS_DUPLEX         = 0x00000003
	PIPE_TYPE_BYTE             = 0x00000000
	PIPE_READMODE_BYTE         = 0x00000000
	PIPE_WAIT                  = 0x00000000
	PIPE_UNLIMITED_INSTANCES   = 255
	PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
	NMPWAIT_WAIT_FOREVER       = 0xFFFFFFFF

	SEE_MASK_NOCLOSEPROCESS = 0x00000040

	COINIT_APARTMENTTHREADED = 0x2
	CLSCTX_INPROC_SERVER     = 0x1
	FOS_PICKFOLDERS          = 0x00000020
	FOS_FORCEFILESYSTEM      = 0x00000040
	FOS_PATHMUSTEXIST        = 0x00000800
	FOS_OVERWRITEPROMPT      = 0x00000002
	FOS_NOREADONLYRETURN     = 0x00008000
	SIGDN_FILESYSPATH        = 0x80058000

	SACL_SECURITY_INFORMATION             = 0x00000008
	DACL_SECURITY_INFORMATION             = 0x00000004
	PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
	PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
	UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
	// SE_SACL_PROTECTED in the descriptor's control word: restoring a SACL has to
	// put back whether it blocked inherited audit entries, not just its contents.
	SE_SACL_PROTECTED          = 0x2000
	SE_FILE_OBJECT             = 1
	POLICY_AUDIT_EVENT_SUCCESS = 0x00000001
	POLICY_AUDIT_EVENT_NONE    = 0x00000004
	ACL_REVISION_INFORMATION   = 1
	ACL_SIZE_INFORMATION       = 2
	REVOKE_ACCESS              = 4
	SET_AUDIT_SUCCESS          = 5
	OBJECT_INHERIT_ACE         = 0x00000001
	CONTAINER_INHERIT_ACE      = 0x00000002

	SC_MANAGER_CONNECT           = 0x0001
	SC_MANAGER_CREATE_SERVICE    = 0x0002
	SC_MANAGER_ALL_ACCESS        = 0xF003F
	SERVICE_QUERY_CONFIG         = 0x0001
	SERVICE_CHANGE_CONFIG        = 0x0002
	SERVICE_QUERY_STATUS         = 0x0004
	SERVICE_ENUMERATE_DEPENDENTS = 0x0008
	SERVICE_START                = 0x0010
	SERVICE_STOP                 = 0x0020
	SERVICE_DELETE               = 0x00010000
	SERVICE_ALL_ACCESS           = 0xF01FF
	SERVICE_WIN32_OWN_PROCESS    = 0x00000010
	SERVICE_AUTO_START           = 0x00000002
	SERVICE_DEMAND_START         = 0x00000003
	SERVICE_INTERROGATE          = 0x0080
	SERVICE_ERROR_NORMAL         = 0x00000001
	SERVICE_CONTROL_STOP         = 0x00000001
	SERVICE_CONTROL_SHUTDOWN     = 0x00000005
	SERVICE_CONTROL_PRESHUTDOWN  = 0x0000000F
	SERVICE_STOPPED              = 0x00000001
	SERVICE_START_PENDING        = 0x00000002
	SERVICE_STOP_PENDING         = 0x00000003
	SERVICE_RUNNING              = 0x00000004
	SERVICE_ACCEPT_STOP          = 0x00000001
	SERVICE_ACCEPT_SHUTDOWN      = 0x00000004
	SERVICE_ACCEPT_PRESHUTDOWN   = 0x00000100
	SERVICE_CONFIG_DESCRIPTION   = 1
	SC_STATUS_PROCESS_INFO       = 0

	DELETE = 0x00010000
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	dwmapi   = syscall.NewLazyDLL("dwmapi.dll")
	uxtheme  = syscall.NewLazyDLL("uxtheme.dll")
	ole32    = syscall.NewLazyDLL("ole32.dll")
	wevtapi  = syscall.NewLazyDLL("wevtapi.dll")

	procGetModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
	procGetCurrentProcess      = kernel32.NewProc("GetCurrentProcess")
	procGetCurrentProcessId    = kernel32.NewProc("GetCurrentProcessId")
	procGetLastError           = kernel32.NewProc("GetLastError")
	procLocalFree              = kernel32.NewProc("LocalFree")
	procCreateMutexW           = kernel32.NewProc("CreateMutexW")
	procOpenMutexW             = kernel32.NewProc("OpenMutexW")
	procReleaseMutex           = kernel32.NewProc("ReleaseMutex")
	procCreateEventW           = kernel32.NewProc("CreateEventW")
	procOpenEventW             = kernel32.NewProc("OpenEventW")
	procSetEvent               = kernel32.NewProc("SetEvent")
	procResetEvent             = kernel32.NewProc("ResetEvent")
	procWaitForSingleObject    = kernel32.NewProc("WaitForSingleObject")
	procWaitForMultipleObjects = kernel32.NewProc("WaitForMultipleObjects")
	procCancelIoEx             = kernel32.NewProc("CancelIoEx")
	procCloseHandle            = kernel32.NewProc("CloseHandle")
	procGetFileAttributesW     = kernel32.NewProc("GetFileAttributesW")
	procMoveFileExW            = kernel32.NewProc("MoveFileExW")
	procCreateFileW            = kernel32.NewProc("CreateFileW")
	// The capability set: identify an open object and find it again by identity
	// alone, without consulting its configured name.
	procGetFileInformationByHandle      = kernel32.NewProc("GetFileInformationByHandle")
	procGetFileInformationByHandleEx    = kernel32.NewProc("GetFileInformationByHandleEx")
	procGetVolumeInformationByHandleW   = kernel32.NewProc("GetVolumeInformationByHandleW")
	procGetFinalPathNameByHandleW       = kernel32.NewProc("GetFinalPathNameByHandleW")
	procGetVolumeNameForVolumeMountPntW = kernel32.NewProc("GetVolumeNameForVolumeMountPointW")
	procOpenFileById                    = kernel32.NewProc("OpenFileById")
	procDuplicateHandle                 = kernel32.NewProc("DuplicateHandle")
	procReplaceFileW                    = kernel32.NewProc("ReplaceFileW")
	// Known folders are the authority for these locations. An elevated process
	// must not take them from inherited environment variables, which the account
	// it elevated from controls.
	procSHGetKnownFolderPath    = shell32.NewProc("SHGetKnownFolderPath")
	procCreateNamedPipeW        = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe        = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe     = kernel32.NewProc("DisconnectNamedPipe")
	procWaitNamedPipeW          = kernel32.NewProc("WaitNamedPipeW")
	procSetNamedPipeHandleState = kernel32.NewProc("SetNamedPipeHandleState")
	procFlushFileBuffers        = kernel32.NewProc("FlushFileBuffers")
	procGetFullPathNameW        = kernel32.NewProc("GetFullPathNameW")
	procGetDriveTypeW           = kernel32.NewProc("GetDriveTypeW")
	procGetLogicalDrives        = kernel32.NewProc("GetLogicalDrives")
	procSetErrorMode            = kernel32.NewProc("SetErrorMode")

	procRegisterClassExW       = user32.NewProc("RegisterClassExW")
	procRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
	procCreateWindowExW        = user32.NewProc("CreateWindowExW")
	procDefWindowProcW         = user32.NewProc("DefWindowProcW")
	procShowWindow             = user32.NewProc("ShowWindow")
	procUpdateWindow           = user32.NewProc("UpdateWindow")
	procGetMessageW            = user32.NewProc("GetMessageW")
	procIsDialogMessageW       = user32.NewProc("IsDialogMessageW")
	procTranslateMessage       = user32.NewProc("TranslateMessage")
	procDispatchMessageW       = user32.NewProc("DispatchMessageW")
	procPostQuitMessage        = user32.NewProc("PostQuitMessage")
	procPostMessageW           = user32.NewProc("PostMessageW")
	procSendMessageW           = user32.NewProc("SendMessageW")
	procGetClientRect          = user32.NewProc("GetClientRect")
	procGetWindowRect          = user32.NewProc("GetWindowRect")
	procMoveWindow             = user32.NewProc("MoveWindow")
	procSetWindowPos           = user32.NewProc("SetWindowPos")
	procBeginPaint             = user32.NewProc("BeginPaint")
	procEndPaint               = user32.NewProc("EndPaint")
	procInvalidateRect         = user32.NewProc("InvalidateRect")
	procLoadCursorW            = user32.NewProc("LoadCursorW")
	procLoadIconW              = user32.NewProc("LoadIconW")
	procLoadImageW             = user32.NewProc("LoadImageW")
	procSetWindowTextW         = user32.NewProc("SetWindowTextW")
	procGetWindowTextLengthW   = user32.NewProc("GetWindowTextLengthW")
	procGetWindowTextW         = user32.NewProc("GetWindowTextW")
	procEnableWindow           = user32.NewProc("EnableWindow")
	procDestroyWindow          = user32.NewProc("DestroyWindow")
	procSetTimer               = user32.NewProc("SetTimer")
	procKillTimer              = user32.NewProc("KillTimer")
	procIsWindowVisible        = user32.NewProc("IsWindowVisible")
	procSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	procSetFocus               = user32.NewProc("SetFocus")
	procGetWindowLongPtrW      = user32.NewProc("GetWindowLongPtrW")
	procSetWindowLongPtrW      = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW        = user32.NewProc("CallWindowProcW")
	procGetDlgCtrlID           = user32.NewProc("GetDlgCtrlID")
	procCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	procAppendMenuW            = user32.NewProc("AppendMenuW")
	procTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	procDestroyMenu            = user32.NewProc("DestroyMenu")
	procGetCursorPos           = user32.NewProc("GetCursorPos")
	// MonitorFromRect rather than MonitorFromPoint: POINT is an 8-byte struct
	// passed by value, which x64 hands over in a single register, and getting
	// that wrong through LazyProc.Call is silent. A rect is a pointer.
	procMonitorFromRect               = user32.NewProc("MonitorFromRect")
	procGetMonitorInfoW               = user32.NewProc("GetMonitorInfoW")
	procMessageBoxW                   = user32.NewProc("MessageBoxW")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procGetDpiForWindow               = user32.NewProc("GetDpiForWindow")
	procGetDpiForSystem               = user32.NewProc("GetDpiForSystem")
	procSystemParametersInfoW         = user32.NewProc("SystemParametersInfoW")
	procFillRect                      = user32.NewProc("FillRect")
	procDrawTextW                     = user32.NewProc("DrawTextW")
	procSetActiveWindow               = user32.NewProc("SetActiveWindow")
	procIsIconic                      = user32.NewProc("IsIconic")
	procGetSystemMetrics              = user32.NewProc("GetSystemMetrics")
	procGetSysColor                   = user32.NewProc("GetSysColor")
	procGetDC                         = user32.NewProc("GetDC")
	procReleaseDC                     = user32.NewProc("ReleaseDC")
	procTrackMouseEvent               = user32.NewProc("TrackMouseEvent")

	procGetTextExtentPoint32W = gdi32.NewProc("GetTextExtentPoint32W")
	procCreateSolidBrush      = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject          = gdi32.NewProc("DeleteObject")
	procCreateFontW           = gdi32.NewProc("CreateFontW")
	procSetBkMode             = gdi32.NewProc("SetBkMode")
	procSetTextColor          = gdi32.NewProc("SetTextColor")
	procSetBkColor            = gdi32.NewProc("SetBkColor")
	procSelectObject          = gdi32.NewProc("SelectObject")
	procGetStockObject        = gdi32.NewProc("GetStockObject")

	procOpenProcessToken                                     = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation                                  = advapi32.NewProc("GetTokenInformation")
	procLookupPrivilegeValueW                                = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges                                = advapi32.NewProc("AdjustTokenPrivileges")
	procConvertSidToStringSidW                               = advapi32.NewProc("ConvertSidToStringSidW")
	procConvertStringSidToSidW                               = advapi32.NewProc("ConvertStringSidToSidW")
	procConvertStringSecurityDescriptorToSecurityDescriptorW = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procConvertSecurityDescriptorToStringSecurityDescriptorW = advapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	procGetSecurityDescriptorDacl                            = advapi32.NewProc("GetSecurityDescriptorDacl")
	procSetNamedSecurityInfoW                                = advapi32.NewProc("SetNamedSecurityInfoW")
	// The handle forms. A name can be rebound between the read and the write;
	// a handle refers to the object that was actually checked.
	procGetSecurityInfo               = advapi32.NewProc("GetSecurityInfo")
	procSetSecurityInfo               = advapi32.NewProc("SetSecurityInfo")
	procGetSecurityDescriptorSacl     = advapi32.NewProc("GetSecurityDescriptorSacl")
	procGetAclInformation             = advapi32.NewProc("GetAclInformation")
	procGetAce                        = advapi32.NewProc("GetAce")
	procSetSecurityDescriptorSacl     = advapi32.NewProc("SetSecurityDescriptorSacl")
	procInitializeSecurityDescriptor  = advapi32.NewProc("InitializeSecurityDescriptor")
	procSetSecurityDescriptorControl  = advapi32.NewProc("SetSecurityDescriptorControl")
	procGetSecurityDescriptorControl  = advapi32.NewProc("GetSecurityDescriptorControl")
	procOpenThreadToken               = advapi32.NewProc("OpenThreadToken")
	procGetCurrentThread              = kernel32.NewProc("GetCurrentThread")
	procGetNamedSecurityInfoW         = advapi32.NewProc("GetNamedSecurityInfoW")
	procSetFileSecurityW              = advapi32.NewProc("SetFileSecurityW")
	procBuildTrusteeWithSidW          = advapi32.NewProc("BuildTrusteeWithSidW")
	procSetEntriesInAclW              = advapi32.NewProc("SetEntriesInAclW")
	procAuditQuerySystemPolicy        = advapi32.NewProc("AuditQuerySystemPolicy")
	procAuditSetSystemPolicy          = advapi32.NewProc("AuditSetSystemPolicy")
	procAuditFree                     = advapi32.NewProc("AuditFree")
	procRegOpenKeyExW                 = advapi32.NewProc("RegOpenKeyExW")
	procRegCreateKeyExW               = advapi32.NewProc("RegCreateKeyExW")
	procRegQueryValueExW              = advapi32.NewProc("RegQueryValueExW")
	procRegSetValueExW                = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW               = advapi32.NewProc("RegDeleteValueW")
	procRegDeleteTreeW                = advapi32.NewProc("RegDeleteTreeW")
	procRegCloseKey                   = advapi32.NewProc("RegCloseKey")
	procImpersonateNamedPipeClient    = advapi32.NewProc("ImpersonateNamedPipeClient")
	procRevertToSelf                  = advapi32.NewProc("RevertToSelf")
	procOpenSCManagerW                = advapi32.NewProc("OpenSCManagerW")
	procCreateServiceW                = advapi32.NewProc("CreateServiceW")
	procOpenServiceW                  = advapi32.NewProc("OpenServiceW")
	procStartServiceW                 = advapi32.NewProc("StartServiceW")
	procControlService                = advapi32.NewProc("ControlService")
	procDeleteService                 = advapi32.NewProc("DeleteService")
	procQueryServiceStatusEx          = advapi32.NewProc("QueryServiceStatusEx")
	procChangeServiceConfigW          = advapi32.NewProc("ChangeServiceConfigW")
	procChangeServiceConfig2W         = advapi32.NewProc("ChangeServiceConfig2W")
	procSetServiceObjectSecurity      = advapi32.NewProc("SetServiceObjectSecurity")
	procCloseServiceHandle            = advapi32.NewProc("CloseServiceHandle")
	procStartServiceCtrlDispatcherW   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32.NewProc("SetServiceStatus")

	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
	procShellExecuteW    = shell32.NewProc("ShellExecuteW")

	procInitCommonControlsEx  = comctl32.NewProc("InitCommonControlsEx")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
	procSetWindowTheme        = uxtheme.NewProc("SetWindowTheme")

	procCoInitializeEx   = ole32.NewProc("CoInitializeEx")
	procCoUninitialize   = ole32.NewProc("CoUninitialize")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
	procCoTaskMemFree    = ole32.NewProc("CoTaskMemFree")

	procEvtSubscribe = wevtapi.NewProc("EvtSubscribe")
	procEvtRender    = wevtapi.NewProc("EvtRender")
	procEvtClose     = wevtapi.NewProc("EvtClose")
)

func utf16Ptr(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		panic(err)
	}
	return p
}

func utf16FromPtr(p *uint16) string {
	if p == nil {
		return ""
	}
	var n int
	for *(*uint16)(unsafe.Add(unsafe.Pointer(p), n*int(unsafe.Sizeof(*p)))) != 0 {
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}

func copyUTF16(dst []uint16, s string) {
	u := syscall.StringToUTF16(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
	}
	copy(dst, u)
	if len(dst) > 0 {
		dst[len(dst)-1] = 0
	}
}

func loword(v uintptr) uint16         { return uint16(v & 0xffff) }
func hiword(v uintptr) uint16         { return uint16((v >> 16) & 0xffff) }
func makelparam(lo, hi int32) uintptr { return uintptr(uint32(lo)&0xffff | (uint32(hi)&0xffff)<<16) }
func rgb(r, g, b byte) uint32         { return uint32(r) | uint32(g)<<8 | uint32(b)<<16 }

func winErr(label string, err error) error {
	if err == nil || errors.Is(err, syscall.Errno(0)) {
		return errors.New(label)
	}
	return fmt.Errorf("%s: %w", label, err)
}

func lastErr(label string) error {
	r, _, _ := procGetLastError.Call()
	if r == 0 {
		return errors.New(label)
	}
	return fmt.Errorf("%s: %w", label, syscall.Errno(r))
}

func messageBox(owner HWND, text, title string, flags uint32) int32 {
	r, _, _ := procMessageBoxW.Call(uintptr(owner), uintptr(unsafe.Pointer(utf16Ptr(text))), uintptr(unsafe.Pointer(utf16Ptr(title))), uintptr(flags))
	return int32(r)
}

func sendMessage(hwnd HWND, msg uint32, w, l uintptr) uintptr {
	r, _, _ := procSendMessageW.Call(uintptr(hwnd), uintptr(msg), w, l)
	return r
}

func postMessage(hwnd HWND, msg uint32, w, l uintptr) bool {
	r, _, _ := procPostMessageW.Call(uintptr(hwnd), uintptr(msg), w, l)
	return r != 0
}

func closeHandle(h HANDLE) {
	if h != 0 && uintptr(h) != INVALID_HANDLE_VALUE {
		procCloseHandle.Call(uintptr(h))
	}
}

func closeServiceHandle(h SC_HANDLE) {
	if h != 0 {
		procCloseServiceHandle.Call(uintptr(h))
	}
}

func deleteObject(h uintptr) {
	if h != 0 {
		procDeleteObject.Call(h)
	}
}

func windowText(hwnd HWND) string {
	n, _, _ := procGetWindowTextLengthW.Call(uintptr(hwnd))
	buf := make([]uint16, n+1)
	if len(buf) == 0 {
		return ""
	}
	procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf)
}

func setWindowText(hwnd HWND, text string) {
	procSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(utf16Ptr(text))))
}
