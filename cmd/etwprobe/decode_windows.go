//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"syscall"
	"unsafe"
)

// Event ids on Microsoft-Windows-Kernel-File, confirmed against a tracerpt dump
// of a real capture on this host rather than taken from documentation. Layouts
// below are read from the same dump, and every one of them is length-checked
// before a field is touched: an unexpected version must fail closed rather than
// be parsed by positional guesswork.
const (
	evNameCreate   = 10
	evNameDelete   = 11
	evCreate       = 12
	evCleanup      = 13
	evClose        = 14
	evRead         = 15
	evWrite        = 16
	evDirEnum      = 20
	evOperationEnd = 24
)

// keywordsAny is FILENAME|FILEIO|OP_END|CREATE|READ.
const keywordsAny = 0x1F0

var errShort = errors.New("event payload shorter than its declared layout")

// readEvent is Read (15). It carries no path: the name has to come from a
// FileObject or FileKey seen on another event, and the outcome from matching
// Irp against OperationEnd.
type readEvent struct {
	ByteOffset      uint64
	Irp             uint64
	FileObject      uint64
	FileKey         uint64
	IssuingThreadID uint32
	IOSize          uint32
}

func decodeRead(b []byte) (readEvent, error) {
	var r readEvent
	if len(b) < 40 {
		return r, errShort
	}
	r.ByteOffset = binary.LittleEndian.Uint64(b[0:])
	r.Irp = binary.LittleEndian.Uint64(b[8:])
	r.FileObject = binary.LittleEndian.Uint64(b[16:])
	r.FileKey = binary.LittleEndian.Uint64(b[24:])
	r.IssuingThreadID = binary.LittleEndian.Uint32(b[32:])
	r.IOSize = binary.LittleEndian.Uint32(b[36:])
	return r, nil
}

// nameEvent is NameCreate (10) and NameDelete (11): FileKey then the NT path.
type nameEvent struct {
	FileKey uint64
	Name    string
}

func decodeName(b []byte) (nameEvent, error) {
	var n nameEvent
	if len(b) < 8 {
		return n, errShort
	}
	n.FileKey = binary.LittleEndian.Uint64(b[0:])
	n.Name = utf16FromBytes(b[8:])
	return n, nil
}

// createEvent is Create (12): the other half of name resolution, keyed by
// FileObject rather than FileKey.
type createEvent struct {
	Irp        uint64
	FileObject uint64
	Name       string
}

func decodeCreate(b []byte) (createEvent, error) {
	var c createEvent
	if len(b) < 32 {
		return c, errShort
	}
	c.Irp = binary.LittleEndian.Uint64(b[0:])
	c.FileObject = binary.LittleEndian.Uint64(b[8:])
	c.Name = utf16FromBytes(b[32:])
	return c, nil
}

// opEndEvent is OperationEnd (24): whether the read actually succeeded.
type opEndEvent struct {
	Irp    uint64
	Status uint32
}

func decodeOpEnd(b []byte) (opEndEvent, error) {
	var o opEndEvent
	if len(b) < 20 {
		return o, errShort
	}
	o.Irp = binary.LittleEndian.Uint64(b[0:])
	o.Status = binary.LittleEndian.Uint32(b[16:])
	return o, nil
}

// closeEvent is Cleanup (13) and Close (14): when a FileObject mapping may be
// retired. Layout is Irp, FileObject, FileKey, IssuingThreadId.
type closeEvent struct {
	FileObject uint64
	FileKey    uint64
}

func decodeClose(b []byte) (closeEvent, error) {
	var c closeEvent
	if len(b) < 24 {
		return c, errShort
	}
	c.FileObject = binary.LittleEndian.Uint64(b[8:])
	c.FileKey = binary.LittleEndian.Uint64(b[16:])
	return c, nil
}

// utf16FromBytes reads a null-terminated UTF-16 string out of an event payload,
// stopping at the end of the buffer if the provider did not terminate it.
func utf16FromBytes(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	u := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		c := binary.LittleEndian.Uint16(b[i*2:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return syscall.UTF16ToString(u)
}

// payload copies the provider's bytes out while the record is still live. ETW
// owns that memory only for the duration of the callback, so nothing may retain
// it: every decode above works on this Go-owned copy.
func payload(rec *EVENT_RECORD) []byte {
	if rec.UserData == nil || rec.UserDataLength == 0 {
		return nil
	}
	src := unsafe.Slice((*byte)(rec.UserData), int(rec.UserDataLength))
	out := make([]byte, len(src))
	copy(out, src)
	return out
}
