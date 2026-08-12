package logsink

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"readwatch/internal/model"
)

type Format string

const (
	Text  Format = "text"
	JSONL Format = "jsonl"
	CSV   Format = "csv"
)

type Writer struct {
	file   *os.File
	buf    *bufio.Writer
	format Format
	csv    *csv.Writer
	dirty  bool
}

func Open(path string, format Format) (*Writer, error) {
	if path == "" {
		return nil, errors.New("log path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	w := &Writer{file: f, buf: bufio.NewWriterSize(f, 64*1024), format: format}
	if format == CSV {
		w.csv = csv.NewWriter(w.buf)
		if info, statErr := f.Stat(); statErr == nil && info.Size() == 0 {
			_ = w.csv.Write([]string{"time", "action", "process", "pid", "user", "path", "process_path", "record_id", "access_mask"})
		}
	}
	return w, nil
}

func (w *Writer) Write(e model.Event) error {
	var err error
	switch w.format {
	case JSONL:
		var b []byte
		b, err = json.Marshal(e)
		if err == nil {
			_, err = w.buf.Write(append(b, '\n'))
		}
	case CSV:
		err = w.csv.Write([]string{
			e.Time.Local().Format(time.RFC3339Nano), action(e), e.Process, strconv.FormatUint(uint64(e.PID), 10), e.User,
			e.Path, e.ProcessPath, strconv.FormatUint(e.RecordID, 10), fmt.Sprintf("0x%x", e.AccessMask),
		})
	case Text:
		fallthrough
	default:
		_, err = fmt.Fprintf(w.buf, "%s | %-4s | %-24s | pid=%-6d | %-28s | %s | exe=%s\n",
			e.Time.Local().Format("2006-01-02 15:04:05.000"), action(e), clean(e.Process), e.PID, clean(e.User), clean(e.Path), clean(e.ProcessPath))
	}
	if err == nil {
		w.dirty = true
	}
	return err
}

func (w *Writer) Dirty() bool { return w != nil && w.dirty }

func (w *Writer) Flush() error {
	if w == nil || !w.dirty {
		return nil
	}
	if w.csv != nil {
		w.csv.Flush()
		if err := w.csv.Error(); err != nil {
			return err
		}
	}
	if err := w.buf.Flush(); err != nil {
		return err
	}
	w.dirty = false
	return nil
}

func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	flushErr := w.Flush()
	closeErr := w.file.Close()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

func action(e model.Event) string {
	if e.Directory {
		return "LIST"
	}
	return "READ"
}

func clean(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "|", "¦").Replace(s)
}
