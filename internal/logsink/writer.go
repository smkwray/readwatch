package logsink

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

// New takes an already-open file and owns it from then on. It deliberately
// cannot open a path: the service opens the log under the connected owner's
// token and hands the handle here, so nothing in the writing path can be
// redirected by changing what the configured pathname points at. Creating the
// parent directory is gone for the same reason - a missing log folder is an
// error the owner fixes, not something to create with SYSTEM's authority.
func New(file *os.File, format Format) (*Writer, error) {
	if file == nil {
		return nil, errors.New("no log file was provided")
	}
	w := &Writer{file: file, buf: bufio.NewWriterSize(file, 64*1024), format: format}
	if format == CSV {
		w.csv = csv.NewWriter(w.buf)
		if info, statErr := file.Stat(); statErr == nil && info.Size() == 0 {
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

// WriteGap records that reads were missed, and why. A log that simply stops
// mentioning a folder is indistinguishable from a quiet folder, which is the
// one confusion this tool cannot afford: the reader who matters most is the one
// whose reads went unrecorded. Each category is written separately because they
// have different causes - a session that dropped buffers is not the same problem
// as a correlation that could not name a file.
func (w *Writer) WriteGap(at time.Time, category string, count uint64, detail string) error {
	if w == nil {
		return nil
	}
	var err error
	switch w.format {
	case JSONL:
		var b []byte
		b, err = json.Marshal(struct {
			Time     time.Time `json:"time"`
			Gap      string    `json:"gap"`
			Count    uint64    `json:"count"`
			Detail   string    `json:"detail,omitempty"`
			Category string    `json:"category"`
		}{at, "reads were not recorded", count, detail, category})
		if err == nil {
			_, err = w.buf.Write(append(b, '\n'))
		}
	case CSV:
		err = w.csv.Write([]string{
			at.Local().Format(time.RFC3339Nano), "GAP", category,
			strconv.FormatUint(count, 10), "", detail, "", "0", "0x0",
		})
	case Text:
		fallthrough
	default:
		_, err = fmt.Fprintf(w.buf, "%s | GAP  | %-24s | %d read(s) not recorded%s\n",
			at.Local().Format("2006-01-02 15:04:05.000"), clean(category), count, gapDetail(detail))
	}
	if err == nil {
		w.dirty = true
	}
	return err
}

func gapDetail(detail string) string {
	if detail == "" {
		return ""
	}
	return " | " + clean(detail)
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
