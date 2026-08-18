package logsink

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"readwatch/internal/model"
)

func sampleEvent() model.Event {
	return model.Event{
		Time:        time.Date(2026, 8, 11, 16, 42, 8, 194_000_000, time.UTC),
		RecordID:    1234,
		Path:        `C:\Docs\report.txt`,
		ProcessPath: `C:\Windows\System32\notepad.exe`,
		Process:     "notepad.exe",
		PID:         8420,
		User:        `DESKTOP\User`,
		AccessMask:  1,
	}
}

func TestTextWriterProducesOneSanitizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "readwatch.log")
	f, ferr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if ferr != nil {
		t.Fatal(ferr)
	}
	w, err := New(f, Text)
	if err != nil {
		t.Fatal(err)
	}
	e := sampleEvent()
	e.Process = "bad|process\nname"
	e.Path = "C:\\Docs\\line1\r\nline2.txt"
	if err := w.Write(e); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Count(text, "\n") != 1 {
		t.Fatalf("expected one physical line, got %q", text)
	}
	if strings.Contains(text, "bad|process") || strings.Contains(text, "line1\r") {
		t.Fatalf("unsanitized text output: %q", text)
	}
	if !strings.Contains(text, "| READ |") || !strings.Contains(text, "bad¦process name") || !strings.Contains(text, "line1  line2.txt") {
		t.Fatalf("missing sanitized fields: %q", text)
	}
}

func TestJSONLWriterProducesValidEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "readwatch.jsonl")
	f, ferr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if ferr != nil {
		t.Fatal(ferr)
	}
	w, err := New(f, JSONL)
	if err != nil {
		t.Fatal(err)
	}
	want := sampleEvent()
	if err := w.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), "\n") != 1 {
		t.Fatalf("JSONL must contain one newline-delimited object: %q", string(b))
	}
	var got model.Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &got); err != nil {
		t.Fatal(err)
	}
	if got.RecordID != want.RecordID || got.Path != want.Path || got.PID != want.PID {
		t.Fatalf("event mismatch: got %+v want %+v", got, want)
	}
}

func TestCSVHeaderIsWrittenOnlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "readwatch.csv")
	for i := 0; i < 2; i++ {
		f, ferr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if ferr != nil {
			t.Fatal(ferr)
		}
		w, err := New(f, CSV)
		if err != nil {
			t.Fatal(err)
		}
		e := sampleEvent()
		e.RecordID += uint64(i)
		if err := w.Write(e); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("expected header plus two events, got %d rows: %#v", len(records), records)
	}
	if records[0][0] != "time" || records[0][1] != "action" || records[1][7] != "1234" || records[2][7] != "1235" {
		t.Fatalf("unexpected CSV rows: %#v", records)
	}
}

func TestGapIsRecordedInEveryFormat(t *testing.T) {
	// A log that simply stops mentioning a folder is indistinguishable from a
	// quiet folder. The reader who matters most is the one whose reads went
	// unrecorded, so the gap has to be in the log itself, not only in a counter.
	when := time.Date(2026, 8, 18, 9, 30, 0, 0, time.UTC)
	for _, f := range []Format{Text, JSONL, CSV} {
		path := filepath.Join(t.TempDir(), "log")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w, err := New(file, f)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteGap(when, "reads whose file could not be named", 7, ""); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out := string(b)
		if !strings.Contains(out, "7") {
			t.Errorf("%s: the count is missing from %q", f, out)
		}
		if !strings.Contains(out, "could not be named") {
			t.Errorf("%s: the reason is missing from %q", f, out)
		}
	}
}

func TestGapOnANilWriterIsNotAnError(t *testing.T) {
	var w *Writer
	if err := w.WriteGap(time.Now(), "x", 1, ""); err != nil {
		t.Fatal(err)
	}
}
