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
	w, err := Open(path, Text)
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
	w, err := Open(path, JSONL)
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
		w, err := Open(path, CSV)
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
