package eventparse

import "testing"

func TestParse4663(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4663</EventID><TimeCreated SystemTime="2026-08-11T20:13:54.7704297Z"/><EventRecordID>273866</EventRecordID></System><EventData><Data Name="SubjectUserSid">S-1-5-21-1</Data><Data Name="SubjectUserName">User</Data><Data Name="SubjectDomainName">DESKTOP</Data><Data Name="SubjectLogonId">0x4367b</Data><Data Name="ObjectType">File</Data><Data Name="ObjectName">C:\Data\a &amp; b.txt</Data><Data Name="HandleId">0x1bc</Data><Data Name="AccessList">%%4416</Data><Data Name="AccessMask">0x1</Data><Data Name="ProcessId">0x458</Data><Data Name="ProcessName">C:\Windows\System32\notepad.exe</Data></EventData></Event>`
	e, ok := Parse4663(xml)
	if !ok {
		t.Fatal("event was not parsed")
	}
	if e.Path != `C:\Data\a & b.txt` || e.PID != 0x458 || e.Process != "notepad.exe" || e.User != `DESKTOP\User` || e.RecordID != 273866 {
		t.Fatalf("unexpected event: %+v", e)
	}
}

func TestParse4663AcceptsSingleQuotedEventXML(t *testing.T) {
	xml := `<Event><System><EventID>4663</EventID><TimeCreated SystemTime='2026-08-11T20:13:54.7704297Z'/><EventRecordID>42</EventRecordID></System><EventData><Data Name='SubjectUserName'>User</Data><Data Name='SubjectDomainName'>DESKTOP</Data><Data Name='ObjectType'>File</Data><Data Name='ObjectName'>C:\Data\report.txt</Data><Data Name='AccessMask'>0x1</Data><Data Name='ProcessId'>1234</Data><Data Name='ProcessName'>C:\Windows\notepad.exe</Data></EventData></Event>`
	e, ok := Parse4663(xml)
	if !ok {
		t.Fatal("single-quoted event was not parsed")
	}
	if e.PID != 1234 || e.RecordID != 42 || e.Process != "notepad.exe" {
		t.Fatalf("unexpected event: %+v", e)
	}
}

func TestParse4663RejectsWriteOnly(t *testing.T) {
	xml := `<Event><System><EventID>4663</EventID></System><EventData><Data Name="ObjectType">File</Data><Data Name="ObjectName">C:\a.txt</Data><Data Name="AccessMask">0x2</Data></EventData></Event>`
	if _, ok := Parse4663(xml); ok {
		t.Fatal("write-only event should be ignored")
	}
}
