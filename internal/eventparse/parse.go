package eventparse

import (
	"html"
	"strconv"
	"strings"
	"time"

	"readwatch/internal/model"
)

// Parse4663 parses the compact set of fields ReadWatch uses from EvtRender XML.
// It deliberately avoids a general XML decoder to keep allocations low on busy folders.
func Parse4663(s string) (model.Event, bool) {
	if !strings.Contains(s, "<EventID>4663</EventID>") || data(s, "ObjectType") != "File" {
		return model.Event{}, false
	}

	mask64, err := parseWindowsNumber(data(s, "AccessMask"), 32)
	if err != nil || uint32(mask64)&0x1 == 0 { // FILE_READ_DATA / FILE_LIST_DIRECTORY
		return model.Event{}, false
	}

	path := data(s, "ObjectName")
	if path == "" {
		return model.Event{}, false
	}

	pid64, _ := parseWindowsNumber(data(s, "ProcessId"), 32)
	procPath := data(s, "ProcessName")
	domain := data(s, "SubjectDomainName")
	name := data(s, "SubjectUserName")
	user := name
	if domain != "" && domain != "-" {
		user = domain + `\` + name
	}

	when, _ := time.Parse(time.RFC3339Nano, attr(s, "<TimeCreated", "SystemTime"))
	recordID, _ := strconv.ParseUint(strings.TrimSpace(tag(s, "EventRecordID")), 10, 64)

	return model.Event{
		Time:        when,
		RecordID:    recordID,
		Path:        path,
		ProcessPath: procPath,
		Process:     windowsBase(procPath),
		PID:         uint32(pid64),
		User:        user,
		UserSID:     data(s, "SubjectUserSid"),
		LogonID:     data(s, "SubjectLogonId"),
		HandleID:    data(s, "HandleId"),
		AccessMask:  uint32(mask64),
	}, true
}

func parseWindowsNumber(value string, bits int) (uint64, error) {
	value = strings.TrimSpace(value)
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		value = value[2:]
		base = 16
	}
	return strconv.ParseUint(value, base, bits)
}

func data(s, name string) string {
	for _, quote := range []byte{'"', '\''} {
		needle := "Name=" + string(quote) + name + string(quote) + ">"
		start := strings.Index(s, needle)
		if start < 0 {
			continue
		}
		start += len(needle)
		end := strings.Index(s[start:], "</Data>")
		if end < 0 {
			return ""
		}
		return html.UnescapeString(s[start : start+end])
	}
	return ""
}

func tag(s, name string) string {
	open := "<" + name + ">"
	close := "</" + name + ">"
	start := strings.Index(s, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(s[start:], close)
	if end < 0 {
		return ""
	}
	return s[start : start+end]
}

func attr(s, elementPrefix, name string) string {
	start := strings.Index(s, elementPrefix)
	if start < 0 {
		return ""
	}
	end := strings.IndexByte(s[start:], '>')
	if end < 0 {
		return ""
	}
	fragment := s[start : start+end]
	for _, quote := range []byte{'"', '\''} {
		needle := name + "=" + string(quote)
		p := strings.Index(fragment, needle)
		if p < 0 {
			continue
		}
		p += len(needle)
		q := strings.IndexByte(fragment[p:], quote)
		if q < 0 {
			return ""
		}
		return html.UnescapeString(fragment[p : p+q])
	}
	return ""
}

func windowsBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
