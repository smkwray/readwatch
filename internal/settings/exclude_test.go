package settings

import "testing"

func TestExcludes(t *testing.T) {
	list := []string{"explorer.exe", `C:\Program Files\Vendor\Suite\viewer.exe`, "  ", "MsMpEng.EXE"}
	cases := []struct {
		name      string
		imagePath string
		imageName string
		want      bool
	}{
		{"image name matches", `C:\Windows\explorer.exe`, "explorer.exe", true},
		{"image name is case insensitive", `C:\Windows\Explorer.EXE`, "Explorer.EXE", true},
		{"entry case is ignored", `C:\x\MsMpEng.exe`, "MsMpEng.exe", true},
		{"full path entry matches that path", `C:\Program Files\Vendor\Suite\viewer.exe`, "viewer.exe", true},
		{"full path entry does not match same name elsewhere", `C:\Temp\viewer.exe`, "viewer.exe", false},
		{"unrelated reader is kept", `C:\App\myapp.exe`, "myapp.exe", false},
		{"name derived from path when name is absent", `C:\Windows\explorer.exe`, "", true},
		{"blank entries are ignored", `C:\App\a.exe`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Excludes(list, tc.imagePath, tc.imageName); got != tc.want {
				t.Fatalf("Excludes(%q, %q) = %v, want %v", tc.imagePath, tc.imageName, got, tc.want)
			}
		})
	}
	if Excludes(nil, `C:\Windows\explorer.exe`, "explorer.exe") {
		t.Fatal("an empty list must suppress nothing")
	}
}

func TestNormalizeDedupesExclusionsAndKeepsEmptyEmpty(t *testing.T) {
	c := Config{ExcludedProcesses: []string{"explorer.exe", "EXPLORER.EXE", " viewer.exe ", ""}}
	c.Normalize()
	if len(c.ExcludedProcesses) != 2 {
		t.Fatalf("want 2 entries after dedupe, got %d: %v", len(c.ExcludedProcesses), c.ExcludedProcesses)
	}
	// Clearing the list must stick: it means "show me everything", not "reseed".
	c.ExcludedProcesses = nil
	c.Normalize()
	if len(c.ExcludedProcesses) != 0 {
		t.Fatalf("cleared list was refilled: %v", c.ExcludedProcesses)
	}
}

func TestPublicRoundTripCarriesExclusions(t *testing.T) {
	c := Default(`C:\logs\r.log`, "S-1-5-21-1", "u")
	// Nothing is excluded until the user says so: which readers count as noise
	// depends on the machine, not on the tool.
	if len(c.ExcludedProcesses) != 0 {
		t.Fatalf("a fresh config must exclude nothing, got %v", c.ExcludedProcesses)
	}
	pub := c.Public()
	pub.ExcludedProcesses = append(pub.ExcludedProcesses, "notepad.exe")
	var target Config
	target.ApplyPublic(pub)
	if !Excludes(target.ExcludedProcesses, `C:\W\notepad.exe`, "notepad.exe") {
		t.Fatal("exclusion added through PublicConfig did not survive ApplyPublic")
	}
	if Excludes(target.ExcludedProcesses, `C:\Windows\explorer.exe`, "explorer.exe") {
		t.Fatal("nothing beyond the added entry should be excluded")
	}
}
