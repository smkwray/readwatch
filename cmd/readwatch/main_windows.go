//go:build windows

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

var (
	version                 = "dev"
	expectedInstallOwnerSID string
)

func main() {
	setLeanRuntime()
	args := os.Args[1:]
	quiet := hasArg(args, "--quiet")

	if hasArg(args, "--service") {
		if err := runServiceDispatcher(); err != nil {
			writeServiceDiagnostic(err)
		}
		return
	}

	// Win32 windows, shell dialogs, and COM apartment calls stay on one OS thread.
	runtime.LockOSThread()

	var err error
	switch {
	case hasArg(args, "--install-elevated"):
		expectedInstallOwnerSID = argValue(args, "--owner-sid")
		if !isElevated() {
			err = fmt.Errorf("installation requires administrator permission")
		} else {
			err = installApp()
		}
	case hasArg(args, "--install"):
		err = installApp()
	case hasArg(args, "--uninstall-elevated"):
		err = uninstallElevated(quiet)
	case hasArg(args, "--uninstall"):
		err = beginUninstall(quiet)
	case hasArg(args, "--startup"):
		err = RunUI(true)
	case hasArg(args, "--installed"):
		err = RunUI(false)
	case hasArg(args, "--version"):
		messageBox(0, "ReadWatch "+version, appName, MB_OK|MB_ICONINFORMATION)
	case hasArg(args, "--help") || hasArg(args, "-h") || hasArg(args, "/?"):
		messageBox(0, "ReadWatch monitors successful reads from selected local folders.\r\n\r\nRun the downloaded app to install it, then use Settings to choose folders and a log file.", appName, MB_OK|MB_ICONINFORMATION)
	default:
		err = runDefaultMode()
	}

	if err != nil && !quiet {
		messageBox(0, err.Error(), appName, MB_OK|MB_ICONERROR)
	}
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if strings.EqualFold(arg, want) {
			return true
		}
	}
	return false
}

func argValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if strings.EqualFold(args[i], name) {
			return args[i+1]
		}
	}
	return ""
}

func runDefaultMode() error {
	if executableIsInstalled() {
		return RunUI(false)
	}
	if _, err := os.Stat(paths().Exe); err == nil {
		return launch(paths().Exe, "--installed")
	}
	answer := messageBox(
		0,
		"Install ReadWatch on this PC?\r\n\r\nOne administrator approval is needed now. After installation, ReadWatch starts and runs without recurring UAC prompts.",
		appName,
		MB_YESNO|MB_ICONINFORMATION,
	)
	if answer != IDYES {
		return nil
	}
	return installApp()
}
