# ReadWatch

ReadWatch is a compact native Windows utility that records successful reads from selected local folders. It shows a bounded live view and appends processed events to a plain-text, JSON Lines, or CSV log.

This preview is deliberately small:

- one `ReadWatch.exe` contains the non-elevated UI, Windows service, installer, and uninstaller modes;
- direct Win32, COM, Service Control Manager, Windows Event Log, and security APIs;
- no WebView2, browser engine, XAML framework, PowerShell runtime, console window, database, external Go module, or separate runtime installation;
- event-driven service and UI: no filesystem scan loop, animation loop, or normal status-polling loop;
- compact native controls with system light/dark handling and per-monitor DPI awareness.

## Runtime design

The installer creates the `ReadWatchSvc` Windows service. The service owns the privileged work: it applies a narrowly scoped success-audit entry to each selected folder, subscribes to Security event 4663, filters events to the configured roots, writes the append-only log, and streams live events to the user interface.

The normal UI is not elevated. It communicates with the service through a local-only named pipe whose DACL is limited to LocalSystem and the Windows account that installed ReadWatch. Settings are validated while the service impersonates that pipe client.

ReadWatch stores exact before/after SACL snapshots. On Stop or uninstall, it restores a folder only if the current SACL is still the state ReadWatch applied; an external change is not overwritten. It follows the same ownership rule for the File System success-audit policy.

## Build

Requirements:

- Go 1.23 or later
- Windows 10 version 1903 or later, or Windows 11
- x64

From a Developer Command Prompt or ordinary Command Prompt:

```bat
build.cmd
```

Equivalent command:

```bat
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0
go test ./...
go vet -unsafeptr=false ./...
go build -trimpath -ldflags "-s -w -H=windowsgui -X main.version=0.1.0" -o dist\ReadWatch.exe .\cmd\readwatch
```

The checked-in `cmd/readwatch/rsrc_windows_amd64.syso` embeds the multi-resolution icon, version information, and application manifest, so a normal build requires only Go. Regenerating that resource object is optional and requires Python 3 plus Clang:

```text
python tools/make_resources.py --version 0.1.0.0
```

## Project layout

```text
cmd/readwatch/       Win32 UI, service, installer, audit, IPC, and event subscription
internal/eventparse/ low-allocation parser for event 4663 XML
internal/logsink/    append-only text, JSONL, and CSV writers
internal/model/      event model
internal/protocol/   named-pipe protocol
internal/settings/   persisted/private and public configuration
assets/              source icon and manifest
tools/               resource-object generator
```

## Install and use

1. Build or download `ReadWatch.exe`.
2. Double-click it and approve the one installation UAC prompt.
3. Add one or more local folders, choose the log file and format, and save.
4. Select **Start**.

The service remembers the monitoring state. If Windows restarts while ReadWatch is monitoring, monitoring resumes when the service starts. **Show tray icon at sign-in** controls the lightweight viewer; it is not required for the service to keep logging.

Closing or minimizing the main window hides it in the notification area. **Exit viewer** closes only the UI. Use **Stop** before exiting when monitoring itself should stop and the scoped audit rules should be removed.

## Log formats

The default readable log is one append-only file:

```text
2026-08-11 16:42:08.194 | READ | notepad.exe              | pid=8420   | DESKTOP\User                | C:\Docs\report.txt | exe=C:\Windows\System32\notepad.exe
```

`LIST` marks a folder-listing event when that optional setting is enabled. JSONL and CSV retain additional fields such as full process path, event record ID, and access mask.

## Limits

- Local folders only. Monitor a network share on its file server using the server's local path.
- The underlying filesystem must support Windows auditing and SACLs.
- Event 4663 indicates an exercised access right; it does not reveal which bytes or content were consumed.
- Antivirus, indexing, preview handlers, backup tools, and Explorer can legitimately appear.
- Broad roots can create large Security and application logs. Watching an entire drive is blocked.
- The running log is intentionally not rotated in this preview.
- Extreme bursts can overflow the bounded service or live-view queues; ReadWatch reports log and live-view drops separately. The Windows Security log remains the source record.
- Installation from a standard account using a different administrator's credentials is rejected. Install while signed in to the administrator account that will own the UI.
- The preview executable is not code-signed.

## Validation scope

Portable parser, log-writer, and configuration tests run on Linux and under the race detector. The complete program cross-compiles as a Windows GUI PE with embedded icon, version information, and manifest resources. Native Windows service, SACL, Security-log, tray, and dialog paths require final execution on Windows and were not runtime-tested in the build container.
