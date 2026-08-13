# Changelog

## 0.3.0 — 2026-08-13

A security review found that the service validated a folder or log path as you, then later resolved
that same path again as SYSTEM. Anything able to change what the path pointed at in between could
have made SYSTEM act on a different object. Closing that changed several things you can see.

> **Upgrading from 0.1.x or 0.2.x:** stop monitoring in the old version before upgrading. The
> installer refuses to replace a copy that still has audit rules applied, because those records
> identify folders by path and cannot be undone reliably after the upgrade.

### Changed behaviour

- **Junctions, symbolic links, mounted volumes and cloud placeholders are refused** anywhere in a
  watched folder's path or its log's path, rather than followed. If a folder you watch sits behind
  one, it can no longer be watched.
- **The log file's folder must already exist.** ReadWatch creates the log file itself, with your
  account's permissions, but no longer creates directories.
- **Watched folders cannot be renamed or deleted while monitoring is on.** The audit rule and the
  folder stay together.
- Monitoring resumes when you open ReadWatch rather than when the service starts, and a folder or
  log that is no longer the same object as when you set it up is refused with a message instead of
  being used.
- Uninstall removes everything immediately except the running program file and its folder, which
  Windows deletes at the next restart.

### Security

- Folders and the log are opened under your token and held open; every privileged operation goes
  through those handles instead of re-resolving a name.
- Audit rules are read and written through the handle, preserving whether the folder's audit entries
  were protected from inheritance.
- Every audit change is journalled before it is made, identified by volume and file identity rather
  than by path, so a crash or power loss can be undone on the next start.
- The uninstaller elevates the installed program file rather than a copy staged in your Temp folder,
  and refuses to run as anything but the installed copy.
- Installation locations come from Windows rather than from environment variables an elevated
  process inherits.
- The service now stops itself when no viewer is connected, so killing ReadWatch rather than closing
  it can no longer leave a SYSTEM process behind.

## 0.2.1 — 2026-08-13

Viewer only. The service and its privilege boundary are unchanged.

> The embedded PE version resource still reports `0.1.0.0`, as in 0.2.0: regenerating
> `rsrc_windows_amd64.syso` needs Clang, which is still not available on the build machine. Only
> **--version** tracks the release.

### Features

- Hovering a cell whose text the column had to clip shows the whole string, in the event list and
  in both Settings lists. Only when it was actually clipped — a hint over text you can already read
  is noise.
- **Keep the ReadWatch window on top of other windows**, in Settings. A viewer preference: it is
  stored per user in `HKCU\Software\ReadWatch`, needs no elevation and no running service, and is
  removed on uninstall.
- Start and Stop now show `Starting…` / `Stopping…` while the command is in flight, and Save shows
  `Applying changes…`. Re-applying an audit rule across a large folder takes seconds, and the
  window used to give no sign it was working.

### Fixes

- Start and Settings stayed clickable while a command was still running, and the click was then
  discarded without a word. Both buttons, and the matching tray entries, are now held for the
  command's duration.
- A folder path typed or pasted into Settings but never **Add**ed was dropped silently by **Save**.
  It is committed now, and a **Save** that cannot proceed says so instead of doing nothing.
- `· N excluded` counted suppressed *reads* but read like a count of excluded processes. It says
  `· N reads excluded`, and **Clear** now rebases the suppressed, log-dropped and live-dropped
  counters and discards events still queued from before the clear, so the summary describes the
  span since you cleared it.
- A state update that arrived while an earlier one was being applied could be left unposted, so the
  window kept showing the previous state until something else came along.
- `tools/readwatch_resources_amd64.s` is marked `linguist-generated`; that generated file is larger
  than all the Go in the repository and GitHub was reporting the project as half Assembly.

### Known

- `comMethod` still passes pointer-bearing COM arguments through a `[]uintptr`, so the
  `unsafe.Pointer` conversion does not happen in the `syscall.SyscallN` call expression as the
  unsafe rules require. `go vet` is clean because the helper hides the conversion from it, not
  because the pattern is sound. Typed per-method wrappers are the fix.

## 0.2.0 — 2026-08-12

First revision after the preview was actually run on Windows. Several paths had never executed.

> The embedded PE version resource still reports `0.1.0.0`; only the value shown by **--version**
> tracks the release. Regenerating `rsrc_windows_amd64.syso` needs Clang, which was not available
> when this build was cut.

### Privilege lifetime

- Service is registered `SERVICE_DEMAND_START` instead of auto-start, with a protected service
  DACL granting the installing user only start, stop and query. `SERVICE_CHANGE_CONFIG`, `DELETE`,
  `WRITE_DAC` and `WRITE_OWNER` are withheld, and an `OWNER RIGHTS` ACE stops the owning account
  granting itself the rest.
- Installing no longer starts LocalSystem; exiting the viewer stops the service.
- Stopping the service now removes the SACLs and restores the audit policy. Previously it stopped
  the watcher and left both applied, so Windows kept writing 4663 events with no consumer.

### Fixes

- **IPC deadlocked on the first message and had never completed a handshake.** Both ends opened
  the pipe synchronously and then ran a reader goroutine while writing to the same handle; Windows
  serialises I/O per handle, so each side's write parked behind its own pending read. Both ends
  are now `FILE_FLAG_OVERLAPPED`, with a cancellable `ConnectNamedPipe`.
- Service hung in `STOP_PENDING` indefinitely: `CloseHandle` does not cancel a pending
  `ConnectNamedPipe`, so the accept loop never woke. Stop now completes in under a second.
- Settings could not open — `RegisterClassEx` reports a duplicate class as
  `ERROR_CLASS_ALREADY_EXISTS` (1410), and both call sites checked `ERROR_ALREADY_EXISTS` (183).
- With a demand-start service the viewer launched with no peer, and Start and Settings were both
  disabled in that state, leaving the window inert with no way out of it.
- Installing over a running viewer failed while the viewer was still shutting down normally.
- All nine `possible misuse of unsafe.Pointer` vet diagnostics resolved by typing the Windows
  interop; `build.cmd` no longer passes `-unsafeptr=false`.

### Features

- Process exclusion filtering, applied in the service before the log and before the pipe. An entry
  containing a path separator matches the full image path; otherwise it matches the image name.
  Nothing is excluded by default. Suppressed reads are counted and shown rather than silently
  dropped.
- Right-click a row to exclude that process by name or by exact path.
- Settings takes a typed or pasted folder path, validated, with quotes stripped; the exclusion
  list is editable there too.
- Exit button in the window — closing only hid it to the tray.
- Dark list header. The header is a separate control that ignores the dark theme, so it is
  custom-drawn.
- Clearer labels: "Start ReadWatch at sign-in (runs in the tray)" and "Also log reads of the folder
  itself, not just files".

## 0.1.0 — 2026-08-11

Initial native preview.

- Compact direct-Win32 light/dark UI and notification-area viewer.
- Windows service with event-driven Security event 4663 subscription.
- Multiple recursive local folder roots and entire-drive guard.
- Append-only text, JSON Lines, and CSV logs.
- Bounded owner-data live list and burst-safe event delivery.
- One-time elevated installation; normal UI launches without UAC.
- Persistent monitoring state and optional tray viewer at sign-in.
- Scoped SACL and audit-policy ownership snapshots with conservative cleanup.
- Single x64 executable with icon, version metadata, and manifest resources; no WebView2, console
  window, external runtime, or third-party Go modules.
