# Changelog

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
