# Changelog

## Unreleased

**ReadWatch can now watch drives it previously refused, including exFAT USB sticks.** It has two
ways of detecting reads and picks between them, because neither is better than the other in every
case.

Watched folders may also live on drives that are not always attached — a USB stick, a card reader.
Before this, one unreachable folder stopped monitoring for every folder, and a path on a drive that
was out could not even be added.

### Two ways of detecting reads

- **Audit markers** — the original mechanism. ReadWatch marks the watched folders, so only those
  folders produce events. Switching a marker on and off costs about a tenth of a millisecond per
  file: imperceptible for an ordinary folder, minutes for a whole drive. Sees a read made through a
  memory mapping. Cannot be used on exFAT or FAT, which is how most USB sticks ship.
- **Event tracing** — new. Writes nothing to the drives and starts instantly on any of them,
  including exFAT and encrypted volumes. It watches the whole machine's file activity and discards
  what was not asked for, which costs a little CPU continuously. Does not report a read made purely
  through a memory mapping.
- **ReadWatch chooses**, unless told otherwise: markers when every watched folder can carry one,
  event tracing when any folder cannot. Never both at once — an event-tracing session already
  reports reads on volumes that could carry a marker, so running both would report those reads
  twice. A folder whose drive is out does not influence the choice.
- The window's summary names the mechanism in use. If you asked for markers and a watched folder
  made that impossible, ReadWatch says so rather than quietly running the other one.
- Settings offers the choice, with what each option costs and what each can see written next to it.
- **Event tracing names files that were already open when you pressed Start.** Windows only offers
  that list when a trace session ends, so ReadWatch runs a short one during startup purely to
  collect it — about a second. Without it, a program holding a file open before monitoring began
  would have gone unattributed for the whole run, which is exactly the reader worth noticing.
- **What event tracing cannot do, it says rather than silently skips.** Folder listings are
  unavailable while it runs, and the window says so. A read whose process cannot be identified with
  certainty — a short-lived reader that has already exited, whose process id Windows has since given
  to something else — is reported with the process left blank rather than named wrongly.

### Removed

- **Event tracing no longer reads other programs' security tokens.** It supplied only the User
  column, and ReadWatch's job is to name the *process*. Under event tracing that column is now
  blank; audit markers still report the user. Removing it takes out the most surveillance-shaped
  thing the program did for the least of what it exists to tell you.

### Known issue: antivirus

- **Windows Defender may flag an event-tracing build and remove it.** Classified
  `Trojan:Win32/Bearfoos.A!ml` on an unsigned build about ten seconds after install. The three
  things that draw it — a machine-wide kernel file-trace session, enumerating every open file at
  startup, and opening other processes' tokens to name a reader — are what the feature is. The
  audit-marker path has never been flagged. The README says where each lives and how to allow it.

### Changed behaviour

- **A folder on an exFAT or FAT drive can now be watched.** It is watched with event tracing, since
  no audit rule can attach to such a volume. One limitation comes with it, and ReadWatch cannot
  avoid it: those filesystems record no durable identity for a folder, so ReadWatch can tell that a
  path now points at a *different drive*, but cannot tell that a folder was deleted and recreated at
  the same path on the same drive. On NTFS and ReFS the full check is unchanged.
- **A folder on a drive that is not attached can be added.** Settings checks the shape of the path,
  the same way the service does, and no longer requires the folder to exist.
- **One unreachable folder no longer stops the others.** Each configured folder is now reported
  individually as watched, waiting for its drive, or not watched with the reason. Start, Save, Stop
  and the resume on reconnect all continue with whatever is reachable.
- **Drives are picked up when they arrive.** ReadWatch notices a volume appearing or leaving and
  asks the service to bind again. If monitoring was on but nothing was reachable, a drive arriving
  starts it.
- **A folder that has been substituted is refused on its own** instead of failing the whole start.
  Open Settings and Save to authorise the folder that is at the path now.
- **Nothing reachable means monitoring stays off**, rather than enabling the machine-wide audit
  policy with no folder carrying a rule.
- Mapped network drives are refused with a message that says so, instead of failing with a raw
  Windows error.
- The window's summary line reports the breakdown: `3 folders (1 waiting for a drive) · 412 events`.

### Fixed

- **An unplugged drive no longer made ReadWatch forget the audit rule it left on it.** Measured: an
  unattached volume fails with `ERROR_FILE_NOT_FOUND`, which the code treated as "this object is gone
  for good" — so the journal record was deleted while the rule was still on the disk. The two cases
  are now told apart by which of the two opens failed rather than by the error number. A folder that
  is genuinely gone reports `ERROR_INVALID_PARAMETER`, and only that answer forgets a record;
  anything else keeps it. `cmd/readwatch/removable_test.go` holds both measurements.
- A rule that cannot be removed because its drive is out is kept, counted and named in the window,
  and uninstall now says which drive to attach rather than refusing with no explanation.
- Uninstall re-reads the configuration after cleanup, so its fail-closed check no longer tests a copy
  loaded before the cleanup ran.
- The handles a watched folder was applied through are no longer trusted blindly at removal time: if
  the handle has stopped working, the object is reopened by identity, which is what can tell an
  unplugged drive from a deleted folder.
- Restoring the previous configuration after a failed Save no longer closes the handles it just
  reinstated.
- The exclusion list is copied rather than shared when the configuration is cloned, closing a race
  with the state the window is sent.

### Security

- **An event-tracing session is cleared whenever ReadWatch gets the chance.** Such a session is a
  Windows object that keeps running even if the program that created it is killed, so a service that
  was force-killed could otherwise leave one running with nothing consuming it. ReadWatch clears any
  session of its own at service start, at monitoring start and at uninstall, by name, so it can
  never stop a session belonging to another program.
- **Event tracing is only allowed to relax the folder identity check where the filesystem offers no
  identity at all**, and only because it writes nothing to the volume and so has nothing it must
  find again to undo. Audit markers still refuse such a volume outright, and so does the log file.
- A folder that could not be opened keeps the identity it was last authorised with. Without this,
  skipping an unreachable folder would have erased its recorded identity, and an unrecorded folder is
  treated as one being authorised for the first time — so the next volume to claim that drive letter
  would have been watched, and given an audit rule by LocalSystem, with nobody deciding.
- Only a Save from Settings authorises what a watched path means. A refresh caused by a drive
  arriving does not, nor does the right-click process exclusion, nor the sign-in rollback. The
  service enforces this rather than trusting the sender: an apply that does not claim to be an owner
  decision is refused outright if it would change the watched folders or the log file.
- An audit record is forgotten only when the volume is attached and the object is provably not on
  it. An access denial, a filter, or any other indeterminate failure keeps the record and reports it,
  because Windows returns access-denied for an object that still exists but is pending deletion —
  reading that as absence would discard the only record of a rule still applied.
- Uninstall abandons a rule only when the drive is provably not attached. Any other reason a volume
  cannot be opened now blocks uninstall and names the folder, rather than telling the owner a drive
  is unplugged when it may not be.
- Failures to withdraw a privileged change are reported instead of being logged and passed over. A
  stop that could not restore the machine-wide audit policy no longer reports success.

## 0.3.0 — 2026-08-13

A security review found that the service validated a folder or log path as you, then later resolved
that same path again as SYSTEM. Anything able to change what the path pointed at in between could
have made SYSTEM act on a different object. Closing that changed several things you can see.

> **Upgrading from 0.1.x or 0.2.x:** stop monitoring in the old version before upgrading. The
> installer refuses to replace a copy that still has audit rules applied, because those records
> identify folders by path and cannot be undone reliably after the upgrade.

### Removed

- **Event tracing no longer reads other programs' security tokens.** It supplied only the User
  column, and ReadWatch's job is to name the *process*. Under event tracing that column is now
  blank; audit markers still report the user. Removing it takes out the most surveillance-shaped
  thing the program did for the least of what it exists to tell you.

### Known issue: antivirus

- **Windows Defender may flag an event-tracing build and remove it.** Classified
  `Trojan:Win32/Bearfoos.A!ml` on an unsigned build about ten seconds after install. The three
  things that draw it — a machine-wide kernel file-trace session, enumerating every open file at
  startup, and opening other processes' tokens to name a reader — are what the feature is. The
  audit-marker path has never been flagged. The README says where each lives and how to allow it.

### Changed behaviour

- **Junctions, symbolic links, mounted volumes and cloud placeholders are refused** anywhere in a
  watched folder's path or its log's path, rather than followed. If a folder you watch sits behind
  one, it can no longer be watched.
- **The log file's folder must already exist.** ReadWatch creates the log file itself, with your
  account's permissions, but no longer creates directories.
- **Watched folders cannot be renamed or deleted while monitoring is on.** The audit rule and the
  folder stay together.
- **Exit stops monitoring**, it does not pause it. Opening ReadWatch again starts idle and waits for
  Start, rather than resuming what was running when you quit. A folder or log that is no longer the
  same object as when you set it up is refused with a message instead of being used.
- Uninstall removes everything immediately except the running program file and its folder, which
  Windows deletes at the next restart.
- Cleanup is best-effort when the target has gone: a deleted watched folder, or one whose rules were
  changed elsewhere, is reported once and forgotten rather than blocking Stop, Save and uninstall
  forever. A temporarily unreachable folder is retried instead.

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
