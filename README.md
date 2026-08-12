<div align="center">
  <img src="assets/ReadWatch-Icon.png" width="120" alt="ReadWatch"/>
  <h1>ReadWatch</h1>
  <p>Find out which processes are reading the files in a folder you care about.</p>
</div>

Point ReadWatch at a folder and it tells you, live, every process that reads a file inside it —
name, PID, full image path, and the file touched. A single 2.8 MB `ReadWatch.exe` with no
installer bundle, no runtime to install, and no third-party Go modules.

- **Nothing privileged runs unless you're watching.** The Windows service is demand-start. Exit
  the app and the service stops, the audit rules come off your folders, and no LocalSystem
  process is left behind.
- **No repeated UAC.** One approval at install. After that the ordinary, non-elevated window
  starts and stops the service on its own.
- **Filters the noise that makes this unusable otherwise.** On a normal desktop, a real sampled
  sample from a watched folder was 24 `explorer.exe` + 17 `viewer.exe` + **one** genuine read —
  Explorer re-thumbnails its Recent list even with no window open. Background readers are
  excluded in the service before they cost anything, and the suppressed count stays on screen so
  nothing is hidden silently.
- **Effectively free.** Measured: **0% CPU** when nothing is reading, **0.1 ms of CPU per event**,
  173 bytes of log per event, ~10 MB resident. It is an event subscription, not a polling loop.

## How it works

Windows can already audit file reads; almost nobody turns it on because the results are
unreadable. ReadWatch drives that machinery for you: it enables the *Audit File System (success)*
policy, applies a narrowly scoped audit entry (SACL) to the folders you choose, subscribes to
Security event **4663**, and turns the raw XML into a readable line.

Two parts:

- a **LocalSystem service** that owns everything privileged — audit policy, SACLs, the event
  subscription, the log; and
- a **non-elevated viewer** that talks to it over a local named pipe whose DACL admits only
  LocalSystem and the account that installed ReadWatch.

The service is registered `SERVICE_DEMAND_START` with a protected DACL that grants the installing
user exactly `SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS` — and withholds
`SERVICE_CHANGE_CONFIG`, `DELETE`, `WRITE_DAC` and `WRITE_OWNER`, with an `OWNER RIGHTS` ACE so
the owning account cannot grant itself the rest. That is the boundary that lets an unprivileged
window start a SYSTEM service without also letting any other medium-integrity process on the
machine rewrite its image path.

ReadWatch keeps exact before/after SACL snapshots and restores a folder **only** if the live SACL
is still the state it applied, so an external change is never overwritten. The audit policy is
owned the same way.

## Build

Go 1.23+, Windows 10 1903 / Windows 11, x64.

```bat
build.cmd
```

which is:

```bat
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0
go test ./...
go vet ./...
go build -trimpath -ldflags "-s -w -H=windowsgui -X main.version=0.1.0" -o dist\ReadWatch.exe .\cmd\readwatch
```

`cmd/readwatch/rsrc_windows_amd64.syso` is checked in and embeds the icon, version info and
manifest, so a plain `go build` needs nothing but Go. Regenerating it is optional and wants
Python 3 + Clang: `python tools/make_resources.py --version 0.1.0.0`.

## Use

1. Run `ReadWatch.exe` and approve the single installation prompt.
2. **Settings** → paste a folder path (or **Browse**), pick a log file and format, **Save**.
3. **Start**.

Right-click any row to stop hearing from that process again:

- **Exclude `python.exe`** matches the *image name*, so every `python.exe` anywhere is silenced.
- **Exclude only this exact path** matches that one binary.

Prefer the exact path for anything you have several copies of — a machine typically has multiple
`python.exe` installs, and a filename is trivially spoofable, which matters for a tool whose job
is noticing an unexpected reader. `explorer.exe`, `SearchIndexer.exe`, `MsMpEng.exe` and
`viewer.exe` are excluded by name out of the box; edit the list in Settings.

Closing the window hides it to the tray. **Exit** quits and stops the service with it.
**Start ReadWatch at sign-in** launches it hidden in the tray on login.

## Log

```text
2026-08-12 12:30:43.426 | READ | pwsh.exe | pid=32740 | HOST\user | D:\Renders\output\frame.png | exe=C:\Program Files\PowerShell\7\pwsh.exe
```

Plain text, JSON Lines, or CSV. `LIST` marks a folder-listing event when that setting is on. JSONL
and CSV carry extra fields — full process path, event record ID, access mask.

## Limits

- Local folders only. To watch a network share, run ReadWatch on the file server against its local path.
- The filesystem must support Windows auditing and SACLs.
- Event 4663 reports an *exercised access right*, not which bytes were consumed.
- Applying an inheritable audit entry rewrites the security descriptor of every file already in
  the folder. Reversible, but not instant on a large tree.
- Antivirus, indexing, preview handlers, backup tools and Explorer legitimately appear. That is
  what the exclusion list is for.
- Broad roots produce large Security logs. Watching an entire drive is refused.
- The log is not rotated.
- Extreme bursts can overflow the bounded service and live-view queues; drops are counted and
  reported separately. The Windows Security log remains the source record.
- Install while signed in to the administrator account that will own the viewer.
- Not code-signed, so SmartScreen will warn on first run.
- If the service is killed rather than stopped, cleanup does not run and the audit entries stay
  applied until it next starts. Stopping normally always removes them.

## Validation

`go vet ./...` runs unsuppressed and clean. Portable parser, log-writer, configuration and
process-exclusion tests run on Linux and under the race detector.

Install, the demand-start lifecycle, the service DACL boundary (medium-integrity start/stop
allowed, reconfigure denied), SACL apply/remove, 4663 capture and log output have been exercised
on Windows 11. The tray, dialogs and per-monitor DPI paths have not been systematically tested.

## License

MIT — see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
