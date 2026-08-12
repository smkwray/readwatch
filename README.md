<div align="center">
  <img src="assets/ReadWatch-Icon.png" width="120" alt="ReadWatch"/>
  <h1>ReadWatch</h1>
  <p>Find out which processes are reading the files in a folder you care about.</p>
</div>

Point ReadWatch at a folder and it shows you, live, every process that reads a file inside it —
name, PID, full image path, and the file touched. One 2.8 MB `ReadWatch.exe`, one UAC prompt at
install, and it's running.

- **Live view and a durable log.** Text, JSON Lines, or CSV, appended as events arrive.
- **Privileged only while you're watching.** The service starts when you hit Start and stops when
  you exit, taking its audit rules off your folders with it.
- **Filters the noise.** Shell thumbnailing, search indexing and antivirus can easily outnumber
  the reads you're looking for. Exclude them by process name or exact image path — dropped inside
  the service, with a running count of what was suppressed so nothing hides silently.
- **Cheap to leave running.** Idles at 0% CPU and ~10 MB; roughly 0.1 ms of CPU and 173 bytes of
  log per event. It's an event subscription, not a polling loop.

## How it works

Windows can already audit file reads — ReadWatch drives that machinery for you. It enables the
*Audit File System (success)* policy, applies a narrowly scoped audit entry (SACL) to your chosen
folders, subscribes to Security event **4663**, and turns the raw XML into a readable line.

A **LocalSystem service** owns everything privileged; a **non-elevated viewer** talks to it over a
local named pipe admitting only LocalSystem and the installing account. The service is
`SERVICE_DEMAND_START` behind a protected DACL granting that account exactly
`SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS` — enough for an ordinary window to run a
SYSTEM service, too little for anything on the machine to repoint it.

Before/after SACL snapshots mean a folder is restored only if the live SACL is still what
ReadWatch applied. The audit policy is owned the same way.

## Build

Go 1.23+, Windows 10 1903 / Windows 11, x64.

```bat
build.cmd
```

which is `go test ./...`, `go vet ./...`, then:

```bat
go build -trimpath -ldflags "-s -w -H=windowsgui -X main.version=0.2.0" -o dist\ReadWatch.exe .\cmd\readwatch
```

`cmd/readwatch/rsrc_windows_amd64.syso` is checked in with the icon, version info and manifest, so
a plain `go build` needs only Go. Regenerating it wants Python 3 + Clang:
`python tools/make_resources.py --version 0.2.0.0`.

## Use

1. Run `ReadWatch.exe` and approve the installation prompt.
2. **Settings** → paste a folder path (or **Browse**), pick a log file and format, **Save**.
3. **Start**.

Right-click any row to silence that process:

- **Exclude `python.exe`** matches the *image name* — every `python.exe`, anywhere.
- **Exclude only this exact path** matches that one binary.

Prefer the exact path for anything you have several copies of; a machine typically has multiple
`python.exe` installs, and a filename is easy to imitate, which matters for a tool whose job is
noticing an unexpected reader. Nothing is excluded until you say so — the list lives in Settings.

Closing the window hides it to the tray; **Exit** quits and stops the service. **Start ReadWatch
at sign-in** launches it hidden in the tray on login.

## Log

```text
2026-08-12 12:30:43.426 | READ | pwsh.exe | pid=32740 | HOST\user | D:\Renders\output\frame.png | exe=C:\Program Files\PowerShell\7\pwsh.exe
```

`LIST` marks a folder-listing event when that setting is on. JSONL and CSV carry the full process
path, event record ID, and access mask.

## Good to know

- Watches local folders on filesystems that support Windows auditing. For a network share, run
  ReadWatch on the file server against its local path.
- Event 4663 reports an exercised access right, not which bytes were read.
- Applying the audit entry rewrites the security descriptor of every file already in the folder —
  reversible, but not instant on a large tree.
- Antivirus, indexing, preview handlers and backup tools read files legitimately and will appear.
  That's what the exclusion list is for.
- The build is unsigned, so SmartScreen warns on first run.

Install, the demand-start lifecycle, the service DACL boundary, SACL apply/remove and 4663 capture
are exercised on Windows 11. Parser, log-writer, configuration and exclusion tests run portably and
under the race detector; `go vet ./...` is clean unsuppressed.

## License

MIT — see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
