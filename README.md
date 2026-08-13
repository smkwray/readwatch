<div align="center">
  <img src="assets/ReadWatch-Icon.png" width="120" alt="ReadWatch"/>
  <h1>ReadWatch</h1>
  <p>Find out which processes are reading the files in a folder you care about.</p>
</div>

Point ReadWatch at a folder and it shows you, live, every process that reads a file inside it —
name, PID, full image path, and the file touched. One 2.9 MB `ReadWatch.exe`, one UAC prompt at
install, and it's running.

- **Live view and a durable log.** Text, JSON Lines, or CSV, appended as events arrive.
- **Privileged only while ReadWatch is open.** The service is demand-start: it comes up with the
  window so the viewer can read the protected configuration, and it stops when you exit — including
  when the viewer is killed rather than closed, because the service stops itself once no viewer is
  connected. **Stop** ends monitoring and removes ReadWatch's audit rules, folder handles and log
  handle; the idle service stays only while the window is open. Nothing of ReadWatch's runs as
  SYSTEM once you quit.
- **Filters the noise.** Shell thumbnailing, search indexing and antivirus can easily outnumber
  the reads you're looking for. Exclude them by process name or exact image path — dropped inside
  the service, with a running count of what was suppressed so nothing hides silently.
- **Cheap to leave running.** It's an event subscription, not a polling loop: no folder scanning,
  no timers, nothing to do between reads.

## How it works

Windows can already audit file reads — ReadWatch drives that machinery for you. It enables the
*Audit File System (success)* policy, applies a narrowly scoped audit entry (SACL) to your chosen
folders, subscribes to Security event **4663**, and turns the raw XML into a readable line.

A **LocalSystem service** owns everything privileged; a **non-elevated viewer** talks to it over a
local named pipe admitting only LocalSystem and the installing account. The service is
`SERVICE_DEMAND_START` behind a protected DACL granting that account start, stop, query and
interrogate rights and nothing else — enough for an ordinary window to run a SYSTEM service, too
little for anything on the machine to repoint it. Changing the configuration, rewriting the
descriptor and deleting the service are all withheld, including from the owner.

Your folders and log file are opened under **your** account when you press Start or Save, and the
service keeps those handles: every privileged operation goes through them rather than looking the
path up a second time, so nothing can be swapped for something else in between. Each folder is
recorded by volume and file identity, not by name.

Before/after SACL snapshots mean a folder is restored only if the live SACL is still what
ReadWatch applied, and each change is written down before it is made, so an interrupted one can be
undone on the next start. The audit policy is owned the same way.

## Build

Go 1.23+, Windows 10 1903 / Windows 11, x64.

```bat
build.cmd
```

which is `go test ./...`, `go vet ./...`, then:

```bat
go build -trimpath -ldflags "-s -w -H=windowsgui -X main.version=0.3.0" -o dist\ReadWatch.exe .\cmd\readwatch
```

`cmd/readwatch/rsrc_windows_amd64.syso` is checked in with the icon, version info and manifest, so
a plain `go build` needs only Go. Regenerating it wants Python 3 + Clang:
`python tools/make_resources.py --version 0.3.0.0`. It has not been regenerated since 0.1.0, so the
PE version resource reads `0.1.0.0` while `--version` reports the real release.

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

Closing the window hides it to the tray; **Exit** quits, stops monitoring and stops the service —
opening ReadWatch again starts idle, waiting for you to press Start. **Start ReadWatch at sign-in**
puts it in the tray on login, also idle. **Keep the window on top** is in Settings, and
hovering a row that is too narrow for its path shows the whole thing.

## Log

```text
2026-08-12 12:30:43.426 | READ | pwsh.exe | pid=32740 | HOST\user | D:\Renders\output\frame.png | exe=C:\Program Files\PowerShell\7\pwsh.exe
```

`LIST` marks a folder-listing event when that setting is on. JSONL and CSV carry the full process
path, event record ID, and access mask.

## Good to know

- Watches local folders on filesystems that support Windows auditing. For a network share, run
  ReadWatch on the file server against its local path.
- **Junctions, symbolic links, mounted volumes and cloud placeholders are refused**, at any point in
  the path — not followed. ReadWatch has to be able to prove that the folder it later applies an
  audit rule to is the folder you approved, and a link is exactly what can stop being that.
- **The folder holding your log file has to exist already.** ReadWatch writes the log with your own
  account's permissions and will create the file, but not its folder.
- Uninstalling removes everything immediately except the program file itself, which Windows deletes
  at the next restart because it is running at the time.
- **Cleanup is best-effort when a folder has gone.** ReadWatch removes its audit rule from every
  folder it applied one to. If a watched folder is deleted, or its rules are changed by something
  else, ReadWatch says so once and stops tracking it rather than refusing to continue — an
  unfinishable cleanup used to block Stop, Save and uninstall permanently. A folder that is only
  temporarily unreachable is retried, not forgotten.
- Event 4663 reports an exercised access right, not which bytes were read.
- Applying the audit entry rewrites the security descriptor of every file already in the folder —
  reversible, but not instant on a large tree.
- Antivirus, indexing, preview handlers and backup tools read files legitimately and will appear.
  That's what the exclusion list is for.
- The build is unsigned, so SmartScreen warns on first run.

Install, the demand-start lifecycle, the service DACL boundary, SACL apply/remove and 4663 capture
are exercised on Windows 11. The path-binding rules have tests that run against the real filesystem:
a junction is refused as a target and as an ancestor, a folder's identity survives a rename and
distinguishes a replacement at the same path, and a watched folder cannot be renamed while it is
held. `go vet ./...` is clean unsuppressed.

## License

MIT — see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
