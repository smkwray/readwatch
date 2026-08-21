<div align="center">
  <img src="assets/ReadWatch-Icon.png" width="120" alt="ReadWatch"/>
  <h1>ReadWatch</h1>
  <p>See which programs are reading the files in a folder you care about.</p>
</div>

**What it does, and what it does not.** ReadWatch records file reads under folders you choose. How
much it can tell you depends on which of two Windows mechanisms it is using, and it will tell you
which one is running:

| | Audit markers | Event tracing |
| --- | --- | --- |
| Which program read the file | yes | yes |
| Which user account | yes | **no** — the column is blank |
| Folder listings | yes, if you enable it | **no** — the setting is unavailable |
| Reads through a memory mapping | yes | **no** |
| Works on exFAT or FAT | **no** | yes |
| What it costs | marks every file in the watched folders when monitoring starts | watches the whole machine's file activity and discards the rest |

**ReadWatch is not a complete audit log and not a security boundary.** Neither mechanism captures
everything, and it should not be the only evidence that a particular person opened a particular
file.

**One mechanism runs at a time, for every watched folder.** ReadWatch picks it, and a single folder
that cannot take a marker — an exFAT USB stick, say — puts *all* your folders on event tracing,
including the NTFS ones. That is why adding one folder can change what the others report.

> ### Before you install
>
> The downloadable build is **not code-signed**, so Windows cannot verify who published it, and
> **your antivirus may quarantine it**. Microsoft Defender classified an earlier build as
> `Trojan:Win32/Bearfoos.A!ml` and deleted it. That detection has not been reviewed by Microsoft, so
> this project does **not** claim it was a false positive.
>
> Do not turn off real-time protection or add a broad antivirus exclusion in order to run this. If
> you are not comfortable running an unsigned tool that does what this one does, build it yourself
> from source — it needs nothing but Go.

## What you get

- **Live view and a durable log.** Text, JSON Lines, or CSV, appended as events arrive.
- **Privileged only while ReadWatch is open.** The service is demand-start: it comes up with the
  window and stops when you exit, including when the viewer is killed rather than closed. **Stop**
  ends monitoring and removes ReadWatch's audit rules, folder handles and log handle.
- **Filters the noise.** Thumbnailing, indexing and antivirus can outnumber the reads you want.
  Exclude them by process name or exact image path, with a running count of what was suppressed so
  nothing hides silently.
- **Drives that come and go.** A folder on a USB stick can be added while the drive is out; it is
  watched whenever the drive is there and reported as waiting when it isn't.
- **Gaps are recorded, not hidden.** When reads are missed — the machine too busy, a name that
  could not be resolved — the log gets a `GAP` line saying how many and why.

## How it works

Windows offers two quite different ways to find out who read a file. Neither is better in every
case, so ReadWatch uses both and picks.

**1. Folder audit markers.** ReadWatch asks Windows to record access to a watched folder, by adding
an audit entry to that folder's security settings — a *SACL* — and switching on the *Audit File
System (success)* policy. Windows then writes a Security-log record for each matching read, and
ReadWatch turns those into readable lines. Only your watched folders produce anything. Marking costs
about a tenth of a millisecond per file when monitoring starts and again when it stops: instant for
an ordinary folder, minutes for a whole drive. **exFAT and FAT have no security settings for a
marker to live in**, which is why they cannot use this.

**2. System file-I/O tracing.** ReadWatch runs a Windows kernel trace of file activity — an *ETW*
session — and keeps only the events under your folders. Nothing is written to the drive and it works
on any filesystem, including exFAT and encrypted volumes. The trade is that Windows cannot filter it
by folder, so ReadWatch sees the whole machine's file activity and discards what you did not ask
for. That costs a little CPU continuously whether you watch one folder or twenty.

At startup it also spends about a second listing the files already open on the PC. Without that,
Windows will not tell it the name of a file whose handle was already open, and reads of those files
would go unattributed for as long as monitoring ran.

**3. One mechanism at a time.** ReadWatch uses markers when *every* watched folder can carry one,
and tracing when any folder cannot. Never both — a tracing session already reports reads on folders
that could carry a marker, so running both would report the same read twice. You can force either
from Settings; if you ask for markers and a folder makes that impossible, ReadWatch says so rather
than silently doing the other thing. The window names the mechanism in use.

**4. Switching.** Changing folders can change the mechanism. ReadWatch removes every marker it
applied and hands back the audit-policy change before starting a tracing session, and the reverse
going the other way.

## Privileges and privacy

A **LocalSystem service** owns everything privileged; a **non-elevated viewer** talks to it over a
local named pipe admitting only LocalSystem and the installing account. The service is
`SERVICE_DEMAND_START` behind a DACL granting that account start, stop, query and interrogate and
nothing else — enough for an ordinary window to run a SYSTEM service, too little for anything on the
machine to repoint it. Changing the configuration, rewriting the descriptor and deleting the service
are withheld, including from the owner.

Your folders and log file are opened under **your** account when you press Start or Save, and the
service keeps those handles: every privileged operation goes through them rather than resolving the
path a second time, so nothing can be swapped in between. Each folder is recorded by volume and file
identity, not by name.

**ReadWatch sends nothing anywhere.** There is no network code in it — no connections, no telemetry,
no update check. Everything it records stays in the log file you chose.

Under event tracing it does see file activity from the whole machine before discarding what is not
yours. Those events are not written anywhere and not kept; only reads under your watched folders
reach the log or the window.

### What it records about a read

The time, the file path, the program's name and full image path, its process ID, and how many bytes
were transferred. Under audit markers, also the user account and the access mask. **Under event
tracing the user column is blank** — naming the account means opening other programs' security
tokens, which is more than this tool needs to name the *program*.

If a program has already exited by the time ReadWatch looks it up, the process fields are left blank
rather than guessed at: Windows reuses process IDs, and naming the wrong program is worse than
naming none.

### On exFAT and FAT

Those filesystems record no durable identity for a folder, so a folder there is remembered by volume
only. ReadWatch can still tell that a path now points at a **different drive**; it cannot tell that a
folder was deleted and recreated at the same path on the same drive. That reduction is accepted only
under tracing, which writes nothing to the volume and so has nothing it must find again to undo.

Two limits worth being exact about:

- **This is replacement detection, not media authentication.** ReadWatch trusts what the Windows
  storage stack reports. The volume serial is assigned by Windows at format time, not burned into the
  hardware, so a deliberately cloned volume is not something it can distinguish.
- **The junction check trusts the filesystem driver.** ReadWatch refuses to follow a junction or
  symbolic link into a watched folder. On a volume that reports it cannot hold one, that check is
  skipped, and an object claiming otherwise there is refused rather than reconciled. A hostile
  *kernel* driver could lie about both, but one at that level can defeat ReadWatch far more directly.

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

### Removable drives

A watched folder does not have to be on a drive that is always attached. Paste the path while the
drive is out and ReadWatch writes it down; the summary line then reads *"2 folders (1 waiting for a
drive)"* until it turns up. Plug the drive in and ReadWatch picks the folder up on its own — it
watches for volumes arriving and asks the service to look again, so there is nothing to press.

A folder that ReadWatch will not watch, as opposed to one it is waiting for, is called out in the
status line with the reason: a junction, a permission you don't have, a network drive, or a path
that now refers to a different folder than the one you approved. Those need you; a waiting folder
does not, which is why it never becomes a warning.

**Press Stop before you eject.** ReadWatch holds each watched folder open on purpose — that is what
stops it being renamed away from its own audit rule — so Safely Remove Hardware will refuse while
the folder is being watched. Stop, then eject the drive the normal way.

If a drive is disconnected without that, ReadWatch is built to recover rather than to break: the
folders on other drives keep being watched. But **the audit rule stays on the disconnected disk**,
because nothing can reach it to remove it. ReadWatch says so in the summary line, keeps the record,
and removes the rule when that drive is next attached. It will not quietly forget it — uninstalling
with such a rule outstanding tells you which drive to attach rather than abandoning it silently.

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

## Requirements

- **Windows 11** on x64. Developed and exercised on Windows 11 Pro 26200. Windows 10 is untested.
- **Administrator once, at install and at uninstall.** Never during ordinary use.
- Watches local folders. For a network share, run ReadWatch on the file server against its local
  path.
- Event tracing needs no particular filesystem. Audit markers need NTFS or ReFS.

## Uninstalling

Removes the service, the viewer, the Start Menu entry, the uninstall entry and everything in
`C:\ProgramData\ReadWatch`, and withdraws every audit rule and audit-policy change ReadWatch
applied. **Your log file is left alone** — it is yours.

The program file itself cannot delete itself while it is running, so Windows removes it and its
folder at the next restart. ReadWatch tells you so.

If a watched drive is not attached, the audit rule on it cannot be withdrawn. Uninstall says which
drive to plug in rather than abandoning the rule silently.

## Good to know

- **Junctions, symbolic links, mounted volumes and cloud placeholders are refused**, at any point in
  the path — not followed. ReadWatch has to be able to prove that the folder it applies an audit rule
  to is the folder you approved, and a link is exactly what can stop being that.
- **The folder holding your log file has to exist already.** ReadWatch creates the file with your own
  account's permissions, but not its folder. The log is never rotated or trimmed — it grows until you
  do something about it.
- **Cleanup is best-effort when a folder has gone.** If a watched folder is deleted, or its rules are
  changed by something else, ReadWatch says so once and stops tracking it rather than refusing to
  continue. A folder whose *drive* is merely unplugged is a different case and is kept, counted and
  named until the drive returns.
- **Nothing to watch is not an error.** If every configured folder is on a drive that is out,
  monitoring stays off rather than switching the machine-wide audit policy on with no folder carrying
  a rule. It starts by itself when a drive arrives.
- Applying an audit entry rewrites the security descriptor of every file already in the folder —
  reversible, but not instant on a large tree.
- Antivirus, indexing, preview handlers and backup tools read files legitimately and will appear.
  That is what the exclusion list is for.
- Under audit markers, event 4663 reports an exercised access right, not which bytes were read.
- The build is unsigned, so SmartScreen warns on first run.

## What has not been qualified

Stated as unqualified rather than assumed to work:

- **A physical removable-drive disconnect** while ReadWatch holds the folder open. The Windows error
  codes it turns on are measured on the development host and held in place by tests; the unplug
  itself has not been run.
- **Uninstall while audit markers are applied.** Uninstall from an idle service is tested and passes.
- **Encrypted volumes such as VeraCrypt.**
- **Memory-mapped reads.** Not reported under event tracing. How much that misses in practice has not
  been measured against the audit-marker path.
- **Reads served from cache**, in one narrow case: a read issued immediately after writing the same
  file, in the same program, produced no event. A re-read through a fresh handle does. Whether the
  narrow case generalises is not established.
- **ReFS.** Claimed to work, never run on one.
- Sleep, resume, and a full disk.

What *is* exercised on Windows 11: install and uninstall, the demand-start lifecycle, the killed-
viewer teardown, the service DACL boundary, applying and removing audit rules, 4663 capture, event
tracing end to end on an exFAT stick including reads of a file opened before monitoring started, and
switching mechanism in both directions. The path-binding rules run against the real filesystem: a
junction is refused as a target and as an ancestor, a folder's identity survives a rename and
distinguishes a replacement at the same path, and a watched folder cannot be renamed while held.
`gofmt`, `go vet ./...` unsuppressed, and `go test ./...` are clean.

## License

MIT — see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
