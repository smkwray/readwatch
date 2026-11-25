<div align="center">
  <img src="assets/ReadWatch-Icon.png" width="120" alt="ReadWatch"/>
  <h1>ReadWatch</h1>
  <p>See which programs are reading the files in a folder you care about.</p>
</div>

ReadWatch is a Windows 11 utility that records which programs read files inside folders you choose. It shows each read in a live window and appends it to a log file in text, JSON Lines, or CSV format. It is a native Win32 program written in Go, with no runtime dependencies and no network code. The current release is 0.4.0, and the download is not signed (see [Before you install](#before-you-install)).

Windows has two ways to report file reads, and they tell you different things. ReadWatch uses folder audit markers when every watched folder can carry one, and Event Tracing for Windows (ETW) when any folder cannot, such as a folder on an exFAT USB stick. One mechanism runs at a time for all watched folders, so adding one exFAT folder moves your NTFS folders to event tracing too. The window names the mechanism in use, and Settings lets you force either one.

| | Audit markers | Event tracing |
| --- | --- | --- |
| Which program read the file | yes | yes |
| Which user account | yes | no |
| Folder listings | yes, if you turn it on | no |
| Reads through a memory mapping | yes | no |
| exFAT and FAT drives | cannot be used | yes |
| What it costs | marks the files already in the folder when monitoring starts | watches the whole machine's file activity and discards the rest |

Files created after monitoring starts are watched either way.

Neither mechanism captures every read, so ReadWatch is not a complete audit log or a security boundary. Do not treat it as the only evidence that a particular person opened a particular file.

> ### Before you install
>
> There is no signed download. Windows cannot verify who published this, and your antivirus may quarantine it: Microsoft Defender classified an earlier build as `Trojan:Win32/Bearfoos.A!ml` and deleted it. Microsoft has not reviewed that detection, so this project does not claim it was a false positive. To report which program read a file, ReadWatch runs a kernel file-trace session, lists the files already open on the PC, and opens other processes to read their executable path, which is also what spyware does.
>
> Do not turn off real-time protection or add a broad antivirus exclusion in order to run this. If you are not comfortable running an unsigned tool that does these things, [build it yourself](#build-from-source); it needs nothing but Go.

## Requirements

- Windows 11 on x64. Windows 10 is untested.
- Administrator approval once at install and once at uninstall, never during ordinary use.
- Local folders only. For a network share, run ReadWatch on the file server against its local path.
- Audit markers need NTFS or ReFS. Event tracing works on any local filesystem.

## Use

1. Download `ReadWatch-v0.4.0-windows-amd64.exe` from [Releases](https://github.com/smkwray/readwatch/releases) (checksums are in `SHA256SUMS.txt`), run it, and approve the installation prompt.
2. Open **Settings**, add a folder, pick a log file and format, and save. The folder that will hold the log file must already exist.
3. Press **Start**.

Antivirus, indexing, thumbnailing and backup tools read files legitimately and will appear. Right-click a row to exclude that process by image name (every `python.exe`, anywhere) or by exact path (that one binary). Prefer the exact path, since a file name is easy to imitate. The summary line counts excluded reads, and the list lives in Settings.

A watched folder can be on a drive that is not always attached. ReadWatch shows it as waiting and starts watching it when the drive is plugged in. Press **Stop** before you eject: ReadWatch holds watched folders open, so Windows will refuse to eject the drive while it is watched.

Closing the window hides it to the tray; **Exit** stops monitoring and the service. Settings can also start ReadWatch in the tray at sign-in.

## Log

```text
2026-08-12 12:30:43.426 | READ | pwsh.exe | pid=32740 | HOST\user | D:\Renders\output\frame.png | exe=C:\Program Files\PowerShell\7\pwsh.exe
```

Each read records the time, file path, program name and image path, process ID, and bytes transferred, plus the user account and access mask under audit markers. `LIST` marks a folder listing. A `GAP` line says how many reads were missed and why, for example because the machine was too busy. JSONL and CSV also carry the event record ID. If a program exits before ReadWatch can look it up, its process fields are left blank rather than guessed. The log is never rotated or trimmed.

## Privileges and privacy

- A LocalSystem service does the privileged work, and the window runs as you without elevation. They talk over a local named pipe that only LocalSystem and the installing account can open. The service starts with the window and stops when you exit, even if the window is killed. Your account can start, stop and query it, but cannot reconfigure or delete it.
- Under audit markers, ReadWatch adds an audit entry to the security settings (the SACL) of each watched folder and the files in it, and turns on the *Audit File System (success)* policy. **Stop** removes the entries and restores the previous policy. Under event tracing it writes nothing to the drives.
- Folders and the log file are opened under your account when you press Start or Save, and the service works through those handles rather than looking the path up again, so nothing can be swapped in between.
- Under event tracing, ReadWatch sees file activity from the whole machine. Events outside your folders are discarded without being written or kept.
- ReadWatch sends nothing anywhere: no connections, telemetry, or update checks.

## Known limits

- Junctions, symbolic links, mounted volumes and cloud placeholders are refused anywhere in a watched path, because ReadWatch must prove the folder it marks is the one you approved. The check trusts what the filesystem driver reports.
- On exFAT and FAT, ReadWatch can tell that a path now points at a different drive, but not that a folder was deleted and recreated on the same drive, and it cannot tell a deliberately cloned volume from the original.
- Under event tracing, the user column is blank and reads made purely through a memory mapping are not reported. Under audit markers, event 4663 shows that an access right was used, not which bytes were read, and marking a large tree takes minutes.
- A read issued right after the same program wrote the same file produced no event in testing.
- If a drive is unplugged without pressing Stop, the audit rule stays on that disk until it is next attached, when ReadWatch removes it. Folders on other drives keep being watched.
- Not tested: Windows 10, ReFS, encrypted volumes such as VeraCrypt, unplugging a watched drive, sleep and resume, a full disk, and uninstalling while audit markers are applied.

## Uninstalling

Uninstall ReadWatch from Windows Settings under Installed apps. This removes the service, the program, the Start Menu entry and `C:\ProgramData\ReadWatch`, and withdraws every audit rule and policy change ReadWatch made; your log file is kept. Windows deletes the program file at the next restart. If a watched drive is not attached, the uninstaller tells you which drive to plug in so its audit rule can be removed.

## Build from source

Requires Go 1.23 or later.

```bat
build.cmd 0.4.0
```

This runs `go test ./...` and `go vet ./...`, then builds `dist\ReadWatch.exe` for Windows x64 with the given version. The icon, version information and manifest come from the checked-in `cmd/readwatch/rsrc_windows_amd64.syso`; regenerating it needs Python 3 and Clang (`python tools/make_resources.py --version 0.4.0.0`).

## License

MIT; see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
