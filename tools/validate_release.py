#!/usr/bin/env python3
"""Perform deterministic structural checks on a ReadWatch Windows release."""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

IMAGE_FILE_MACHINE_AMD64 = 0x8664
PE32_PLUS = 0x20B
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2


def u16(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<H", blob, offset)[0]


def u32(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def validate(path: Path) -> list[str]:
    blob = path.read_bytes()
    if len(blob) < 0x100 or blob[:2] != b"MZ":
        raise ValueError("not a DOS/PE executable")
    pe = u32(blob, 0x3C)
    if pe + 24 >= len(blob) or blob[pe:pe + 4] != b"PE\0\0":
        raise ValueError("PE signature is missing")

    coff = pe + 4
    machine = u16(blob, coff)
    section_count = u16(blob, coff + 2)
    optional_size = u16(blob, coff + 16)
    optional = coff + 20
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError(f"unexpected machine 0x{machine:04x}")
    if u16(blob, optional) != PE32_PLUS:
        raise ValueError("not a PE32+ image")
    subsystem = u16(blob, optional + 68)
    if subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI:
        raise ValueError(f"subsystem is {subsystem}, not Windows GUI")

    directory_count = u32(blob, optional + 108)
    if directory_count <= 2:
        raise ValueError("resource data directory is absent")
    resource_rva = u32(blob, optional + 112 + 2 * 8)
    resource_size = u32(blob, optional + 112 + 2 * 8 + 4)
    if resource_rva == 0 or resource_size == 0:
        raise ValueError("resource data directory is empty")

    sections = optional + optional_size
    names: list[str] = []
    resource_section = False
    resource_offset: int | None = None
    for i in range(section_count):
        off = sections + i * 40
        if off + 40 > len(blob):
            raise ValueError("section table is truncated")
        name = blob[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        names.append(name)
        virtual_size = u32(blob, off + 8)
        virtual_address = u32(blob, off + 12)
        span = max(virtual_size, u32(blob, off + 16))
        if name == ".rsrc" and virtual_address <= resource_rva < virtual_address + span:
            resource_section = True
            raw_pointer = u32(blob, off + 20)
            resource_offset = raw_pointer + (resource_rva - virtual_address)
    if not resource_section or resource_offset is None:
        raise ValueError("resource directory does not point into .rsrc")

    if resource_offset + 16 > len(blob):
        raise ValueError("resource directory header is truncated")
    named_count = u16(blob, resource_offset + 12)
    id_count = u16(blob, resource_offset + 14)
    resource_types: set[int] = set()
    for i in range(named_count + id_count):
        entry = resource_offset + 16 + i * 8
        if entry + 8 > len(blob):
            raise ValueError("resource directory entries are truncated")
        name_or_id = u32(blob, entry)
        if name_or_id & 0x80000000 == 0:
            resource_types.add(name_or_id)
    required_types = {3, 14, 16, 24}
    if not required_types.issubset(resource_types):
        missing_types = sorted(required_types - resource_types)
        raise ValueError(f"required resource type(s) missing: {missing_types}")

    required = [
        b"Microsoft.Windows.Common-Controls",
        b"requestedExecutionLevel",
        b"PerMonitorV2",
        b"ReadWatch",
    ]
    missing = [needle.decode("ascii") for needle in required if needle not in blob]
    if missing:
        raise ValueError("embedded manifest/resource markers missing: " + ", ".join(missing))

    version_markers = ["FileDescription", "ReadWatch folder read monitor", "FileVersion", "0.1.0.0"]
    missing_version = [text for text in version_markers if text.encode("utf-16le") not in blob]
    if missing_version:
        raise ValueError("embedded version markers missing: " + ", ".join(missing_version))

    forbidden = [b"WebView2", b"powershell.exe", b"cmd.exe"]
    present = [needle.decode("ascii") for needle in forbidden if needle.lower() in blob.lower()]
    if present:
        raise ValueError("unexpected runtime marker(s): " + ", ".join(present))

    digest = hashlib.sha256(blob).hexdigest()
    return [
        f"file={path}",
        f"size={len(blob)}",
        f"sha256={digest}",
        f"machine=amd64",
        f"subsystem=windows-gui",
        f"sections={','.join(names)}",
        f"resources=rva:0x{resource_rva:x},size:0x{resource_size:x},types={','.join(map(str, sorted(resource_types)))}",
        "manifest=embedded",
        "version-info=embedded",
        "forbidden-runtime-markers=none",
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", type=Path, default=Path("dist/ReadWatch.exe"))
    args = parser.parse_args()
    try:
        lines = validate(args.path)
    except (OSError, ValueError, struct.error) as exc:
        print(f"FAIL: {exc}")
        return 1
    print("PASS")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
