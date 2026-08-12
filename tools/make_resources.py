#!/usr/bin/env python3
"""Generate the amd64 COFF resource object used by the Go linker.

The object contains ReadWatch's application icon, version information, and Windows manifest. It is
created with clang's integrated COFF assembler; the generated .syso is checked
into the source package, so normal Windows builds require only Go.
"""
from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

RT_ICON = 3
RT_GROUP_ICON = 14
RT_VERSION = 16
RT_MANIFEST = 24
LANG_EN_US = 1033

@dataclass(frozen=True)
class IconImage:
    width: int
    height: int
    color_count: int
    reserved: int
    planes: int
    bit_count: int
    data: bytes


def read_ico(path: Path) -> list[IconImage]:
    blob = path.read_bytes()
    if len(blob) < 6:
        raise ValueError("icon file is truncated")
    reserved, kind, count = struct.unpack_from("<HHH", blob, 0)
    if reserved != 0 or kind != 1 or count < 1:
        raise ValueError("not a Windows icon file")
    images: list[IconImage] = []
    for i in range(count):
        off = 6 + i * 16
        if off + 16 > len(blob):
            raise ValueError("icon directory is truncated")
        width, height, colors, entry_reserved, planes, bits, size, data_off = struct.unpack_from("<BBBBHHII", blob, off)
        if data_off + size > len(blob):
            raise ValueError("icon image extends beyond the file")
        images.append(IconImage(width, height, colors, entry_reserved, planes, bits, blob[data_off:data_off + size]))
    return images


def group_icon(images: list[IconImage]) -> bytes:
    out = bytearray(struct.pack("<HHH", 0, 1, len(images)))
    for resource_id, image in enumerate(images, 1):
        out.extend(struct.pack(
            "<BBBBHHIH",
            image.width,
            image.height,
            image.color_count,
            image.reserved,
            image.planes,
            image.bit_count,
            len(image.data),
            resource_id,
        ))
    return bytes(out)



def _utf16z(value: str) -> bytes:
    return value.encode("utf-16le") + b"\x00\x00"


def _pad4(data: bytearray) -> None:
    data.extend(b"\x00" * ((-len(data)) & 3))


def _version_block(key: str, value: bytes, value_length: int, value_type: int, children: list[bytes] | None = None) -> bytes:
    out = bytearray(b"\x00" * 6)
    out.extend(_utf16z(key))
    _pad4(out)
    out.extend(value)
    _pad4(out)
    for child in children or []:
        out.extend(child)
        _pad4(out)
    struct.pack_into("<HHH", out, 0, len(out), value_length, value_type)
    return bytes(out)


def version_info(version: str = "0.1.0.0") -> bytes:
    parts = [int(p) for p in version.split(".")]
    if len(parts) > 4 or any(p < 0 or p > 65535 for p in parts):
        raise ValueError("version must contain up to four 16-bit integers")
    parts.extend([0] * (4 - len(parts)))
    major, minor, patch, build = parts
    file_ms = (major << 16) | minor
    file_ls = (patch << 16) | build
    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,  # VS_FFI_SIGNATURE
        0x00010000,  # VS_FFI_STRUCVERSION
        file_ms, file_ls,
        file_ms, file_ls,
        0x0000003F,  # VS_FFI_FILEFLAGSMASK
        0x00000002,  # VS_FF_PRERELEASE
        0x00040004,  # VOS_NT_WINDOWS32
        0x00000001,  # VFT_APP
        0, 0, 0,
    )
    strings = {
        "CompanyName": "ReadWatch",
        "FileDescription": "ReadWatch folder read monitor",
        "FileVersion": f"{major}.{minor}.{patch}.{build}",
        "InternalName": "ReadWatch",
        "LegalCopyright": "Copyright © 2026 ReadWatch contributors",
        "OriginalFilename": "ReadWatch.exe",
        "ProductName": "ReadWatch",
        "ProductVersion": f"{major}.{minor}.{patch}",
        "Comments": "Compact native Windows folder read monitor",
    }
    string_children = [
        _version_block(name, _utf16z(value), len(value) + 1, 1)
        for name, value in strings.items()
    ]
    string_table = _version_block("040904B0", b"", 0, 1, string_children)
    string_file_info = _version_block("StringFileInfo", b"", 0, 1, [string_table])
    translation = _version_block("Translation", struct.pack("<HH", 0x0409, 1200), 4, 0)
    var_file_info = _version_block("VarFileInfo", b"", 0, 1, [translation])
    return _version_block("VS_VERSION_INFO", fixed, len(fixed), 0, [string_file_info, var_file_info])

def emit_bytes(lines: list[str], data: bytes, width: int = 24) -> None:
    if not data:
        lines.append(".byte 0")
        return
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        lines.append(".byte " + ",".join(f"0x{b:02x}" for b in chunk))


def dir_header(lines: list[str], ids: int) -> None:
    lines.extend([".long 0", ".long 0", ".short 0", ".short 0", ".short 0", f".short {ids}"])


def generate_assembly(icon_path: Path, manifest_path: Path, version: str = "0.1.0.0") -> str:
    icons = read_ico(icon_path)
    manifest = manifest_path.read_bytes()
    group = group_icon(icons)
    version_blob = version_info(version)

    lines: list[str] = [
        ".section .rsrc$01,\"dr\"",
        ".p2align 2",
        "rsrc_start:",
    ]
    dir_header(lines, 4)
    for rtype, label in ((RT_ICON, "type_icons"), (RT_GROUP_ICON, "type_group"), (RT_VERSION, "type_version"), (RT_MANIFEST, "type_manifest")):
        lines.extend([f".long {rtype}", f".long ({label}-rsrc_start) | 0x80000000"])

    lines.append("type_icons:")
    dir_header(lines, len(icons))
    for i in range(1, len(icons) + 1):
        lines.extend([f".long {i}", f".long (icon_{i}_lang-rsrc_start) | 0x80000000"])

    lines.append("type_group:")
    dir_header(lines, 1)
    lines.extend([".long 1", ".long (group_1_lang-rsrc_start) | 0x80000000"])

    lines.append("type_version:")
    dir_header(lines, 1)
    lines.extend([".long 1", ".long (version_1_lang-rsrc_start) | 0x80000000"])

    lines.append("type_manifest:")
    dir_header(lines, 1)
    lines.extend([".long 1", ".long (manifest_1_lang-rsrc_start) | 0x80000000"])

    for i in range(1, len(icons) + 1):
        lines.append(f"icon_{i}_lang:")
        dir_header(lines, 1)
        lines.extend([f".long {LANG_EN_US}", f".long icon_{i}_entry-rsrc_start"])
    lines.append("group_1_lang:")
    dir_header(lines, 1)
    lines.extend([f".long {LANG_EN_US}", ".long group_1_entry-rsrc_start"])
    lines.append("version_1_lang:")
    dir_header(lines, 1)
    lines.extend([f".long {LANG_EN_US}", ".long version_1_entry-rsrc_start"])
    lines.append("manifest_1_lang:")
    dir_header(lines, 1)
    lines.extend([f".long {LANG_EN_US}", ".long manifest_1_entry-rsrc_start"])

    for i, image in enumerate(icons, 1):
        lines.extend([
            f"icon_{i}_entry:",
            f".rva icon_{i}_raw",
            f".long {len(image.data)}",
            ".long 0",
            ".long 0",
        ])
    lines.extend([
        "group_1_entry:",
        ".rva group_1_raw",
        f".long {len(group)}",
        ".long 0",
        ".long 0",
        "version_1_entry:",
        ".rva version_1_raw",
        f".long {len(version_blob)}",
        ".long 0",
        ".long 0",
        "manifest_1_entry:",
        ".rva manifest_1_raw",
        f".long {len(manifest)}",
        ".long 0",
        ".long 0",
        ".section .rsrc$02,\"dr\"",
        ".p2align 2",
    ])
    for i, image in enumerate(icons, 1):
        lines.append(f"icon_{i}_raw:")
        emit_bytes(lines, image.data)
        lines.append(".p2align 2")
    lines.append("group_1_raw:")
    emit_bytes(lines, group)
    lines.append(".p2align 2")
    lines.append("version_1_raw:")
    emit_bytes(lines, version_blob)
    lines.append(".p2align 2")
    lines.append("manifest_1_raw:")
    emit_bytes(lines, manifest)
    lines.append(".p2align 2")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--version", default="0.1.0.0")
    args = parser.parse_args()
    root = args.root.resolve()
    icon = root / "cmd/readwatch/resources/ReadWatch.ico"
    manifest = root / "cmd/readwatch/resources/ReadWatch.exe.manifest"
    assembly = root / "tools/readwatch_resources_amd64.s"
    output = root / "cmd/readwatch/rsrc_windows_amd64.syso"
    assembly.write_text(generate_assembly(icon, manifest, args.version), encoding="utf-8", newline="\n")
    clang = shutil.which(args.clang)
    if clang is None:
        raise SystemExit(f"{args.clang!r} was not found")
    subprocess.run([
        clang,
        "-target", "x86_64-pc-windows-gnu",
        "-c", str(assembly),
        "-o", str(output),
    ], check=True)
    print(output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
