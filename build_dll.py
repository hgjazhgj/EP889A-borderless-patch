#!/usr/bin/env python3
"""Build or inspect the EP-889A Japanese Retain Size dialog resource patch.

Python 3.10+ standard library only. Building requires native x64 Windows;
verification is read-only and platform-independent. No driver module is loaded
or executed, and no printer API is used. The original DLL is never modified.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import uuid

SOURCE_SHA256 = "fb15414f8b5afdb3bd8a7be3471748615dfc0397c507ff2d57a53e4849900c61"
DONOR_SHA256 = "65b3c9d9ade3a893f2282861b3488aceb925da1685073ac7a5967e9288c40f18"
TEMPLATE_SHA256 = "e01089b261f9299646a0d91bf28632cbb2c3f18e1e4e70c03abdfea8b34b32ec"
RELEASE_SHA256 = "6b09338332a6525fb235a447c7c1ec621d99fceec24bf29def1803ab8f198eac"
TARGET = (5, 4065, 1041)  # RT_DIALOG, resource ID, Japanese language ID.
# The reviewed 664-byte RT_DIALOG 4065/1041 template from E1YUIRBJJ.DLL.
# The complete donor DLL is not needed. Its original SHA256 is recorded above.
TEMPLATE_BASE64 = (
    "RADAgAAAAAAOAAAAAAD3AL4AAAAAAG8wfzD6UVcwz5EtippbAAAJAE0AUwAgAFMAaABlAGwAbAAgAEQAbABnAAAAAAAHAAJQAAAAAAMABADwACoA4g///4AA1TDBMGowVzC5ZdVsLYqaWwAAAAAAAAkgAlAAAAAAFAASAD0ACQDjD///gADqgdVS4WInWQAAAAAAAAkgAFAAAAAAFAAfAF4ACQDkD///gACrMLkwvzDgMC2KmlsoAJ9T+FutfQFjKQAAAAAAAAAHAAJQAAAAAAMANADwAG0A5Q///4AAbzB/MPpRVzDPkQAAAAABAANQAAAAADkATwCEABYA6w9tAHMAYwB0AGwAcwBfAHQAcgBhAGMAawBiAGEAcgAzADIAAAAAAAAAAAAAAAJQAAAAADwAZgAjAAgA5g///4IAiDCKMBFcajBEMAAAAAABAAJQAAAAAGwAZgAjAAgA5w///4IAEVxqMEQwAAAAAAIAAlAAAAAAmwBmACMACADoD///ggAZapZuAAAAAAAAQwAAUAAAAAAZAFEAHgAeAOkP//+CAAAAAAAAAEMAAFAAAAAAxwBRAB4AHgDqD///ggAAAAAAAAAAAAJQAAAAABoAdQC8ACMA7A///4IAWwAZapZuXQDlThZZazBZMIswaDABMG8wfzD6UVcwz5FMMBFcajBPMGowijABMCh1GX1uMO96azBZT312TDBnME0wizBTMGgwgjBCMIowfjBZMAIwAAAAAAAAAQADUAAAAABkAKgALAAPAO0P//+AAE8ASwAAAAAAAAAAAAFQAAAAAJYAqAAsAA8A7g///4AArTDjMPMwuzDrMAAAAAAAAAFQAAAAAMgAqAAsAA8A7w///4AA2DDrMNcwAAAAAA=="
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def template_bytes():
    data = base64.b64decode(TEMPLATE_BASE64, validate=True)
    require(len(data) == 664 and sha256(data) == TEMPLATE_SHA256,
            "Embedded dialog template failed its integrity check")
    return data


class PE:
    """Bounded x64 PE/resource reader; does not use LoadLibrary."""

    def __init__(self, data):
        self.data = data
        require(data[:2] == b"MZ", "Not a PE file")
        self.pe_offset = self.unpack("<I", 60)[0]
        require(data[self.pe_offset:self.pe_offset + 4] == b"PE\0\0", "Missing PE signature")
        require(self.unpack("<H", self.pe_offset + 4)[0] == 0x8664, "Expected an x64 DLL")
        self.optional = self.pe_offset + 24
        optional_size = self.unpack("<H", self.pe_offset + 20)[0]
        require(self.unpack("<H", self.optional)[0] == 0x20B, "Expected PE32+")
        require(optional_size >= 240 and self.unpack("<I", self.optional + 108)[0] >= 16,
                "Truncated or unsupported optional header")
        self.bounds(self.optional, optional_size)
        self.sections = {}
        for index in range(self.unpack("<H", self.pe_offset + 6)[0]):
            entry = self.optional + optional_size + index * 40
            name, virtual_size, rva, raw_size, raw = self.unpack("<8sIIII", entry)
            require(name not in self.sections, "Duplicate PE section")
            self.bounds(raw, raw_size)
            self.sections[name] = (virtual_size, rva, raw_size, raw)
        self.resource_rva, self.resource_size = self.directory(2)
        self.resource_base = self.rva_offset(self.resource_rva, self.resource_size)
        self.resources = {}
        self._walk(0)

    def bounds(self, offset, size):
        require(offset >= 0 and size >= 0 and offset + size <= len(self.data),
                "PE structure points outside the file")

    def unpack(self, fmt, offset):
        self.bounds(offset, struct.calcsize(fmt))
        return struct.unpack_from(fmt, self.data, offset)

    def directory(self, index):
        return self.unpack("<II", self.optional + 112 + index * 8)

    def rva_offset(self, rva, size=1):
        for _, start, raw_size, raw in self.sections.values():
            if start <= rva and rva + size <= start + raw_size:
                offset = raw + rva - start
                self.bounds(offset, size)
                return offset
        raise ValueError("Resource RVA has no complete file-backed section")

    def _resource_position(self, relative, size):
        require(relative >= 0 and relative + size <= self.resource_size,
                "Resource directory pointer exceeds its declared boundary")
        self.bounds(self.resource_base + relative, size)
        return self.resource_base + relative

    def _key(self, value):
        if not value & 0x80000000:
            return value
        relative = value & 0x7FFFFFFF
        units = self.unpack("<H", self._resource_position(relative, 2))[0]
        position = self._resource_position(relative + 2, units * 2)
        return self.data[position:position + units * 2].decode("utf-16le")

    def _walk(self, relative, prefix=(), ancestors=frozenset()):
        require(relative not in ancestors and len(prefix) < 3,
                "Cyclic or excessively deep resource directory")
        position = self._resource_position(relative, 16)
        named, numbered = self.unpack("<HH", position + 12)
        self._resource_position(relative, 16 + (named + numbered) * 8)
        for index in range(named + numbered):
            key, child = self.unpack("<II", position + 16 + index * 8)
            current = prefix + (self._key(key),)
            if child & 0x80000000:
                self._walk(child & 0x7FFFFFFF, current, ancestors | {relative})
            else:
                require(len(current) == 3 and current not in self.resources,
                        "Unexpected or duplicate resource leaf")
                entry = self._resource_position(child, 16)
                rva, size, codepage, reserved = self.unpack("<IIII", entry)
                offset = self.rva_offset(rva, size)
                self.resources[current] = {"entry": entry, "offset": offset,
                                           "payload": self.data[offset:offset + size],
                                           "codepage": codepage, "reserved": reserved}


def parse_dialog(data):
    """Read the reviewed standard DLGTEMPLATE, including all child controls."""
    require(len(data) >= 18, "Truncated dialog template")
    style, exstyle, count, x, y, width, height = struct.unpack_from("<IIHhhhh", data)
    position = 18

    def word():
        nonlocal position
        require(position + 2 <= len(data), "Truncated dialog field")
        result = struct.unpack_from("<H", data, position)[0]
        position += 2
        return result

    def text():
        value = word()
        if value == 0xFFFF:
            return ("ordinal", word())
        start = position - 2
        while value:
            value = word()
        return data[start:position - 2].decode("utf-16le")

    menu, window_class, title = text(), text(), text()
    font = (word(), text()) if style & 0x40 else None
    items = {}
    for _ in range(count):
        position = (position + 3) & ~3
        require(position + 18 <= len(data), "Truncated dialog control")
        st, ex, ix, iy, iw, ih, control_id = struct.unpack_from("<IIhhhhH", data, position)
        position += 18
        cls, label = text(), text()
        extra = word()
        if extra:
            require(extra >= 2, "Invalid dialog creation data")
            position += extra - 2
        require(position <= len(data) and control_id not in items,
                "Invalid or duplicate dialog control")
        items[control_id] = {"style": st, "exstyle": ex, "class": cls,
                             "text": label, "rect": (ix, iy, iw, ih)}
    require(position == len(data), "Unexpected trailing dialog data")
    return {"style": style, "exstyle": exstyle, "count": count,
            "rect": (x, y, width, height), "menu": menu, "class": window_class,
            "title": title, "font": font, "items": items}


def check_dialogs(before, after):
    a, b = parse_dialog(before), parse_dialog(after)
    require(a["count"] == 10 and b["count"] == 14, "Unexpected dialog versions")
    require(set(b["items"]) - set(a["items"]) == {4066, 4067, 4068, 4069},
            "Unexpected added controls")
    for key in ("style", "exstyle", "menu", "class", "title", "font"):
        require(a[key] == b[key], "Dialog header differs beyond the reviewed changes")
    require(b["rect"] == (*a["rect"][:3], a["rect"][3] + 60), "Unexpected dialog dimensions")
    for control_id, item in a["items"].items():
        other = b["items"][control_id]
        for key in ("style", "exstyle", "class", "text"):
            require(item[key] == other[key], "Shared dialog control changed")
        require(other["rect"] == (item["rect"][0], item["rect"][1] + 60, *item["rect"][2:]),
                "Shared control is not at the reviewed position")


def checksum(data, offset):
    total = 0
    for position in range(0, len(data), 2):
        if offset <= position < offset + 4:
            continue
        total += int.from_bytes(data[position:position + 2], "little")
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total + len(data)


def validate(source_data, candidate_data):
    """Validate the complete resource inventory, code/data, PE metadata and dialog."""
    require(sha256(source_data) == SOURCE_SHA256, "Original DLL SHA256 does not match the supported build")
    original, candidate = PE(source_data), PE(candidate_data)
    replacement = template_bytes()
    require(len(original.resources) == 428 and original.resources.keys() == candidate.resources.keys(),
            "Resource inventory changed")
    changed = [key for key in original.resources
               if original.resources[key]["payload"] != candidate.resources[key]["payload"]]
    require(changed == [TARGET], "Unexpected changed resource payloads")
    require(candidate.resources[TARGET]["payload"] == replacement, "Wrong replacement dialog")
    for key, old in original.resources.items():
        new = candidate.resources[key]
        require((old["codepage"], old["reserved"]) == (new["codepage"], new["reserved"]),
                "Resource leaf metadata changed")
    require(original.sections.keys() == candidate.sections.keys(), "Section inventory changed")
    for name, old in original.sections.items():
        if name.rstrip(b"\0") == b".rsrc":
            continue
        new = candidate.sections[name]
        require(old[0] == new[0] and old[2] == new[2], "Nonresource section size changed")
        if name.rstrip(b"\0") != b".reloc":
            require(old[1] == new[1], "Nonresource code/data RVA changed")
        require(source_data[old[3]:old[3] + old[2]] == candidate_data[new[3]:new[3] + new[2]],
                "Nonresource section contents changed")
    require(candidate.directory(4) == (0, 0), "Invalid or unexpected certificate directory")
    require(candidate.directory(5) == (candidate.sections[b".reloc\0\0"][1], original.directory(5)[1]),
            "Relocation directory does not match its section")
    for index in range(16):
        if index not in (2, 4, 5):
            require(original.directory(index) == candidate.directory(index), "Unrelated PE directory changed")
    require(original.unpack("<I", original.optional + 64)[0] == checksum(source_data, original.optional + 64),
            "Checksum algorithm does not match the original")
    require(candidate.unpack("<I", candidate.optional + 64)[0] == checksum(candidate_data, candidate.optional + 64),
            "Candidate PE checksum mismatch")
    require(len(candidate_data) == max(section[3] + section[2] for section in candidate.sections.values()),
            "Unexpected candidate overlay")
    check_dialogs(original.resources[TARGET]["payload"], replacement)
    digest = sha256(candidate_data)
    return {"verified": True, "bytes": len(candidate_data), "sha256": digest,
            "matches_release_sha256": digest == RELEASE_SHA256,
            "resource_count": len(candidate.resources), "changed_resource": list(TARGET),
            "unchanged_other_resource_count": len(candidate.resources) - 1,
            "driver_loaded_or_called": False,
            "runtime_ui_and_print_behavior_verified": False}


def finalize(source_data, modified_data):
    original, modified = PE(source_data), PE(modified_data)
    require(original.resources.keys() == modified.resources.keys(), "Resource inventory changed during update")
    data = bytearray(modified_data)
    for key, leaf in modified.resources.items():
        old = original.resources[key]
        struct.pack_into("<II", data, leaf["entry"] + 8, old["codepage"], old["reserved"])
    # The updater removes the old certificate overlay. Clear its obsolete pointer;
    # this is an unsigned modified DLL, not a preserved valid vendor signature.
    struct.pack_into("<II", data, modified.optional + 112 + 4 * 8, 0, 0)
    struct.pack_into("<I", data, modified.optional + 64, 0)
    struct.pack_into("<I", data, modified.optional + 64, checksum(data, modified.optional + 64))
    return data


def build(source, output):
    require(sys.platform == "win32" and ctypes.sizeof(ctypes.c_void_p) == 8,
            "Building requires native x64 Windows Python")
    source = Path(source).resolve(strict=True)
    requested_output = Path(output).absolute()
    require(not requested_output.exists() and not requested_output.is_symlink(),
            "Output must be a new file, not an existing file or symbolic link")
    output = requested_output.resolve()
    require(source != output and not output.exists(),
            "Output must be a new file, separate from the original")
    require(output.parent.is_dir(), "Output parent directory must already exist")
    original_data = source.read_bytes()
    require(sha256(original_data) == SOURCE_SHA256, "Original DLL SHA256 does not match the supported build")
    original = PE(original_data)
    replacement = template_bytes()
    check_dialogs(original.resources[TARGET]["payload"], replacement)
    temporary = output.parent / ("." + output.name + ".build-" + uuid.uuid4().hex)
    try:
        with temporary.open("xb") as stream:
            stream.write(original_data)
            stream.flush()
            os.fsync(stream.fileno())
        # This API edits PE file resources; it never loads or executes this DLL.
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.BeginUpdateResourceW.argtypes = [ctypes.c_wchar_p, ctypes.c_int]
        kernel.BeginUpdateResourceW.restype = ctypes.c_void_p
        kernel.UpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_uint16, ctypes.c_void_p, ctypes.c_uint32]
        kernel.UpdateResourceW.restype = ctypes.c_int
        kernel.EndUpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_int]
        kernel.EndUpdateResourceW.restype = ctypes.c_int
        handle = kernel.BeginUpdateResourceW(str(temporary), False)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            buffer = ctypes.create_string_buffer(replacement, len(replacement))
            if not kernel.UpdateResourceW(handle, ctypes.c_void_p(TARGET[0]), ctypes.c_void_p(TARGET[1]),
                                          TARGET[2], buffer, len(replacement)):
                raise ctypes.WinError(ctypes.get_last_error())
            active, handle = handle, None
            if not kernel.EndUpdateResourceW(active, False):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            if handle:
                kernel.EndUpdateResourceW(handle, True)
        data = finalize(original_data, temporary.read_bytes())
        result = validate(original_data, data)
        with temporary.open("r+b") as stream:
            stream.write(data)
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())
        require(temporary.read_bytes() == data, "Final output readback mismatch")
        # On Windows rename refuses an existing destination; no file is overwritten.
        os.rename(temporary, output)
        result["output"] = str(output)
        return result
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="Unmodified supported E1YUIRFKJ.DLL")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="New output DLL; existing files are never overwritten")
    mode.add_argument("--verify-only", type=Path, help="Read-only verification of an existing patched DLL")
    args = parser.parse_args(argv)
    try:
        if args.verify_only is not None:
            result = validate(args.source.read_bytes(), args.verify_only.read_bytes())
            result["file_modified"] = False
        else:
            result = build(args.source, args.output)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, KeyError, struct.error, UnicodeError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
