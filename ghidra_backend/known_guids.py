# SPDX-License-Identifier: MIT

from ghidra_backend.guid_db import UEFI_GUIDS


def _guid_to_struct(guid):
    first, second, third, fourth, fifth = guid.split("-")
    data4 = bytes.fromhex(fourth + fifth)
    return [
        int(first, 16),
        int(second, 16),
        int(third, 16),
        *data4,
    ]


def _build_guid_source():
    source = {}
    seen_names = set()
    for guid, protocol_name in UEFI_GUIDS.items():
        name = protocol_name
        if name in seen_names:
            name = f"{protocol_name}_{guid}"
        seen_names.add(name)
        source[name] = _guid_to_struct(guid)
    return source


GUID_SOURCES = {
    "uefi_guids": _build_guid_source(),
}

GUID_SOURCE_NAMES = tuple(GUID_SOURCES)
