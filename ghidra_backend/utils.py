# SPDX-License-Identifier: MIT

import hashlib
from pathlib import Path

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014C
PE_OFFSET = 0x3C
IMAGE_SUBSYSTEM_EFI_APPLICATION = 0xA
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 0xB
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 0xC


def get_num_le(bytearr):
    """Translate a set of bytes into a little endian number."""
    num_le = 0
    for index, value in enumerate(bytearr):
        num_le += value * pow(256, index)
    return num_le


def get_header_file(module_path, size=4096):
    with open(module_path, "rb") as infile:
        return bytearray(infile.read(size))


def get_pe_header_offset(header):
    if len(header) < PE_OFFSET + 4:
        return None

    pe_pointer = get_num_le(header[PE_OFFSET : PE_OFFSET + 4])
    if len(header) < pe_pointer + 6:
        return None
    if bytes(header[pe_pointer : pe_pointer + 4]) != b"PE\x00\x00":
        return None
    return pe_pointer


def get_machine_type(header):
    """Get the architecture of the investigated file."""
    pe_pointer = get_pe_header_offset(header)
    if pe_pointer is None:
        return "unknown"
    fh_pointer = pe_pointer + 4
    if len(header) < fh_pointer + 3:
        return "unknown"
    machine_type = header[fh_pointer : fh_pointer + 2]
    type_value = get_num_le(machine_type)
    if type_value == IMAGE_FILE_MACHINE_I386:
        return "x86"
    if type_value == IMAGE_FILE_MACHINE_AMD64:
        return "x64"
    return "unknown"


def check_subsystem(header):
    """Check whether the investigated file is a supported UEFI PE image."""
    pe_pointer = get_pe_header_offset(header)
    if pe_pointer is None or len(header) < pe_pointer + 0x5E:
        return False
    subsystem = get_num_le(header[pe_pointer + 0x5C : pe_pointer + 0x5E])
    return subsystem in (
        IMAGE_SUBSYSTEM_EFI_APPLICATION,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
    )


def get_file_md5(path):
    md5 = hashlib.md5()
    with open(path, "rb") as infile:
        for chunk in iter(lambda: infile.read(1024 * 1024), b""):
            md5.update(chunk)
    return md5.hexdigest()


def read_bytes(program, address, size):
    data = []
    memory = program.getMemory()
    try:
        for index in range(size):
            data.append(int(memory.getByte(address.add(index))) & 0xFF)
    except Exception:
        return None
    return bytes(data)


def check_guid(program, address):
    """Mirror the original heuristic: enough byte diversity for a GUID-like blob."""
    data = read_bytes(program, address, 16)
    if data is None or len(data) != 16:
        return False
    return len(set(data)) > 8


def get_guid(program, address):
    """Read a GUID from program memory."""
    data = read_bytes(program, address, 16)
    if data is None or len(data) != 16:
        raise ValueError(f"Unable to read GUID at {address}")
    guid = [
        int.from_bytes(data[0:4], "little"),
        int.from_bytes(data[4:6], "little"),
        int.from_bytes(data[6:8], "little"),
    ]
    guid.extend(data[8:16])
    return guid


def get_guid_str(guid_struct):
    guid = f"{guid_struct[0]:08X}-"
    guid += f"{guid_struct[1]:04X}-"
    guid += f"{guid_struct[2]:04X}-"
    guid += "".join(f"{guid_struct[index]:02X}" for index in range(3, 11))
    return guid


def get_operand_scalar(instruction, op_index=0):
    """Return the first scalar found in the requested operand."""
    try:
        op_objects = instruction.getOpObjects(op_index)
    except Exception:
        return None
    for obj in op_objects:
        if hasattr(obj, "getUnsignedValue"):
            try:
                return int(obj.getUnsignedValue())
            except Exception:
                continue
        if hasattr(obj, "getValue"):
            try:
                return int(obj.getValue())
            except Exception:
                continue
    return None


def get_instruction_data_refs(program, instruction, minimum_address=None):
    """Collect data references attached to an instruction operands."""
    refs = {}
    memory = program.getMemory()
    for op_index in range(instruction.getNumOperands()):
        try:
            operand_refs = instruction.getOperandReferences(op_index)
        except Exception:
            operand_refs = []
        for ref in operand_refs:
            to_address = ref.getToAddress()
            if to_address is None:
                continue
            try:
                if not memory.contains(to_address):
                    continue
            except Exception:
                continue
            offset = int(to_address.getOffset())
            if minimum_address is not None and offset <= minimum_address:
                continue
            refs[offset] = to_address
    return list(refs.values())


def normalize_path(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return str(Path(text))
