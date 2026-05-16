# SPDX-License-Identifier: MIT

from pathlib import Path

from . import known_guids, tables, utils


class Analyser:
    def __init__(self, flat_api, module_path):
        self.flat_api = flat_api
        self.program = flat_api.getCurrentProgram()
        self.module_path = Path(module_path)
        header = utils.get_header_file(self.module_path)
        self.arch = utils.get_machine_type(header)
        self.subsystem = utils.check_subsystem(header)
        self.valid = True
        if not self.subsystem:
            self.valid = False
        if self.arch not in ("x86", "x64"):
            self.valid = False

        self.base = int(self.program.getImageBase().getOffset())
        self.address_space = self.program.getAddressFactory().getDefaultAddressSpace()
        self.listing = self.program.getListing()
        self.memory = self.program.getMemory()
        self.code_set = self.memory.getExecuteSet()
        if self.code_set.isEmpty():
            self.code_set = self.memory.getLoadedAndInitializedAddressSet()

        if self.arch == "x86":
            self.BOOT_SERVICES_OFFSET = tables.BOOT_SERVICES_OFFSET_x86
        else:
            self.BOOT_SERVICES_OFFSET = tables.BOOT_SERVICES_OFFSET_x64

        self.gBServices = {
            "InstallProtocolInterface": [],
            "ReinstallProtocolInterface": [],
            "UninstallProtocolInterface": [],
            "HandleProtocol": [],
            "RegisterProtocolNotify": [],
            "OpenProtocol": [],
            "CloseProtocol": [],
            "OpenProtocolInformation": [],
            "ProtocolsPerHandle": [],
            "LocateHandleBuffer": [],
            "LocateProtocol": [],
            "InstallMultipleProtocolInterfaces": [],
            "UninstallMultipleProtocolInterfaces": [],
        }

        self.Protocols = dict(known_guids.GUID_SOURCES)
        self.Protocols["all"] = []
        self.Protocols["prop_guids"] = []
        self.Protocols["data"] = []

    def _to_relative(self, absolute):
        if hasattr(absolute, "getOffset"):
            absolute = absolute.getOffset()
        return int(absolute) - self.base

    def _to_absolute(self, relative):
        return self.address_space.getAddress(f"{self.base + int(relative):x}")

    def _instruction_refs(self, instruction):
        return utils.get_instruction_data_refs(self.program, instruction, self.base)

    def _instruction_at_relative(self, relative_address):
        return self.listing.getInstructionAt(self._to_absolute(relative_address))

    def _find_guid_load_instruction(self, call_relative_address):
        instruction = self._instruction_at_relative(call_relative_address)
        if instruction is None:
            return None

        search_depth = 24 if self.arch == "x86" else 16
        expected_mnemonic = "push" if self.arch == "x86" else "lea"

        for _ in range(search_depth):
            instruction = self.listing.getInstructionBefore(instruction.getAddress())
            if instruction is None:
                break
            if instruction.getMnemonicString().lower() != expected_mnemonic:
                continue
            if self._instruction_refs(instruction):
                return instruction
        return None

    def get_boot_services(self):
        iterator = self.listing.getInstructions(self.code_set, True)
        while iterator.hasNext():
            instruction = iterator.next()
            if instruction.getMnemonicString().lower() != "call":
                continue
            call_offset = utils.get_operand_scalar(instruction, 0)
            if call_offset is None:
                continue
            for service_name, expected_offset in self.BOOT_SERVICES_OFFSET.items():
                if call_offset != expected_offset:
                    continue
                relative = self._to_relative(instruction.getAddress())
                if relative not in self.gBServices[service_name]:
                    self.gBServices[service_name].append(relative)

    def get_protocols(self):
        for service_name in self.gBServices:
            for relative_call in self.gBServices[service_name]:
                instruction = self._find_guid_load_instruction(relative_call)
                if instruction is None:
                    continue
                for guid_address in self._instruction_refs(instruction):
                    if not utils.check_guid(self.program, guid_address):
                        continue
                    record = {
                        "address": self._to_relative(guid_address),
                        "service": service_name,
                        "guid": utils.get_guid(self.program, guid_address),
                    }
                    if record not in self.Protocols["all"]:
                        self.Protocols["all"].append(record)

    def get_prot_names(self):
        for index in range(len(self.Protocols["all"])):
            found = False
            for guid_place in known_guids.GUID_SOURCE_NAMES:
                for protocol_name, guid_conf in self.Protocols[guid_place].items():
                    guid_value = self.Protocols["all"][index]["guid"]
                    if guid_value != guid_conf:
                        continue
                    self.Protocols["all"][index]["protocol_name"] = protocol_name
                    self.Protocols["all"][index]["protocol_place"] = guid_place
                    found = True
                    break
                if found:
                    break
            if not found:
                self.Protocols["all"][index]["protocol_name"] = "ProprietaryProtocol"
                self.Protocols["all"][index]["protocol_place"] = "unknown"

    def analyse_all(self):
        self.get_boot_services()
        self.get_protocols()
        self.get_prot_names()
