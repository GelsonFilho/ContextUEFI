# SPDX-License-Identifier: MIT

from .utils import get_guid_str


def get_boot_services(analyser):
    boot_services = []
    for service_name in analyser.gBServices:
        for address in analyser.gBServices[service_name]:
            boot_services.append(
                {
                    "address": f"{address:#x}",
                    "bs_name": f"EFI_BOOT_SERVICES->{service_name}",
                }
            )
    return boot_services


def get_protocols(analyser):
    protocols = []
    analyser.get_protocols()
    analyser.get_prot_names()
    for element in analyser.Protocols["all"]:
        protocols.append(
            {
                "address": f"{element['address']:#x}",
                "service": element["service"],
                "protocol_name": element["protocol_name"],
                "protocol_place": element["protocol_place"],
                "guid": get_guid_str(element["guid"]),
            }
        )
    return protocols


def build_context_log(analyser):
    analyser.get_boot_services()
    return {
        "module_name": analyser.module_path.name,
        "boot_services": get_boot_services(analyser),
        "protocols": get_protocols(analyser),
    }
