# SPDX-License-Identifier: MIT

import argparse
import json
import os
import tempfile
import warnings
from pathlib import Path

from ghidra_backend.analyser import Analyser
from ghidra_backend.bootstrap import ensure_pyghidra
from ghidra_backend.context_log import build_context_log
from ghidra_backend.utils import get_file_md5, normalize_path


DEFAULT_LOG_DIRS = {
    "context": os.path.join(tempfile.gettempdir(), "contextuefi-context"),
}
UNSUPPORTED_MODULE_EXIT_CODE = 20
AUTO_ANALYSIS_WARNING_PREFIX = "Ghidra auto-analysis failed"


def _short_exception(exception):
    lines = [line.strip() for line in str(exception).splitlines() if line.strip()]
    if lines:
        return lines[-1]
    return exception.__class__.__name__


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("context",), required=True)
    parser.add_argument("--module-path", required=True)
    parser.add_argument("--ghidra-install-dir", required=True)
    parser.add_argument("--vendor-dir")
    parser.add_argument("--project-dir")
    parser.add_argument("--language")
    parser.add_argument("--compiler")
    parser.add_argument("--loader")
    return parser.parse_args()


def _build_log(analyser, mode):
    return build_context_log(analyser)


def _disable_optional_analyzers(pyghidra_module, program):
    try:
        analysis_options = pyghidra_module.analysis_properties(program)
    except Exception:
        return

    try:
        option_names = list(analysis_options.getOptionNames())
    except Exception:
        return

    disabled = False
    with pyghidra_module.transaction(program, "Disable optional analyzers"):
        for option_name in option_names:
            normalized = str(option_name).lower().replace(" ", "")
            if "efiseek" not in normalized:
                continue
            try:
                analysis_options.setBoolean(option_name, False)
                disabled = True
            except Exception:
                continue
    return disabled


def main():
    args = _parse_args()

    ensure_pyghidra(args.ghidra_install_dir, args.vendor_dir)

    import pyghidra  # pylint: disable=import-error,import-outside-toplevel

    warnings.filterwarnings("ignore", category=DeprecationWarning, module="pyghidra")
    warnings.filterwarnings(
        "ignore",
        category=DeprecationWarning,
        message=r"open_program\(\) is deprecated.*",
    )
    pyghidra.start(install_dir=Path(args.ghidra_install_dir))

    module_path = Path(args.module_path).resolve()
    output_dir = Path(DEFAULT_LOG_DIRS[args.mode])
    output_dir.mkdir(parents=True, exist_ok=True)

    open_kwargs = {
        "binary_path": str(module_path),
        "analyze": False,
        "nested_project_location": False,
    }
    if args.language:
        open_kwargs["language"] = args.language
    if args.compiler:
        open_kwargs["compiler"] = args.compiler
    if args.loader:
        open_kwargs["loader"] = args.loader

    with tempfile.TemporaryDirectory(
        prefix="contextuefi-ghidra-project-",
        dir=normalize_path(args.project_dir),
    ) as project_dir:
        open_kwargs["project_location"] = project_dir
        open_kwargs["project_name"] = "contextuefi"
        with pyghidra.open_program(**open_kwargs) as flat_api:
            program = flat_api.getCurrentProgram()
            _disable_optional_analyzers(pyghidra, program)
            try:
                pyghidra.analyze(program)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                print(
                    f"{AUTO_ANALYSIS_WARNING_PREFIX}: "
                    f"{module_path.name}: {_short_exception(exc)}",
                    flush=True,
                )
            analyser = Analyser(flat_api, module_path)
            if not analyser.valid:
                print(
                    f"Unsupported UEFI module: {module_path.name} "
                    f"(arch={analyser.arch}, efi_subsystem={analyser.subsystem})",
                    flush=True,
                )
                return UNSUPPORTED_MODULE_EXIT_CODE
            data = _build_log(analyser, args.mode)

    output_path = output_dir / f"{get_file_md5(module_path)}.json"
    with output_path.open("w", encoding="utf-8") as outfile:
        json.dump(data, outfile, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
