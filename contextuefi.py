# SPDX-License-Identifier: MIT

import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
CONFIG_FILE = ROOT_DIR / "config.json"

DONE = "DONE"
INFO = "INFO"
SKIP = "SKIP"
WARN = "WARN"
ERROR = "ERROR"
UNSUPPORTED_MODULE_EXIT_CODE = 20

with CONFIG_FILE.open("r", encoding="utf-8") as cfile:
    CONFIG = json.load(cfile)

CONTEXT_LOGS = Path(tempfile.gettempdir()) / "contextuefi-context"


def _config_value(name, default=None):
    for env_name in (f"CONTEXTUEFI_{name}", name):
        env_value = os.environ.get(env_name)
        if env_value is not None and env_value.strip():
            return env_value.strip()

    value = CONFIG.get(name, default)
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return default
    return value


def _config_path(name, default):
    value = Path(str(_config_value(name, default)))
    if not value.is_absolute():
        value = ROOT_DIR / value
    return value


def modules_dir():
    return _config_path("MODULES_DIR", "modules")


def work_dir():
    return _config_path("WORK_DIR", "work")


def logs_dir():
    return _config_path("LOGS_DIR", "logs")


def chipsec_dir():
    return _config_path("CHIPSEC_DIR", "chipsec")


def uefiextract_path():
    configured = str(_config_value("UEFIEXTRACT_PATH", "uefiextract"))
    candidates = []
    raw_path = Path(configured)

    if raw_path.is_absolute():
        candidates.append(raw_path)
    else:
        candidates.append(ROOT_DIR / raw_path)

    expanded = []
    for candidate in candidates:
        expanded.append(candidate)
        if candidate.suffix == "":
            expanded.append(candidate.with_suffix(".exe"))
        if candidate.is_dir():
            expanded.extend(sorted(candidate.glob("UEFIExtract*")))
            expanded.extend(sorted(candidate.glob("uefiextract*")))

    for candidate in expanded:
        if candidate.is_file():
            return str(candidate)

    return (
        shutil.which(configured)
        or shutil.which("uefiextract")
        or shutil.which("UEFIExtract")
        or shutil.which("UEFIExtract.exe")
    )


def error(message):
    print(f"{ERROR} {message}")
    raise SystemExit(1)


def clear_dir(dirname):
    path = Path(dirname)
    if not path.exists():
        return
    if not path.is_dir():
        error(f'expected directory, got "{path}"')
    shutil.rmtree(path)


def recreate_dir(dirname):
    clear_dir(dirname)
    Path(dirname).mkdir(parents=True, exist_ok=True)


def get_pyghidra_python_command():
    configured = _config_value("PYGHIDRA_PYTHON_PATH")
    if configured:
        return [configured]
    python_launcher = shutil.which("py")
    if python_launcher:
        return [python_launcher, "-3"]
    return [sys.executable]


def get_ghidra_install_dir():
    configured = _config_value("GHIDRA_INSTALL_DIR")
    if configured:
        return configured

    env_path = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_path:
        return env_path

    program_files = Path("C:/Program Files")
    if program_files.is_dir():
        candidates = sorted(program_files.glob("ghidra_*_PUBLIC"), reverse=True)
        if candidates:
            return str(candidates[0])
    return None


def run_command(command, cwd=None, allow_failure=False):
    result = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 and not allow_failure:
        message = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise RuntimeError(message)
    return result


def command_message(result):
    return (result.stderr.strip() or result.stdout.strip() or "").strip()


def command_output(result):
    return "\n".join(
        part.strip()
        for part in (result.stdout, result.stderr)
        if part and part.strip()
    ).strip()


def concise_message(message):
    lines = [line.strip() for line in str(message).splitlines() if line.strip()]
    if not lines:
        return ""
    return lines[-1]


def find_output_line(output, pattern):
    for line in str(output).splitlines():
        line = line.strip()
        if pattern in line:
            return line
    return ""


def chipsec_command(*args):
    chipsec_root = chipsec_dir()
    chipsec_util = chipsec_root / "chipsec_util.py"
    if not chipsec_util.is_file():
        error(f'chipsec_util.py not found at "{chipsec_util}"')
    return [sys.executable, str(chipsec_util), *map(str, args)]


def run_chipsec_decode(firmware_path, mode, cwd):
    args = ("uefi", "decode", firmware_path) if mode == "uefi" else ("decode", firmware_path)
    print(f"{DONE} CHIPSEC {mode} decode: {Path(firmware_path).name}")
    return run_command(chipsec_command(*args), cwd=cwd, allow_failure=True)


def run_uefiextract_all(firmware_path, cwd):
    executable = uefiextract_path()
    if not executable:
        print(f"{WARN} UEFIExtract not found; skipping UEFIExtract stage")
        return []

    firmware_name = Path(firmware_path).name
    print(f"{DONE} UEFIExtract all: {firmware_name}")
    result = run_command(
        [executable, firmware_name, "all"],
        cwd=cwd,
        allow_failure=True,
    )
    if result.returncode != 0:
        message = command_message(result) or "UEFIExtract failed"
        print(f"{WARN} {message}")

    dump_dir = Path(cwd) / f"{firmware_name}.dump"
    csv_path = Path(cwd) / f"{firmware_name}.guids.csv"
    if not dump_dir.is_dir():
        print(f"{WARN} UEFIExtract did not create {dump_dir.name}")
        return []

    staging_dir = Path(cwd) / "uefiextract_efi"
    recreate_dir(staging_dir)
    return copy_uefiextract_bodies_as_efi(dump_dir, csv_path, staging_dir)


def snapshot_dirs(root):
    root = Path(root)
    if not root.is_dir():
        return set()
    return {path.resolve() for path in root.rglob("*") if path.is_dir()}


def find_binwalk_output_dirs(cwd, firmware_name, before_dirs):
    cwd = Path(cwd)
    expected_dirs = [
        cwd / f"_{firmware_name}.extracted",
        cwd / f"{firmware_name}.extracted",
        cwd / "extractions" / f"_{firmware_name}.extracted",
        cwd / "extractions" / f"{firmware_name}.extracted",
    ]

    found = []
    seen = set()
    for candidate in expected_dirs:
        if candidate.is_dir():
            resolved = candidate.resolve()
            found.append(candidate)
            seen.add(resolved)

    after_dirs = snapshot_dirs(cwd)
    for resolved in sorted(after_dirs - before_dirs, key=lambda path: str(path).lower()):
        candidate = Path(resolved)
        if resolved not in seen:
            found.append(candidate)
            seen.add(resolved)
    return found


def run_binwalk(firmware_path, cwd):
    command_name = str(_config_value("BINWALK_COMMAND", "binwalk"))
    binwalk_exe = shutil.which(command_name) or command_name
    if not shutil.which(command_name) and Path(command_name).name == command_name:
        print(f"{WARN} binwalk not found in PATH; skipping binwalk stage")
        return []

    args = _config_value("BINWALK_ARGS", ["-e"])
    if isinstance(args, str):
        args = args.split()

    firmware_name = Path(firmware_path).name
    before_dirs = snapshot_dirs(cwd)

    print(f"{DONE} binwalk extraction: {firmware_name}")
    result = run_command(
        [binwalk_exe, *args, firmware_name],
        cwd=cwd,
        allow_failure=True,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "binwalk failed"
        print(f"{WARN} {message}")
        return []

    output_dirs = find_binwalk_output_dirs(cwd, firmware_name, before_dirs)
    if not output_dirs:
        print(f"{INFO} binwalk did not create an additional extraction directory")
    return output_dirs


def sha256_file(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as infile:
        for chunk in iter(lambda: infile.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def unique_destination_name(destination_dir, filename):
    destination = destination_dir / filename
    if not destination.exists():
        return destination

    stem = destination.stem
    suffix = destination.suffix
    counter = 1
    while True:
        candidate = destination_dir / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def sanitize_module_filename(name):
    sanitized = []
    for char in str(name).strip():
        if char in '"*?<>|:\\/' or ord(char) < 32:
            sanitized.append("_")
        else:
            sanitized.append(char)

    value = "".join(sanitized).strip(" ._")
    return value or "unknown_module"


def parse_uefiextract_module_names(csv_path):
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        print(f"{WARN} UEFIExtract GUID CSV not found: {csv_path.name}")
        return []

    module_names = []
    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as infile:
        reader = csv.reader(infile)
        for row in reader:
            if len(row) < 2:
                continue
            name = row[1].strip()
            if not name:
                continue
            if not module_names and "name" in name.lower():
                continue
            module_names.append(name)
    print(f"{DONE} UEFIExtract GUID CSV module name(s): {len(module_names)}")
    return module_names


def has_pe_signature(path):
    try:
        with Path(path).open("rb") as infile:
            header = infile.read(0x1000)
    except OSError:
        return False

    if len(header) < 0x40 or header[:2] != b"MZ":
        return False
    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    return len(header) >= pe_offset + 4 and header[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def find_uefiextract_body_files(dump_dir):
    body_files = []
    for path in Path(dump_dir).rglob("body.bin"):
        if not path.is_file():
            continue
        parent_name = path.parent.name.lower()
        if "pe32 image section" not in parent_name:
            continue
        if not has_pe_signature(path):
            continue
        body_files.append(path)
    return sorted(body_files, key=lambda path: str(path).lower())


def fallback_uefiextract_module_name(body_path, dump_dir, index):
    dump_dir = Path(dump_dir).resolve()
    for parent in Path(body_path).resolve().parents:
        if parent == dump_dir:
            break
        parent_name = parent.name
        lowered = parent_name.lower()
        if "pe32 image section" in lowered or "section" in lowered:
            continue
        if "volume" in lowered or "padding" in lowered:
            continue
        return sanitize_module_filename(parent_name)
    return f"uefiextract_body_{index + 1:04d}"


def copy_uefiextract_bodies_as_efi(dump_dir, csv_path, staging_dir):
    staging_dir = Path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)
    module_names = parse_uefiextract_module_names(csv_path)
    body_files = find_uefiextract_body_files(dump_dir)
    copied = []

    print(f"{DONE} UEFIExtract PE32 body candidate(s): {len(body_files)}")
    for index, body_path in enumerate(body_files):
        if index < len(module_names):
            module_name = sanitize_module_filename(module_names[index])
        else:
            module_name = fallback_uefiextract_module_name(body_path, dump_dir, index)

        destination = unique_destination_name(staging_dir, f"{module_name}.efi")
        shutil.copy2(body_path, destination)
        copied.append(destination)

    if copied:
        print(f"{DONE} UEFIExtract staged {len(copied)} .efi module candidate(s)")
    return copied


def copy_unique_efi_modules(efi_files, destination_dir):
    destination_dir.mkdir(parents=True, exist_ok=True)
    hashes = {}
    copied = 0
    duplicates = 0

    for source in sorted(set(Path(p) for p in efi_files), key=lambda p: str(p).lower()):
        if not source.is_file() or source.suffix.lower() != ".efi":
            continue

        file_hash = sha256_file(source)
        if file_hash in hashes:
            duplicates += 1
            continue

        destination = unique_destination_name(destination_dir, source.name)
        shutil.copy2(source, destination)
        hashes[file_hash] = destination
        copied += 1

    return copied, duplicates


def find_efi_files(*roots):
    files = []
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        files.extend(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() == ".efi")
    return files


def decode_extensionless_binwalk_blobs(extracted_dir):
    targets = sorted(
        (path for path in extracted_dir.rglob("*") if path.is_file() and not path.suffix),
        key=lambda path: str(path).lower(),
    )
    for target in targets:
        run_command(
            chipsec_command("uefi", "decode", target),
            cwd=target.parent,
            allow_failure=True,
        )
    return len(targets)


def extract_efi_modules(firmware_path, keep_extracted_tree=False):
    firmware = Path(firmware_path).resolve()
    if not firmware.is_file():
        error(f'firmware not found: "{firmware}"')

    module_output_dir = modules_dir()
    recreate_dir(module_output_dir)

    root_work_dir = work_dir()
    root_work_dir.mkdir(parents=True, exist_ok=True)
    extraction_dir = root_work_dir / f"{firmware.name}.contextuefi.tmp"
    recreate_dir(extraction_dir)

    firmware_copy = extraction_dir / firmware.name
    shutil.copy2(firmware, firmware_copy)

    try:
        run_chipsec_decode(firmware_copy, "decode", extraction_dir)
        efi_files = find_efi_files(extraction_dir)
        if not efi_files:
            run_chipsec_decode(firmware_copy, "uefi", extraction_dir)
            efi_files = find_efi_files(extraction_dir)

        efi_files.extend(run_uefiextract_all(firmware_copy, extraction_dir))

        binwalk_dirs = run_binwalk(firmware_copy, extraction_dir)
        if binwalk_dirs:
            decoded = 0
            for binwalk_dir in binwalk_dirs:
                decoded += decode_extensionless_binwalk_blobs(binwalk_dir)
                efi_files.extend(find_efi_files(binwalk_dir))
            print(f"{DONE} decoded {decoded} binwalk blob(s) with CHIPSEC")

        copied, duplicates = copy_unique_efi_modules(efi_files, module_output_dir)
        if copied == 0:
            error("no .efi modules were extracted")

        print(f"{DONE} extracted {copied} .efi module(s) to {module_output_dir}")
        if duplicates:
            print(f"{DONE} skipped {duplicates} duplicate module(s)")
    finally:
        if not keep_extracted_tree and not bool(_config_value("KEEP_EXTRACTED_TREE", False)):
            clear_dir(extraction_dir)


def analyse_module_ghidra(module_name):
    module_path = modules_dir() / module_name
    ghidra_install_dir = get_ghidra_install_dir()
    if not ghidra_install_dir:
        error("check config.json and fill GHIDRA_INSTALL_DIR")

    cmd = [
        *get_pyghidra_python_command(),
        "-m",
        "ghidra_backend.run_module",
        "--mode",
        "context",
        "--module-path",
        str(module_path),
        "--ghidra-install-dir",
        ghidra_install_dir,
    ]

    optional_args = {
        "--project-dir": _config_value("GHIDRA_PROJECT_DIR"),
        "--language": _config_value("GHIDRA_LANGUAGE"),
        "--compiler": _config_value("GHIDRA_COMPILER"),
        "--loader": _config_value("GHIDRA_LOADER"),
        "--vendor-dir": _config_value("PYGHIDRA_VENDOR_DIR"),
    }
    for flag, value in optional_args.items():
        if value:
            cmd.extend([flag, value])

    result = run_command(cmd, cwd=ROOT_DIR, allow_failure=True)
    output = command_output(result)
    if result.returncode != 0:
        message = output or command_message(result)
        if result.returncode == UNSUPPORTED_MODULE_EXIT_CODE or "Unsupported UEFI module" in message:
            return {
                "module": module_name,
                "status": "skipped",
                "message": concise_message(message) or "unsupported UEFI module",
            }
        return {
            "module": module_name,
            "status": "failed",
            "message": concise_message(message) or "Ghidra analysis failed",
        }
    if "Ghidra auto-analysis failed" in output:
        return {
            "module": module_name,
            "status": "warning",
            "message": find_output_line(output, "Ghidra auto-analysis failed") or concise_message(output),
        }
    return {
        "module": module_name,
        "status": "done",
        "message": "",
    }


def analyse_all(max_workers):
    files = sorted(
        path.name for path in modules_dir().iterdir()
        if path.is_file() and path.suffix.lower() == ".efi"
    )
    if not files:
        error(f'no .efi modules found in "{modules_dir()}"')

    total = len(files)
    max_workers = min(max(1, max_workers), total)
    print(f"{DONE} analysing {total} module(s) with {max_workers} worker(s)", flush=True)

    next_index = 0
    completed = 0
    failed = 0
    skipped = 0
    warnings = 0

    def submit_next(executor, futures):
        nonlocal next_index
        module = files[next_index]
        next_index += 1
        print(f"{INFO} START [{next_index}/{total}] {module}", flush=True)
        futures[executor.submit(analyse_module_ghidra, module)] = module

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for _ in range(max_workers):
            submit_next(executor, futures)

        while futures:
            done_futures, _pending = wait(futures, return_when=FIRST_COMPLETED)
            for future in done_futures:
                module = futures.pop(future)
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "module": module,
                        "status": "failed",
                        "message": concise_message(exc) or exc.__class__.__name__,
                    }

                completed += 1
                if result["status"] == "skipped":
                    skipped += 1
                    print(
                        f"{SKIP} [{completed}/{total}] {module}: {result['message']}",
                        flush=True,
                    )
                elif result["status"] == "failed":
                    failed += 1
                    print(
                        f"{ERROR} FAIL [{completed}/{total}] {module}: {result['message']}",
                        flush=True,
                    )
                elif result["status"] == "warning":
                    warnings += 1
                    print(
                        f"{WARN} [{completed}/{total}] {module}: {result['message']}",
                        flush=True,
                    )
                else:
                    print(f"{DONE} [{completed}/{total}] {module}", flush=True)

                if next_index < total:
                    submit_next(executor, futures)

    if skipped:
        print(f"{WARN} skipped {skipped} unsupported module(s)", flush=True)
    if warnings:
        print(f"{WARN} generated partial context for {warnings} module(s)", flush=True)
    if failed:
        print(f"{WARN} failed {failed} module(s); continuing with the remaining context", flush=True)

    produced = total - skipped - failed
    if produced <= 0:
        error("Ghidra did not produce context for any module")


def clear_logs():
    clear_dir(CONTEXT_LOGS)


def collect_context_log(firmware_path, output_dir=None):
    output_dir = Path(output_dir) if output_dir else logs_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    firmware_name = Path(firmware_path).name
    output_path = output_dir / f"{firmware_name}-context.json"
    context = []
    for log_name in sorted(CONTEXT_LOGS.glob("*.json")):
        with log_name.open("r", encoding="utf-8") as infile:
            context.append(json.load(infile))

    with output_path.open("w", encoding="utf-8") as outfile:
        json.dump(context, outfile, indent=4)
    print(f"{DONE} check {output_path} file")


def prepare_modules(firmware_path, reuse_existing_modules, keep_extracted_tree):
    clear_logs()
    CONTEXT_LOGS.mkdir(parents=True, exist_ok=True)
    if reuse_existing_modules:
        return
    extract_efi_modules(firmware_path, keep_extracted_tree=keep_extracted_tree)


def get_context(firmware_path, workers, reuse_existing_modules, keep_extracted_tree, output_dir=None):
    """Extract EFI modules and generate the ContextUEFI dependency JSON."""
    prepare_modules(firmware_path, reuse_existing_modules, keep_extracted_tree)
    analyse_all(max(1, workers))
    collect_context_log(firmware_path, output_dir=output_dir)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ContextUEFI",
        description="ContextUEFI firmware context generator.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    get_context_parser = subparsers.add_parser(
        "get-context",
        help="Extract EFI modules and generate the dependency context JSON.",
    )
    get_context_parser.add_argument("firmware_path")
    get_context_parser.add_argument(
        "-w",
        "--workers",
        default=8,
        type=int,
        help="Number of Ghidra workers. Default: 8.",
    )
    get_context_parser.add_argument(
        "--reuse-existing-modules",
        action="store_true",
        help='Skip extraction and analyze the .efi files already present in "MODULES_DIR".',
    )
    get_context_parser.add_argument(
        "--keep-extracted-tree",
        action="store_true",
        help="Keep the temporary CHIPSEC/UEFIExtract/binwalk extraction tree for debugging.",
    )
    get_context_parser.add_argument(
        "--output-dir",
        help='Directory for the generated "*-context.json" file. Default: LOGS_DIR.',
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "get-context":
        get_context(
            args.firmware_path,
            args.workers,
            args.reuse_existing_modules,
            args.keep_extracted_tree,
            args.output_dir,
        )
        return 0
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
