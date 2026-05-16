# SPDX-License-Identifier: MIT

import os
import shutil
import sys
import sysconfig
import tempfile
import time
import zipfile
from pathlib import Path


def _extract_wheel_once(wheel_path, target_dir):
    marker = target_dir / ".extracted"
    if marker.exists():
        return target_dir

    if target_dir.exists():
        shutil.rmtree(target_dir)

    temp_dir = target_dir.with_name(f"{target_dir.name}.tmp")
    if temp_dir.exists():
        shutil.rmtree(temp_dir)

    temp_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel_path) as archive:
        archive.extractall(temp_dir)
    (temp_dir / ".extracted").write_text(wheel_path.name, encoding="utf-8")
    temp_dir.rename(target_dir)
    return target_dir


def _get_platform_filter():
    if sys.platform == "win32":
        return lambda name: name.endswith("win_amd64.whl")
    if sys.platform.startswith("linux"):
        machine = os.uname().machine.lower()
        if machine in ("aarch64", "arm64"):
            return lambda name: "manylinux_2_17_aarch64" in name
        return lambda name: "manylinux_2_17_x86_64" in name
    if sys.platform == "darwin":
        return lambda name: "macosx" in name
    return lambda _name: False


def _get_jpype_wheel(dist_dir):
    platform_tag = sysconfig.get_platform().lower()
    if "mingw" in platform_tag:
        raise RuntimeError(
            "The current Python interpreter uses the MinGW ABI. "
            "Set PYGHIDRA_PYTHON_PATH to a standard CPython executable."
        )

    cp_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    candidates = sorted(dist_dir.glob(f"jpype1-*-{cp_tag}-{cp_tag}-*.whl"))
    platform_filter = _get_platform_filter()
    candidates = [wheel for wheel in candidates if platform_filter(wheel.name)]
    if not candidates:
        raise RuntimeError(
            "Unable to find a bundled JPype wheel compatible with this Python "
            f"interpreter ({platform_tag})."
        )
    return candidates[0]


def _get_single_wheel(dist_dir, pattern):
    candidates = sorted(dist_dir.glob(pattern))
    if not candidates:
        raise RuntimeError(f"Missing bundled wheel matching {pattern}")
    return candidates[0]


def ensure_pyghidra(ghidra_install_dir, vendor_dir=None):
    install_dir = Path(ghidra_install_dir)
    dist_dir = install_dir / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "dist"
    if not dist_dir.is_dir():
        raise RuntimeError(f"PyGhidra wheel directory not found: {dist_dir}")

    if vendor_dir is None:
        vendor_dir = (
            Path(tempfile.gettempdir())
            / "uefi-retool-pyghidra"
            / f"cp{sys.version_info.major}{sys.version_info.minor}"
        )
    vendor_dir = Path(vendor_dir)
    vendor_dir.mkdir(parents=True, exist_ok=True)
    lock_path = vendor_dir / ".lock"

    lock_fd = None
    timeout_at = time.time() + 120
    while lock_fd is None:
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if time.time() > timeout_at:
                raise RuntimeError(f"Timed out waiting for PyGhidra bootstrap lock: {lock_path}")
            time.sleep(0.2)

    try:
        wheels = [
            _get_single_wheel(dist_dir, "packaging-*.whl"),
            _get_jpype_wheel(dist_dir),
            _get_single_wheel(dist_dir, "pyghidra-*.whl"),
        ]

        extracted = []
        for wheel in wheels:
            target = vendor_dir / wheel.stem
            extracted.append(_extract_wheel_once(wheel, target))
    finally:
        os.close(lock_fd)
        try:
            os.remove(lock_path)
        except FileNotFoundError:
            pass

    for target in reversed(extracted):
        text = str(target)
        if text not in sys.path:
            sys.path.insert(0, text)

    os.environ["GHIDRA_INSTALL_DIR"] = str(install_dir)
