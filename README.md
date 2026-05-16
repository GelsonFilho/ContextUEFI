# ContextUEFI

ContextUEFI extracts EFI modules from a BIOS image, analyzes each module with
Ghidra/PyGhidra, and generates a JSON context file used by the Ghidra graph
script to show module interdependencies.

The current project is intentionally focused on one workflow:

```text
BIOS image -> CHIPSEC/UEFIExtract/binwalk extraction -> .efi modules -> PyGhidra analysis -> *-context.json -> Ghidra graph
```

## Requirements

- Python 3
- Ghidra with PyGhidra available
- CHIPSEC inside this project folder as `extractors/chipsec/chipsec_util.py`
- UEFIExtract available as `extractors/uefiextract` or configured in `UEFIEXTRACT_PATH`
- `binwalk` available in `PATH`

If PyGhidra is not installed globally, install it from your Ghidra folder:

```powershell
$env:GHIDRA_INSTALL_DIR="C:\Program Files\ghidra_12.0.1_PUBLIC"
python -m pip install --no-index -f "$env:GHIDRA_INSTALL_DIR\Ghidra\Features\PyGhidra\pypkg\dist" pyghidra
```

## Generate Context

```powershell
python contextuefi.py get-context "C:\path\to\BIOS.bin"
```

Useful options:

```powershell
python contextuefi.py get-context "C:\path\to\BIOS.bin" -w 6
python contextuefi.py get-context "C:\path\to\BIOS.bin" --reuse-existing-modules
python contextuefi.py get-context "C:\path\to\BIOS.bin" --keep-extracted-tree
python contextuefi.py get-context "C:\path\to\BIOS.bin" --output-dir "C:\path\to"
```

The output is written to:

```text
logs/BIOS.bin-context.json
```

The extraction keeps only `.efi` modules in:

```text
modules/
```

Extraction is intentionally redundant. ContextUEFI collects `.efi` files from
CHIPSEC, stages UEFIExtract `PE32 image section/body.bin` files as `.efi`, then
adds any useful binwalk/CHIPSEC nested results. Duplicate modules are removed by
SHA-256 before analysis.

## Docker

Build the image:

```powershell
docker build -t contextuefi .
```

Run it by mounting the folder that contains the BIOS image.

From PowerShell or Windows Terminal:

```powershell
docker run --rm -v "C:\path\to\bios-folder:/data" contextuefi /data/BIOS.bin
```

From WSL/Linux, use the Linux path for the same Windows folder:

```bash
docker run --rm -v "/mnt/c/path/to/bios-folder:/data" contextuefi /data/BIOS.bin
```

The JSON is written next to the input firmware:

```text
C:\path\to\bios-folder\BIOS.bin-context.json
```

During a Docker run, useful paths inside the container are:

```text
/opt/ContextUEFI/modules        extracted .efi modules
/opt/ContextUEFI/work           temporary CHIPSEC/UEFIExtract/binwalk tree
/tmp/contextuefi-context        temporary per-module JSON files
/data                           mounted folder that receives the final JSON
```

You can pass normal `get-context` options after the firmware path:

```powershell
docker run --rm -v "C:\path\to\bios-folder:/data" contextuefi /data/BIOS.bin -w 6
```

```bash
docker run --rm -v "/mnt/c/path/to/bios-folder:/data" contextuefi /data/BIOS.bin -w 6
```

The image installs:

- Ubuntu 24.04
- OpenJDK 21 for Ghidra 12.0.1
- Ghidra 12.0.1 and its bundled PyGhidra package
- CHIPSEC from tag `1.13.20`
- UEFIExtract NE A74
- Binwalk `3.1.0`

Note: `snap install binwalk` is not used inside the Docker build because snap
expects `snapd/systemd` and privileged mount behavior that standard Docker
builds do not provide. The Dockerfile installs the same Binwalk `3.1.0` version
with the upstream Rust package instead.

## Ghidra Graph

Open Ghidra and add this script directory in `Window -> Script Manager`:

```text
ghidra_scripts/
```

Run:

```text
ContextUefiDependencyGraph.java
```

Select the generated `*-context.json` file. The graph connects modules by
protocol GUID:

- Provider: module calls `InstallProtocolInterface` or `InstallMultipleProtocolInterfaces`.
- Client: module calls `LocateProtocol` or `OpenProtocol`.
- Edge: provider module -> client module for the same GUID.

The graph supports full view, focused view, multi-module focus, double-click
navigation, back with `Ctrl+Z`, and mouse-wheel zoom.
