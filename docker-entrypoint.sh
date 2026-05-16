#!/usr/bin/env bash
set -euo pipefail

CONTEXTUEFI_HOME="${CONTEXTUEFI_HOME:-/opt/ContextUEFI}"

show_help() {
  cat <<'EOF'
ContextUEFI Docker usage:

  docker run --rm -v /path/to/bios-folder:/data contextuefi /data/binario.bin
  docker run --rm -v /path/to/bios-folder:/data contextuefi /data/binario.bin -w 6

The generated JSON is written next to the input firmware:

  /data/binario.bin-context.json

Advanced:

  docker run --rm -v /path/to/bios-folder:/data contextuefi get-context /data/binario.bin --output-dir /data
EOF
}

if [[ $# -eq 0 || "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  show_help
  exit 0
fi

if [[ "${1:-}" == "get-context" ]]; then
  exec python "${CONTEXTUEFI_HOME}/contextuefi.py" "$@"
fi

firmware_path="$1"
shift

if [[ ! -f "$firmware_path" ]]; then
  echo "ERROR firmware not found: $firmware_path" >&2
  exit 1
fi

output_dir="$(dirname "$(realpath "$firmware_path")")"
exec python "${CONTEXTUEFI_HOME}/contextuefi.py" get-context "$firmware_path" --output-dir "$output_dir" "$@"
