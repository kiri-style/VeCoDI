#!/usr/bin/env bash
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
PORT="${VECODI_SERIAL_PORT:-}"
RUNS="${VECODI_RUNS:-1}"
C_LIMIT="${VECODI_C_LIMIT:-10}"
MODEL_ID="${VECODI_MODEL_ID:-0x00000001}"

if [ -z "$PORT" ]; then
    printf 'ERROR: set VECODI_SERIAL_PORT to the board serial device.\n' >&2
    exit 2
fi

if [ -x "$ROOT_DIR/.venv-artifact/bin/python" ]; then
    PYTHON="$ROOT_DIR/.venv-artifact/bin/python"
else
    PYTHON="${PYTHON_BIN:-python3}"
fi

mkdir -p "$ROOT_DIR/build"
exec "$PYTHON" "$ROOT_DIR/tools/vecodi_case_study.py" "$PORT" \
    --c-limit "$C_LIMIT" \
    --runs "$RUNS" \
    --model-id "$MODEL_ID" \
    --benchmark-json "$ROOT_DIR/build/case_study_claim1.json" \
    --benchmark-csv "$ROOT_DIR/build/case_study_claim1.csv"