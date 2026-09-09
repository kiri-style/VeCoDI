#!/usr/bin/env bash
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VECODI_VENV_DIR:-$ROOT_DIR/.venv-artifact}"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    printf 'ERROR: %s is required.\n' "$PYTHON_BIN" >&2
    exit 1
}

"$PYTHON_BIN" -m venv "$VENV_DIR"
# shellcheck disable=SC1091
. "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip
python -m pip install -r "$ROOT_DIR/requirements-artifact.txt"

printf '\nArtifact host dependencies installed in %s\n' "$VENV_DIR"
printf 'Hardware build prerequisites are documented in README.txt.\n'