#!/bin/sh
set -e

PACKAGE="leakscan"
CMD="leakscan"

info()  { printf '%s\n' "$1"; }
error() { printf 'error: %s\n' "$1" >&2; exit 1; }

has() { command -v "$1" >/dev/null 2>&1; }

if has pipx; then
    info "Installing $PACKAGE via pipx..."
    pipx install "$PACKAGE"
elif has uv; then
    info "Installing $PACKAGE via uv tool..."
    uv tool install "$PACKAGE"
elif has pip3; then
    info "Installing $PACKAGE via pip3 (user install)..."
    pip3 install --user "$PACKAGE"
elif has pip; then
    info "Installing $PACKAGE via pip (user install)..."
    pip install --user "$PACKAGE"
else
    error "No package manager found. Install pipx, uv, or pip first.\n  pipx: https://pipx.pypa.io\n  uv:   https://docs.astral.sh/uv"
fi

if has "$CMD"; then
    info ""
    info "leakscan installed successfully. Run: $CMD --help"
else
    info ""
    info "Installed. If '$CMD' is not found, add the following to your shell profile:"
    info "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
