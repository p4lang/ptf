#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The P4 Language Consortium
# SPDX-License-Identifier: Apache-2.0

set -eu

if command -v uv >/dev/null 2>&1; then
    exit 0
fi

if command -v curl >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | bash
elif command -v wget >/dev/null 2>&1; then
    wget -qO- https://astral.sh/uv/install.sh | bash
else
    echo "Neither curl nor wget is available to install uv" >&2
    exit 1
fi

UV_INSTALL_DIR="${HOME}/.local/bin"

export PATH="${UV_INSTALL_DIR}:${PATH}"
if [ -n "${GITHUB_PATH:-}" ]; then
    echo "${UV_INSTALL_DIR}" >> "${GITHUB_PATH}"
fi
