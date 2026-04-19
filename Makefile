# SPDX-FileCopyrightText: 2021 Nex Sabre
#
# SPDX-License-Identifier: Apache-2.0

.PHONY: format-check
format-check:
	@echo "Checking format..."
	uv run black --check src/ ptf

.PHONY: format
format:
	@echo "Formatting..."
	uv run black src/ ptf

.PHONY: set-dev
set-dev:
	@echo "Installing dev-dependencies..."
	# Set up uv for Python dependency management.
	# TODO: Consider using a system-provided package here.
	sudo apt-get install -y curl
	curl -LsSf https://astral.sh/uv/0.6.12/install.sh | sh
	. CI/uv-setup-env.bash && echo "UV_VENV_BIN_DIR=${UV_VENV_BIN_DIR}" && echo "PATH=${PATH}" && uv sync && uv tool update-shell && uv pip install -r requirements-dev.txt

.PHONY: test
test:
	@echo "Running tests..."
	export PYTHONPATH=${PWD}/src && uv run pytest utests/
