# SPDX-FileCopyrightText: 2021 Nex Sabre
#
# SPDX-License-Identifier: Apache-2.0

.PHONY: format-check
format-check:
	@echo "Checking format..."
	uv run ruff format --check src/ ptf

.PHONY: format
format:
	@echo "Formatting..."
	uv run ruff format src/ ptf

.PHONY: lint
lint:
	@echo "Linting..."
	uv run ruff check .

.PHONY: set-dev
set-dev:
	@echo "Installing dev-dependencies..."
	uv sync --dev

.PHONY: test
test:
	@echo "Running tests..."
	export PYTHONPATH=${PWD}/src && uv run pytest utests/

.PHONY: build
build:
	@echo "Building distributions..."
	uv build
