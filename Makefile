# SPDX-FileCopyrightText: 2021 Nex Sabre
#
# SPDX-License-Identifier: Apache-2.0

.PHONY: format-check
format-check:
	@echo "Checking format..."
	python -m black --check src/ ptf

.PHONY: format
format:
	@echo "Formatting..."
	python -m black src/ ptf

.PHONY: set-dev
set-dev:
	@echo "Installing dev-dependencies..."
	python -m pip install -r requirements-dev.txt

.PHONY: test
test:
	@echo "Running tests..."
	export PYTHONPATH=${PWD}/src && python -m pytest utests/
