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

.PHONY: coverage
coverage:
	@echo "Running tests with coverage..."
	export PYTHONPATH=${PWD}/src && python -m coverage run --source src/ -m pytest utests/

.PHONY: coverage-check
coverage-check:
	@echo "Checking coverage..."
	python -m coverage report --fail-under=28

.PHONY: coverage-all
coverage-all: coverage coverage-check
