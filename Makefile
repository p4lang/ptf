.PHONY: format-check
format-check:
	@echo "Checking format..."
	python -m black --check src/ ptf_nn/ example/ utests/ ptf

.PHONY: format
format:
	@echo "Formatting..."
	python -m black src/ ptf_nn/ example/ utests/ ptf

.PHONY: set-dev
set-dev:
	@echo "Installing dev-dependencies..."
	python -m pip install -r requirements-dev.txt
