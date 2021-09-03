.PHONY: check
check:
	@echo "Checking format..."
	python -m black --check src/
	python -m isort --check src/ --profile black


.PHONY: format-isort
format-isort:
	@echo "Formatting imports..."
	python -m isort src/ --profile black

.PHONY: format-black
format-black:
	@echo "Formatting code..."
	python -m black src/


.PHONY: format
format: format-black format-isort
	

.PHONY: set-dev
set-dev:
	@echo "Installing dev-dependencies..."
	python -m pip install -r requirements-dev.txt
