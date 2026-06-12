.PHONY: install test lint gate0 gate2 gate3 clean
install:
	pip install -e ".[dev]"
test:
	pytest -q
lint:
	ruff check .
gate0:  ## behavioural monitor (strace) on the micro-benchmark
	python -m experiments.gate0_runner
gate2:  ## text-monitor obfuscation gap (add --redcode data/RedCode for the real run)
	python -m experiments.gate2_text_monitors --dry-run
gate3:  ## R-Judge anchor (add --rjudge data/R-Judge for the real run)
	python -m experiments.gate3_rjudge_repro --dry-run
clean:
	rm -rf .pytest_cache .ruff_cache *.egg-info build results/gate0_workspace results/gate3_cache.json
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
