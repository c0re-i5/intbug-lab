# Protocol Integer-Bug Lab — common entrypoints
.PHONY: help battery battery-light up down test proof zero-wu

help:
	@echo "make battery       - up targets + unit tests + full battery (./scripts/run-all.sh)"
	@echo "make battery-light - same, skip cleanup_overcredit (~45s each)"
	@echo "make up            - start all loopback targets"
	@echo "make down          - tear down all lab containers"
	@echo "make test          - offline unit tests only"
	@echo "make proof         - slice-2 single-target accounting proof vs nginx 1.31.8"

battery:
	./scripts/run-all.sh

battery-light:
	./scripts/run-all.sh --skip-heavy

up:
	./scripts/box-dockerd.sh
	./scripts/lab-up-targets.sh

down:
	./scripts/lab-down-targets.sh

test:
	.venv/bin/python -m unittest discover -s ours/tests -v

proof:
	./scripts/lab-up.sh
	./scripts/ours-proof.sh

zero-wu:
	./scripts/capture-zero-wu.py
	./scripts/run-h2spec-zero-wu.sh
