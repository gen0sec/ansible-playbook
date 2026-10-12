.DEFAULT_GOAL := help
SHELL := bash

# Commands here are the ones .github/workflows/ci.yml runs.

.PHONY: help install build test lint fmt clean

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

install: ## Install the pinned ansible-core, ansible-lint and yamllint, and Fail2Ban's Python package
	python3 -m pip install -r requirements-dev.txt
	python3 -c 'import sys; sys.path.insert(0, "/usr/lib/python3/dist-packages"); import fail2ban' 2>/dev/null \
		|| sudo apt-get install -y fail2ban

build: ## Syntax-check the playbook
	ansible-playbook -i localhost, --syntax-check playbook.yml

test: ## Run the tests that need no synapse binary
	shellcheck test/*.sh
	bash test/render_and_check.sh
	ANSIBLE_GATHERING=explicit bash test/api_key_precedence.sh
	bash test/fail2ban_render.sh
	python3 test/fail2ban_action.py

lint: ## yamllint and ansible-lint
	yamllint .
	ansible-lint

fmt: ## No formatter is used; yamllint (make lint) checks the YAML style
	@echo "fmt: nothing to format, no formatter is configured; run 'make lint' for yamllint"

clean: ## Remove local ansible and lint caches
	rm -rf .ansible .cache
	find . -name '*.retry' -delete
