.DEFAULT_GOAL := help
SHELL := bash

# Commands here are the ones .github/workflows/ci.yml runs.

.PHONY: help install build test test-install test-old-core lint fmt clean

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-13s %s\n", $$1, $$2}'

F2B_DIR := .cache/fail2ban

install: ## Install the pinned ansible tools, and unpack Fail2Ban's Python package for the action test
	python3 -m pip install -r requirements-dev.txt
	@if python3 -c 'import sys; sys.path.insert(0, "/usr/lib/python3/dist-packages"); import fail2ban' 2>/dev/null; then \
		echo "fail2ban Python package found"; \
	elif command -v apt-get >/dev/null 2>&1 && command -v dpkg-deb >/dev/null 2>&1; then \
		rm -rf $(F2B_DIR) && mkdir -p $(F2B_DIR) && cd $(F2B_DIR) \
		&& apt-get download fail2ban && dpkg-deb -x fail2ban_*.deb root \
		&& echo "fail2ban unpacked into $(F2B_DIR)/root (no service installed)"; \
	else \
		echo "NOTE: no apt-get/dpkg-deb here; test/fail2ban_action.py needs the fail2ban Python package (set GEN0SEC_FAIL2BAN_PYTHONPATH to its dist-packages)"; \
	fi

build: ## Syntax-check the playbook
	ansible-playbook -i localhost, --syntax-check playbook.yml

test: ## Run the tests that need no synapse binary
	shellcheck test/*.sh
	bash test/render_and_check.sh
	ANSIBLE_GATHERING=explicit bash test/api_key_precedence.sh
	GEN0SEC_FAIL2BAN_PYTHONPATH="$$(pwd)/$(F2B_DIR)/root/usr/lib/python3/dist-packages" bash test/fail2ban_render.sh
	GEN0SEC_FAIL2BAN_PYTHONPATH="$$(pwd)/$(F2B_DIR)/root/usr/lib/python3/dist-packages" python3 test/fail2ban_action.py
	bash test/package_selection.sh
	bash test/no_secret_in_output.sh
	bash test/secret_protections.sh
	bash test/verify_key.sh
	bash test/apt_refresh.sh

DISTRO ?= ubuntu
MODE ?= agent
test-install: ## Install in a systemd container (DISTRO=ubuntu|oracle MODE=agent|proxy); needs docker and GEN0SEC_REPO_KEY
	bash test/install_in_container.sh $(DISTRO) $(MODE)

test-old-core: ## Run the fail2ban role on ansible-core 2.14 (Oracle Linux 9) in docker; needs docker
	bash test/old_ansible_core.sh

lint: ## yamllint and ansible-lint
	yamllint .
	ansible-lint

fmt: ## No formatter is used; yamllint (make lint) checks the YAML style
	@echo "fmt: nothing to format, no formatter is configured; run 'make lint' for yamllint"

clean: ## Remove local ansible and lint caches
	rm -rf .ansible .cache
	find . -name '*.retry' -delete
