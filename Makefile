# This tool needs root to read things like /etc/shadow-adjacent files,
# other users' /proc entries, and auth logs — so most targets run with sudo.
# Nothing here installs anything. It's just python3 running a single .py file.
PYTHON := python3
SCRIPT := src/Linux_sys_admin.py
.DEFAULT_GOAL := audit
audit:
	-sudo $(PYTHON) $(SCRIPT) --audit
check:
	-sudo $(PYTHON) $(SCRIPT) --check
users:
	-sudo $(PYTHON) $(SCRIPT) --users
permissions:
	-sudo $(PYTHON) $(SCRIPT) --permissions
suid:
	-sudo $(PYTHON) $(SCRIPT) --suid
processes:
	-sudo $(PYTHON) $(SCRIPT) --processes
network:
	-sudo $(PYTHON) $(SCRIPT) --network
services:
	-sudo $(PYTHON) $(SCRIPT) --services
logs:
	-sudo $(PYTHON) $(SCRIPT) --logs
system:
	-sudo $(PYTHON) $(SCRIPT) --system
track:
	sudo $(PYTHON) $(SCRIPT) -f $(FILES)
list:
	sudo $(PYTHON) $(SCRIPT) --list
untrack:
	sudo $(PYTHON) $(SCRIPT) --remove $(FILES)
version:
	$(PYTHON) $(SCRIPT) --version
# Run make test to verify the standard libraries
test:
	$(PYTHON) tests/verify_stdlib.py $(SCRIPT)
help:
	sudo $(PYTHON) $(SCRIPT) --help
.PHONY: audit check users permissions suid processes network services logs \
        system track list untrack version help test
