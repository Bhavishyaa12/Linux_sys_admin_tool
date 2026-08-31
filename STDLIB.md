# STDLIB.md

Every third-party package I would normally reach for and what standard-library
code replaced it in `Linux_sys_admin.py`

| Third-party package | Standard library used instead | Why |
|---|---|---|
| `click` | `argparse` | CLI flag parsing, subcommand-style dispatch, and auto-generated `--help` — all built into `argparse`, no need for a heavier CLI framework. |
| `psutil` (process listing) | `os.listdir("/proc")` + reading `/proc/<pid>/status` and `/proc/<pid>/cmdline` by hand | `psutil` normally wraps exactly this the linux kernel already exposes live process data as files under `/proc`so reading it directly avoids the dependency entirely |
| `psutil` (network connections) | manual parsing of `/proc/net/tcp`, `/proc/net/udp` (and their ipv6 variants) | Same idea as above — listening ports and connection states are already text-encoded in `/proc/net/*`; |
| `rich` / `colorama` | raw ANSI escape codes (`\033[91m`, etc) | Terminal color codes are a fixed well-known standard — no library needed change the color of the output |
| `watchdog` / `tripwire`-style HIDS packages | `hashlib.sha256` + periodic polling in `check_hashes()` | `watchdog` gives real time filesystem event notifications, this tool instead does point in time integrity checks by re-hashing and comparing on demand which needs no event watching layer at all. |
| `xxhash` | `hashlib.sha256` | `xxhash` is faster but non cryptographic. For file-integrity checking a cryptographic hash matters more than raw speed so the stdlib's `hashlib` was the correct library to be used |
| `sdbus` / `systemd-python` | `subprocess.run(["systemctl", "list-units", ...])` | Talking to systemd over D-Bus directly needs a third-party binding shelling out to the `systemctl` binary (already present on any systemd machine) avoids that while still getting the same service list. |
| `tabulate` / `prettytable` | manual f-string column formatting (e.g. in `audit_users()`, `audit_processes()`) | The aligned-column output (`f"{name:<20}{uid:<8}..."`) is just Python string formatting — no table-rendering library needed for fixed-width terminal output. |
| `pyyaml` / `toml` (as a config/state format) | `json` | The hash database (`hashes.json`) needed a structured human-readable format for storage `json` is fully built into Python and round-trips cleanly so there was no reason to reach for a YAML/TOML library that isn't even in the stdlib for writing. |
| `filelock` | `os.replace()` rename pattern in `save_hashes()` | Instead of a cross-process file-locking library the database is written to a temp file first, then atomically swapped into place with `os.replace()` — this avoids partial/corrupted writes without needing a locking dependency. |
| `pwd`-equivalent third-party user-lookup helpers | `pwd` / `grp` (already stdlib, called out for completeness) | UID→username and GID→groupname resolution is done via Python's built-in `pwd.getpwuid()` and `grp.getgrgid()` — some cross-platform libraries wrap this but on Linux it's already stdlib. |
| `argcomplete` | hand-written `bash_tab_complete.bash` | Rather than a Python package for shell tab-completion completion is implemented as a plain bash function registered with the shell's builtin `complete` command — zero Python dependency and it's optional tooling anyway (not part of the runtime artifact). |

**Note:** every substitution above reflects a real design decision made while building this tool.It took me hours to find a standard library for watchdog though as watchdog checks the filesystem in real time I then thought to implement hashes to check dynamically whenever the user asks for it.If a stdlib substitute was slower, less capable, or a real tradeoff (e.g. `hashlib.sha256` vs `xxhash`, or point-in-time polling vs `watchdog`'s real-time events), that tradeoff is written plainly above rather than gloriffying it 
