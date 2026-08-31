#!/usr/bin/env python3
""" Author : Bhavishya
    Current python version in which this script is built is 3.13.5 """

import os
import sys
import platform
import argparse
import hashlib
import time
import json
import stat
import pwd
import grp
import subprocess
from datetime import datetime

# print(Fore.RED + f"Heyy {os.getenv("USER")} ")
# Global Variables and functions
script_name = sys.argv[0]
filename = ["/etc/passwd", "/etc/group"]
output_file = os.path.expanduser("~/hashes.json")
date = datetime.now().strftime("%d-%m-%Y at %I:%M %p")

# Colors for output
red = "\033[91m"
green = "\033[92m"
yellow = "\033[93m"
reset = "\033[0m"

# Exit status codes
success = 0
failure = 1
error = 2

# Audit limits
MAX_PERMISSION_SCAN = 100000
MAX_SUID_SCAN = 100000

AUTH_FAILURE_WARNING_THRESHOLD = 5
AUTH_FAILURE_CRITICAL_THRESHOLD = 20

def sleep():
    time.sleep(0.5)

def normalize_path(filepath):
    # Convert a path into an absolute normalized path
    return os.path.abspath(os.path.expanduser(filepath))

def human_readable_size(size):
    units = ["B", "K", "M", "G", "T", "P"]
    current_size = size

    for unit in units:
        if current_size < 1024:
            return f"{current_size:.1f}{unit}"
        current_size /= 1024

    return f"{current_size:.1f}E"

def format_mtime(timestamp):
    # Convert modification time into a readable date and time
    return datetime.fromtimestamp(timestamp).strftime(
        "%d-%m-%Y %I:%M:%S %p"
    )

def get_username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)

def get_groupname(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)

def calculate_hash(filepath):
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)

    except FileNotFoundError:
        print(red + f"File not found: {filepath}" + reset)
        return None

    except PermissionError:
        print(red + f"Permission denied: {filepath}" + reset)
        return None

    except IsADirectoryError:
        print(red + f"Not a regular file: {filepath}" + reset)
        return None

    except OSError as error:
        print(red + f"Unable to read {filepath}: {error}" + reset)
        return None

    return sha256.hexdigest()

def get_metadata(filepath):
    try:
        file_stat = os.stat(filepath)

        return {
            "size": file_stat.st_size,
            "mode": stat.S_IMODE(file_stat.st_mode),
            "uid": file_stat.st_uid,
            "gid": file_stat.st_gid,
            "mtime": format_mtime(file_stat.st_mtime)
        }

    except FileNotFoundError:
        print(red + f"File not found: {filepath}" + reset)
        return None

    except PermissionError:
        print(red + f"Permission denied: {filepath}" + reset)
        return None

    except OSError as error:
        print(
            red +
            f"Unable to read metadata for {filepath}: {error}" +
            reset
        )
        return None

def get_file_info(filepath):
    file_hash = calculate_hash(filepath)

    if file_hash is None:
        return None

    metadata = get_metadata(filepath)

    if metadata is None:
        return None

    return {
        "sha256": file_hash,
        "size": metadata["size"],
        "mode": metadata["mode"],
        "uid": metadata["uid"],
        "gid": metadata["gid"],
        "mtime": metadata["mtime"]
    }

def load_hashes():
    try:
        with open(output_file, "r") as f:
            database = json.load(f)

        if not isinstance(database, dict):
            print(red + "Invalid hash database format." + reset)
            return None

        if "files" not in database:
            print(red + "Hash database is missing file information." + reset)
            return None

        if not isinstance(database["files"], dict):
            print(red + "Invalid file information in hash database." + reset)
            return None

        return database

    except FileNotFoundError:
        return None

    except PermissionError:
        print(red + "Permission denied while reading hash database." + reset)
        return None

    except json.JSONDecodeError:
        print(red + "Hash database is corrupted or invalid." + reset)
        return None

    except OSError as error:
        print(red + f"Unable to read hash database: {error}" + reset)
        return None

def save_hashes(stored_hashes):
    temp_file = output_file + ".tmp"

    database = {
        "generated_by": script_name,
        "created": date,
        "files": stored_hashes
    }

    try:
        with open(temp_file, "w") as f:
            json.dump(database, f, indent=4)

        os.chmod(temp_file, 0o600)
        os.replace(temp_file, output_file)
        return True

    except PermissionError:
        print(red + "Permission denied while updating hash database." + reset)

    except OSError as error:
        print(red + f"Unable to update hash database: {error}" + reset)

    if os.path.exists(temp_file):
        try:
            os.remove(temp_file)
        except OSError:
            pass

    return False

def create_hashes(files=None):
    if files is None:
        files = filename

    stored_hashes = {}

    for filepath in files:
        filepath = normalize_path(filepath)

        if not os.path.isfile(filepath):
            print(
                yellow +
                f"Skipping non-regular file: {filepath}" +
                reset
            )
            continue

        file_info = get_file_info(filepath)

        if file_info is not None:
            stored_hashes[filepath] = file_info

    if not stored_hashes:
        print(red + "No valid files were found." + reset)
        return False

    if save_hashes(stored_hashes):
        print(
            green +
            f"Hash database created: {output_file}" +
            reset
        )
        return True

    return False

def check_hashes():
    database = load_hashes()

    if database is None:
        print(red + "Hash database does not exist." + reset)
        print("Run -f first.")
        return error

    stored_hashes = database.get("files", {})

    if not stored_hashes:
        print(yellow + "No files are currently tracked." + reset)
        return success

    changed = False
    missing = False
    checked = 0

    print("Checking file integrity...")
    print()

    for filepath, old_info in stored_hashes.items():

        if not os.path.exists(filepath):
            print(red + f"File missing: {filepath}" + reset)
            print(
                f"Remove it with: "
                f"--remove {filepath}"
            )
            missing = True
            continue

        current_info = get_file_info(filepath)

        if current_info is None:
            continue

        checked += 1
        file_changed = False

        if old_info["sha256"] != current_info["sha256"]:
            print(red + f"Content changed: {filepath}" + reset)
            print(f"  Expected SHA-256: {old_info['sha256']}")
            print(f"  Current SHA-256:  {current_info['sha256']}")
            file_changed = True

        if old_info["size"] != current_info["size"]:
            old_size = human_readable_size(old_info["size"])
            current_size = human_readable_size(current_info["size"])

            print(
                yellow +
                f"Size changed: {filepath} "
                f"({old_size} -> {current_size})" +
                reset
            )
            file_changed = True

        if old_info["mode"] != current_info["mode"]:
            old_mode = oct(old_info["mode"])[2:].zfill(4)
            current_mode = oct(current_info["mode"])[2:].zfill(4)

            print(
                yellow +
                f"Permissions changed: {filepath} "
                f"({old_mode} -> {current_mode})" +
                reset
            )
            file_changed = True

        if old_info["uid"] != current_info["uid"]:
            old_user = get_username(old_info["uid"])
            current_user = get_username(current_info["uid"])

            print(
                yellow +
                f"Owner changed: {filepath} "
                f"({old_user} -> {current_user})" +
                reset
            )
            file_changed = True

        if old_info["gid"] != current_info["gid"]:
            old_group = get_groupname(old_info["gid"])
            current_group = get_groupname(current_info["gid"])

            print(
                yellow +
                f"Group changed: {filepath} "
                f"({old_group} -> {current_group})" +
                reset
            )
            file_changed = True

        if old_info["mtime"] != current_info["mtime"]:
            print(
                yellow +
                f"Modification time changed: {filepath}" +
                reset
            )
            print(f"  Expected: {old_info['mtime']}")
            print(f"  Current:  {current_info['mtime']}")
            file_changed = True

        if file_changed:
            changed = True
        else:
            print(green + f"OK: {filepath}" + reset)

    print()

    if not changed and not missing:
        print(
            green +
            f"Integrity check passed. {checked} file(s) verified." +
            reset
        )
        return success

    print(red + "File integrity check failed." + reset)
    return failure

def add_files(files):
    database = load_hashes()

    if database is None:
        print(red + "Hash database does not exist." + reset)
        print("Run -f first.")
        return error

    stored_hashes = database.get("files", {})
    new_files = False

    for filepath in files:
        filepath = normalize_path(filepath)

        if not os.path.isfile(filepath):
            print(
                red +
                f"Not a regular file: {filepath}" +
                reset
            )
            continue

        if filepath in stored_hashes:
            print(
                yellow +
                f"Already tracked: {filepath}" +
                reset
            )
            continue

        file_info = get_file_info(filepath)

        if file_info is None:
            continue

        stored_hashes[filepath] = file_info

        print(
            green +
            f"Added: {filepath}" +
            reset
        )

        new_files = True

    if not new_files:
        return success

    if save_hashes(stored_hashes):
        print(
            green +
            "Hash database updated." +
            reset
        )
        return success

    return error

def list_files():
    database = load_hashes()

    if database is None:
        print(
            red +
            "Hash database does not exist.Run -f first" +
            reset
        )
        return error

    stored_hashes = database.get("files", {})

    print("Tracked files:")
    print()

    if not stored_hashes:
        print("  No files are currently tracked.")
    else:
        for filepath in sorted(stored_hashes):
            info = stored_hashes[filepath]

            print(
                f"  {filepath} "
                f"({human_readable_size(info['size'])})"
            )

    print()
    print(f"Total files: {len(stored_hashes)}")

    return success

def remove_files(files):
    database = load_hashes()

    if database is None:
        print(
            red +
            "Hash database does not exist.Run -f first" +
            reset
        )
        return error

    stored_hashes = database.get("files", {})
    removed = False

    for filepath in files:
        filepath = normalize_path(filepath)

        if filepath not in stored_hashes:
            print(
                yellow +
                f"File is not tracked: {filepath}" +
                reset
            )
            continue

        del stored_hashes[filepath]

        print(
            green +
            f"Removed from tracking: {filepath}" +
            reset
        )

        removed = True

    if not removed:
        return success

    if save_hashes(stored_hashes):
        print(
            green +
            "Hash database updated." +
            reset
        )
        return success

    return error

def audit_users():
    print("User account check")
    print()

    issues = 0
    uid_zero_accounts = []

    try:
        users = pwd.getpwall()
    except OSError as error:
        print(red + f"Unable to read user database: {error}" + reset)
        return error

    print(
        f"{'USER':<20}"
        f"{'UID':<8}"
        f"{'GID':<8}"
        f"SHELL"
    )

    for user in users:
        if user.pw_uid == 0:
            uid_zero_accounts.append(user.pw_name)

        print(
            f"{user.pw_name:<20}"
            f"{user.pw_uid:<8}"
            f"{user.pw_gid:<8}"
            f"{user.pw_shell}"
        )

    print()

    if len(uid_zero_accounts) > 1:
        print(red + "WARNING: Multiple UID 0 accounts detected:" + reset)

        for user in uid_zero_accounts:
            print(f"  {user}")

        issues += 1
    else:
        print(green + "OK: Only root has UID 0." + reset)

    return failure if issues else success

def audit_permissions():
    print("Permission audit")
    print()

    roots = [
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin"
    ]

    world_writable_files = []
    world_writable_dirs = []
    scanned = 0

    # NOTE: files and directories are now checked in a single os.walk pass
    # per root instead of walking each tree twice. Halves the filesystem
    # I/O on large trees like /etc and /usr/bin.
    for root in roots:
        if not os.path.exists(root):
            continue

        stop_scanning = False

        for current_root, dirs, files in os.walk(
            root,
            topdown=True,
            followlinks=False
        ):
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(
                    os.path.join(current_root, d)
                )
            ]

            for name in dirs:
                filepath = os.path.join(current_root, name)

                try:
                    mode = os.stat(filepath).st_mode
                except (OSError, PermissionError):
                    continue

                if mode & stat.S_IWOTH:
                    world_writable_dirs.append(filepath)

            for name in files:
                if scanned >= MAX_PERMISSION_SCAN:
                    stop_scanning = True
                    break

                filepath = os.path.join(current_root, name)

                try:
                    mode = os.stat(filepath).st_mode
                except (OSError, PermissionError):
                    continue

                scanned += 1

                if mode & stat.S_IWOTH:
                    world_writable_files.append(filepath)

            if stop_scanning:
                break

        if stop_scanning:
            continue

    if world_writable_files:
        print(red + "World-writable files:" + reset)

        for filepath in world_writable_files:
            print(f"  {filepath}")
    else:
        print(green + "OK: No world-writable files found." + reset)

    print()

    if world_writable_dirs:
        print(red + "World-writable directories:" + reset)

        for filepath in world_writable_dirs:
            print(f"  {filepath}")
    else:
        print(green + "OK: No world-writable directories found." + reset)

    print()

    if world_writable_files or world_writable_dirs:
        return failure

    return success

def audit_suid():
    print("SUID / SGID audit")
    print()

    roots = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin"
    ]

    suid_files = []
    sgid_files = []
    scanned = 0

    for root in roots:
        if not os.path.exists(root):
            continue

        for current_root, dirs, files in os.walk(
            root,
            topdown=True,
            followlinks=False
        ):
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(
                    os.path.join(current_root, d)
                )
            ]

            for name in files:
                if scanned >= MAX_SUID_SCAN:
                    break

                filepath = os.path.join(current_root, name)

                try:
                    mode = os.stat(filepath).st_mode
                except (OSError, PermissionError):
                    continue

                scanned += 1

                if mode & stat.S_ISUID:
                    suid_files.append(filepath)

                if mode & stat.S_ISGID:
                    sgid_files.append(filepath)

            if scanned >= MAX_SUID_SCAN:
                break

        if scanned >= MAX_SUID_SCAN:
            break

    print(f"SUID files: {len(suid_files)}")

    for filepath in suid_files:
        print(f"  {filepath}")

    print()

    print(f"SGID files: {len(sgid_files)}")

    for filepath in sgid_files:
        print(f"  {filepath}")

    print()

    print(
        red +
        "Note: SUID/SGID files are not automatically threat to the system" +
        reset
    )

    return success

def read_proc_file(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except (FileNotFoundError, PermissionError, OSError):
        return None

def audit_processes():
    print("Process which are running right now")
    print()

    proc_path = "/proc"

    if not os.path.isdir(proc_path):
        print(red + "/proc is unavailable.Or the kernel is not allowing the user to access this virtual filesystem" + reset)
        return error

    processes = []

    for entry in os.listdir(proc_path):
        if not entry.isdigit():
            continue

        pid = entry

        status = read_proc_file(
            os.path.join(proc_path, pid, "status")
        )

        cmdline = read_proc_file(
            os.path.join(proc_path, pid, "cmdline")
        )

        if status is None:
            continue

        name = pid
        uid = "?"

        for line in status.splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()

            elif line.startswith("Uid:"):
                uid = line.split()[1]

        if cmdline:
            command = cmdline.replace("\x00", " ").strip()
        else:
            command = name

        processes.append(
            (int(pid), uid, name, command)
        )

    processes.sort(key=lambda item: item[0])

    print(
        f"{'PID':<8}"
        f"{'UID':<8}"
        f"{'NAME':<20}"
        f"COMMAND"
    )

    print("-" * 80)

    for pid, uid, name, command in processes:
        print(
            f"{pid:<8}"
            f"{uid:<8}"
            f"{name[:19]:<20}"
            f"{command[:60]}"
        )

    print()
    print(f"Total processes: {len(processes)}")

    return success

def parse_proc_net_file(filepath, protocol):
    connections = []

    data = read_proc_file(filepath)

    if data is None:
        return connections

    for line in data.splitlines()[1:]:
        fields = line.split()

        if len(fields) < 4:
            continue

        local_address = fields[1]
        remote_address = fields[2]
        state = fields[3]

        try:
            local_port = int(
                local_address.split(":")[-1],
                16
            )

            remote_port = int(
                remote_address.split(":")[-1],
                16
            )
        except ValueError:
            continue

        connections.append(
            {
                "protocol": protocol,
                "state": state,
                "local_port": local_port,
                "remote_port": remote_port
            }
        )

    return connections

def audit_network():
    print("Network audit")
    print()

    connections = []

    connections.extend(
        parse_proc_net_file(
            "/proc/net/tcp",
            "TCP"
        )
    )

    connections.extend(
        parse_proc_net_file(
            "/proc/net/tcp6",
            "TCP6"
        )
    )

    connections.extend(
        parse_proc_net_file(
            "/proc/net/udp",
            "UDP"
        )
    )

    connections.extend(
        parse_proc_net_file(
            "/proc/net/udp6",
            "UDP6"
        )
    )

    listening = [
        connection
        for connection in connections
        if connection["state"] == "0A"
    ]

    print(
        f"{'PROTOCOL':<10}"
        f"{'PORT':<10}"
        f"{'STATE':<10}"
    )

    print("-" * 30)

    for connection in listening:
        print(
            f"{connection['protocol']:<10}"
            f"{connection['local_port']:<10}"
            f"{connection['state']:<10}"
        )

    print()

    if listening:
        print(
            yellow +
            "Listening ports:" +
            reset
        )

        ports = sorted(
            set(
                connection["local_port"]
                for connection in listening
            )
        )

        for port in ports:
            print(f"  {port}")
    else:
        print(
            green +
            "No listening TCP/UDP ports detected." +
            reset
        )

    return success

def audit_services():
    print("Service audit")
    print()

    if not os.path.exists("/run/systemd/system"):
        print(
            yellow +
            "systemd does not appear to be running." +
            reset
        )
        return success

    try:
        # Bash specific commands
        result = subprocess.run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-pager",
                "--no-legend"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

    except FileNotFoundError:
        print(
            yellow +
            "systemctl was not found" +
            reset
        )
        return success

    except subprocess.TimeoutExpired:
        print(
            red +
            "systemctl command timed out" +
            reset
        )
        return error

    if result.returncode != 0:
        print(
            red +
            "Unable to query system services" +
            reset
        )
        return error

    services = []

    for line in result.stdout.splitlines():
        fields = line.split()

        if fields:
            services.append(fields[0])

    for service in services:
        print(f"  {service}")

    print()
    print(f"Running services: {len(services)}")

    return success

def find_auth_log():
    logs = [
        "/var/log/auth.log",
        "/var/log/secure"
    ]

    for logfile in logs:
        if os.path.isfile(logfile):
            return logfile

    return None

def audit_logs():
    print("Authentication log check")
    print()

    logfile = find_auth_log()

    if logfile is None:
        print(
            red +
            "Authentication logs not found" +
            reset
        )
        return success

    failed = 0
    accepted = 0

    try:
        with open(
            logfile,
            "r",
            errors="replace"
        ) as f:

            for line in f:
                lower_line = line.lower()

                if (
                    "failed password" in lower_line
                    or "authentication failure" in lower_line
                    or "failed login" in lower_line
                ):
                    failed += 1

                if (
                    "accepted password" in lower_line
                    or "accepted publickey" in lower_line
                ):
                    accepted += 1

    except PermissionError:
        print(
            red +
            f"Permission denied: {logfile}" +
            reset
        )
        return error

    print(f"Log file: {logfile}")
    print(f"Failed authentication attempts: {failed}")
    print(f"successful authentication attempts: {accepted}")
    print()

    if failed >= AUTH_FAILURE_CRITICAL_THRESHOLD:
        print(
            red +
            "High number of failed authentication attempts.Somebody might be bruteforcing" +
            reset
        )
        return failure

    if failed >= AUTH_FAILURE_WARNING_THRESHOLD:
        print(
            yellow +
            "Multiple failed authentication attempts detected.Might be a user who forgot his password :)" +
            reset
        )
        return failure

    print(
        green +
        "No unusual numbers of authentication attempts" +
        reset
    )

    return success

def read_meminfo():
    memory = {}

    data = read_proc_file("/proc/meminfo")

    if data is None:
        return memory

    for line in data.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        fields = value.strip().split()

        if not fields:
            continue

        try:
            memory[key] = int(fields[0])
        except ValueError:
            continue

    return memory

def audit_system():
    print("System information")
    print()

    print(f"Hostname:     {platform.node()}")
    print(f"Kernel:       {platform.release()}")
    print(f"Architecture: {platform.machine()}")

    uptime_data = read_proc_file("/proc/uptime")

    if uptime_data:
        try:
            uptime_seconds = float(
                uptime_data.split()[0]
            )

            days = int(
                uptime_seconds // 86400
            )

            hours = int(
                (uptime_seconds % 86400) // 3600
            )

            minutes = int(
                (uptime_seconds % 3600) // 60
            )

            print(
                f"Uptime:       "
                f"{days}d {hours}h {minutes}m"
            )

        except (ValueError, IndexError):
            pass

    load_data = read_proc_file("/proc/loadavg")

    if load_data:
        fields = load_data.split()

        if fields:
            print(
                f"Load average: "
                f"{fields[0]} {fields[1]} {fields[2]}"
            )
            print(yellow + "Note - Load average is the average load on the cpu displayed in 5 min,10 min,15 min" + reset) 

    memory = read_meminfo()

    if "MemTotal" in memory:
        total = memory["MemTotal"] * 1024

        print(
            f"Memory total: "
            f"{human_readable_size(total)}"
        )

    if "MemAvailable" in memory:
        available = memory["MemAvailable"] * 1024

        print(
            f"Memory available: "
            f"{human_readable_size(available)}"
        )

    try:
        disk = os.statvfs("/")

        total_disk = (
            disk.f_blocks *
            disk.f_frsize
        )

        free_disk = (
            disk.f_bavail *
            disk.f_frsize
        )

        used_disk = total_disk - free_disk

        if total_disk:
            usage = (
                used_disk /
                total_disk
            ) * 100
        else:
            usage = 0

        print(
            f"Disk usage:   "
            f"{human_readable_size(used_disk)} / "
            f"{human_readable_size(total_disk)} "
            f"({usage:.1f}%)"
        )

    except OSError:
        pass

    return success

def run_full_audit():
    print("Linux Security Audit")
    print()

    results = []

    print("File integrity:")
    result = check_hashes()
    results.append(("File integrity", result))

    print()
    print("User accounts:")
    result = audit_users()
    results.append(("User accounts", result))

    print()
    print("Permissions:")
    result = audit_permissions()
    results.append(("Permissions", result))

    print()
    print("SUID/SGID:")
    result = audit_suid()
    results.append(("SUID/SGID", result))

    print()
    print("Processes:")
    result = audit_processes()
    results.append(("Processes", result))

    print()
    print("Network:")
    result = audit_network()
    results.append(("Network", result))

    print()
    print("Services:")
    result = audit_services()
    results.append(("Services", result))

    print()
    print("Authentication logs:")
    result = audit_logs()
    results.append(("Authentication logs", result))

    print()
    audit_system()

    print()
    print("Audit summary:")

    failures = 0

    for name, result in results:

        if result == success:
            print(
                green +
                f"  PASS: {name}" +
                reset
            )

        elif result == failure:
            print(
                red +
                f"  WARNING: {name}" +
                reset
            )
            failures += 1

        else:
            print(
                yellow +
                f"  ERROR: {name}" +
                reset
            )
            failures += 1

    print()

    if failures == 0:
        print(
            green +
            "Audit completed successfully." +
            reset
        )
        return success

    print(
        red +
        f"Audit completed with {failures} issue(s)." +
        reset
    )

    return failure

# Main function
def main():
    operating_system = platform.system()

    # print(f"Operating system: {operating_system}")

    if operating_system != "Linux":
        print(
            red +
            "Unsupported OS. This tool is Linux-only." +
            reset
        )
        return error

    if os.geteuid() != 0:
        print(
            red +
            "Please run this script as root" +
            reset
        )

        print(
            f"sudo python3 {script_name}"
        )

        return error

    return run_linux()


def run_linux():
    parser = argparse.ArgumentParser(
        description=(
            "Linux security and file-integrity "
            "tool using Python std lib. "
            "Say goodbye to pip :)"
        )
    )

    operation = parser.add_mutually_exclusive_group()

    operation.add_argument(
        "-f",
        "--file_integrity",
        nargs="*",
        metavar="FILE",
        help=(
            "Create the hashes for the file's"
            "or add files hashes to an existing database"
        )
    )

    operation.add_argument(
        "--check",
        action="store_true",
        help="Check SHA-256 and metadata of files which are there in the json file"
    )

    operation.add_argument(
        "--list",
        action="store_true",
        help="List all tracked files"
    )

    operation.add_argument(
        "--remove",
        nargs="+",
        metavar="FILE",
        help="Remove one or more files from tracking"
    )

    operation.add_argument(
        "--audit",
        action="store_true",
        help="Run the complete Linux security audit"
    )

    operation.add_argument(
        "--users",
        action="store_true",
        help="Audit Linux user accounts"
    )

    operation.add_argument(
        "--permissions",
        action="store_true",
        help="Find dangerous permissions of file's"
    )

    operation.add_argument(
        "--suid",
        action="store_true",
        help="Find SUID and SGID bit's of executables"
    )

    operation.add_argument(
        "--processes",
        action="store_true",
        help="Show running processes which are actively running"
    )

    operation.add_argument(
        "--network",
        action="store_true",
        help="Check listening network ports"
    )

    operation.add_argument(
        "--services",
        action="store_true",
        help="Show running systemd services(Critical if there is an unkown service available and running)"
    )

    operation.add_argument(
        "--logs",
        action="store_true",
        help="Read authentication logs"
    )

    operation.add_argument(
        "--system",
        action="store_true",
        help="Show system information"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Linux sys admin script 1.0"
    )

    args = parser.parse_args()

    if args.check:
        return check_hashes()

    if args.list:
        return list_files()

    if args.remove:
        return remove_files(args.remove)

    if args.users:
        return audit_users()

    if args.permissions:
        return audit_permissions()

    if args.suid:
        return audit_suid()

    if args.processes:
        return audit_processes()

    if args.network:
        return audit_network()

    if args.services:
        return audit_services()

    if args.logs:
        return audit_logs()

    if args.system:
        return audit_system()

    if args.audit:
        return run_full_audit()

    if args.file_integrity is not None:
        print("File integrity checking selected")
        sleep()

        if args.file_integrity:

            if os.path.isfile(output_file):
                return add_files(
                    args.file_integrity
                )
            files_to_hash = filename + args.file_integrity

            print("Creating hashes for the files")
            sleep()

            return (
                success
                if create_hashes(files_to_hash)
                else error
            )

        if not os.path.isfile(output_file):
            print("Creating hashes for the files")
            sleep()

            return (
                success
                if create_hashes()
                else error
            )

        return check_hashes()

    parser.print_help()
    return error

# Make sure this python script is not imported(sourced)
if __name__ == "__main__":
    sys.exit(main())
