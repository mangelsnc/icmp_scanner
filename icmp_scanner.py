#!/usr/bin/env python3

import argparse
import ipaddress
import signal
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

class ICMPScanner:
    show_all = False

    def __init__(self) -> None:
        signal.signal(signal.SIGINT, self.handle_sigint)
        
        targets = self.parse_target(self.get_arguments())

        print(colored(f"\nStart scanning...\n", 'cyan'))

        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(self.icmp_scan, targets)

    def icmp_scan(self, target):

        try:
            ping = subprocess.run(['ping', '-c', '1', target], timeout=1, stdout=subprocess.DEVNULL)
        
            if ping.returncode == 0:
                print(colored(f"  [+] Host {target} is up", 'green'))
        
        except subprocess.TimeoutExpired:
            if self.show_all:
                print(colored(f"  [!] Host {target} is down", 'red'))

    def get_arguments(self):
        parser = argparse.ArgumentParser(prog='icmp_scanner', description='ICMP Scanner: Discover active hosts in a network')
        parser.add_argument('-t', '--t', dest='target', required=True, help='Host or network address (CIDR) to scan. Ex: -t 192.168.1.1 | --target 192.168.1.0/24')
        parser.add_argument('-a', '--all', dest='show_all', action="store_true", help='Display all hosts, not only the active')
        options = parser.parse_args()

        self.show_all = options.show_all

        return options.target

    def parse_target(self, target):
        if '/' in target:
            try:
                network_address = ipaddress.ip_network(target)
                return [str(ip_address) for ip_address in network_address.hosts()]

            except ValueError:
                print(colored(f"\n[!] Invalid network address: {target}"))
                sys.exit(1)

        try:
            ip_address = ipaddress.ip_address(target)
            return [str(ip_address)]

        except ValueError:
            print(colored(f"\n[!] Invalid IP address: {target}"))
            sys.exit(1)


    def handle_sigint(self, signal, frame):
        print(colored(f"\n\n[!] Aborting execution...", 'red'))
        sys.exit(1)

if __name__ == "__main__":
    ICMPScanner()
