#!/usr/bin/env python3

import subprocess
import pathlib
import platform
import argparse
import sys
import os
import stat
import ipaddress
import json
import re
from datetime import datetime

# Import the nmap logic (assuming the file is named nmap_service_scanner.py)
try:
    import nmap_service_scanner
except ImportError:
    nmap_service_scanner = None

def get_script_dir() -> pathlib.Path:
    return pathlib.Path(__file__).parent.resolve()

def ensure_executable(path: str):
    if platform.system() in ['Linux', 'Darwin']:
        p = pathlib.Path(path)
        if p.exists():
            st = os.stat(p)
            os.chmod(p, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

def normalize_address(address: str) -> str:
    address = address.replace("\\", "/")
    if "/" in address:
        try:
            net = ipaddress.ip_network(address, strict=False)
            return str(net)
        except ValueError:
            return address
    return address

def get_default_binary() -> str:
    suffixes = {'Windows': 'rustscan-windows.exe', 'Linux': 'rustscan-linux', 'Darwin': 'rustscan-macos'}
    sys_type = platform.system()
    binary_name = suffixes.get(sys_type)
    if not binary_name:
        sys.exit(f"[-] Unsupported Platform: {sys_type}")
    binary_path = str(get_script_dir() / "../binaries" / binary_name)
    ensure_executable(binary_path)
    return binary_path

def parse_results(lines: list) -> dict:
    results = {}
    for line in lines:
        line = line.strip()
        if " -> [" in line:
            parts = line.split(" -> [")
            ip = parts[0].strip()
            ports = [int(p.strip()) for p in parts[1].replace("]", "").split(",") if p.strip().isdigit()]
            results.setdefault(ip, []).extend(ports)
        elif line.startswith("Open "):
            match = re.search(r"Open ([\d\.]+):(\d+)", line)
            if match:
                ip, port = match.group(1), int(match.group(2))
                results.setdefault(ip, []).append(port)
    
    filtered = {ip: sorted(list(set(ports))) for ip, ports in results.items() 
                if not (ip.endswith(".1") or ip.endswith(".2"))}
    return filtered

def run_scan(binary_path: str, targets: list, ports: str = None, 
             batch_size: int = 4500, top: bool = False, greppable: bool = False) -> dict:
    ulimit_val = batch_size + 500
    args = [binary_path, "--no-banner", "--scripts", "none", "--ulimit", str(ulimit_val), "-b", str(batch_size)]
    if greppable: args.append("-g")
    for t in targets: args.extend(["-a", normalize_address(t)])
    if top: args.append("--top")
    elif ports: 
        print(ports)
        if "-" in ports:
            args.extend(["-r", ports])
        else:
            args.extend(["-p", ports])
    else: args.extend(["-r", "1-65535"])

    print(f"[*] Executing: {' '.join(args)}\n" + "-"*50)
    captured_lines = []
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in process.stdout:
        print(line, end='')
        captured_lines.append(line)
    process.wait()
    return parse_results(captured_lines)

def main():
    parser = argparse.ArgumentParser(description="Network Recon Wrapper for RustScan")
    parser.add_argument("-a", "--address", action="append")
    parser.add_argument("-p", "--ports")
    parser.add_argument("-b", "--batch-size", type=int, default=4500)
    parser.add_argument("-g", "--greppable", action="store_true")
    parser.add_argument("--top", action="store_true")
    args = parser.parse_args()

    targets = args.address or input("Enter targets (space separated): ").split()
    if not targets: sys.exit("[-] No targets.")

    rustscan_path = get_default_binary()
    scan_data = run_scan(rustscan_path, targets, args.ports, args.batch_size, args.top, args.greppable)

    if scan_data:
        res_dir = get_script_dir() / "scanResults"
        res_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = res_dir / f"rust_results_{timestamp}.json"
        
        output = {"timestamp": datetime.now().isoformat(), "targets": targets, "results": scan_data}
        with open(file_path, "w") as f:
            json.dump(output, f, indent=4)
        
        print(f"\n[!] RustScan complete. JSON saved to: {file_path}")
        
        # PROMPT FOR NMAP
        choice = input("\n[?] Do you want to run Nmap service/version detection on found hosts? (y/n): ").lower()
        if choice == 'y':
            if nmap_service_scanner:
                nmap_service_scanner.run_nmap_from_json(file_path)
            else:
                print("[-] Nmap script not found in current directory.")
    else:
        print("\n[-] No open ports discovered.")

if __name__ == "__main__":
    main()