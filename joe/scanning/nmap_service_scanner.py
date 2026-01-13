#!/usr/bin/env python3


import json
import subprocess
import pathlib
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

def run_nmap_from_json(json_path: pathlib.Path):
    """Reads RustScan JSON and runs detailed Nmap scans."""
    if not json_path.exists():
        print(f"[-] File not found: {json_path}")
        return

    with open(json_path, "r") as f:
        data = json.load(f)

    results_map = data.get("results", {})
    if not results_map:
        print("[-] No hosts to scan in JSON.")
        return

    final_nmap_results = {
        "scan_timestamp": datetime.now().isoformat(),
        "source_file": str(json_path),
        "hosts": []
    }

    print(f"\n[*] Starting Nmap detail scan on {len(results_map)} hosts...")

    for ip, ports in results_map.items():
        port_str = ",".join(map(str, ports))
        print(f"[*] Scanning {ip} on ports: {port_str}")
        
        # -sV: Service version, -sC: Default scripts, -Pn: Skip host discovery
        # Outputting to XML (-oX -) for easy parsing
        cmd = ["nmap", "-sV", "-sC", "-Pn", "-vvv", "-p", port_str, ip, "-oX", "-"]
        print(f"[*] Executing: {' '.join(cmd)}")
        
        try:
            process = subprocess.run(cmd, capture_output=True, text=True)
            if process.returncode != 0:
                print(f"[-] Nmap error on {ip}: {process.stderr}")
                continue
            
            host_data = parse_nmap_xml(process.stdout, ip)
            final_nmap_results["hosts"].append(host_data)
            
            # Print a quick summary to console
            for p in host_data["ports"]:
                print(f"    [+] {p['portid']}/{p['protocol']} - {p['service_name']} ({p['product']} {p['version']})")

        except Exception as e:
            print(f"[-] Failed to scan {ip}: {e}")

    # Save Nmap results
    out_dir = json_path.parent
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"nmap_details_{timestamp}.json"
    
    with open(out_file, "w") as f:
        json.dump(final_nmap_results, f, indent=4)
    
    print(f"\n[!] Nmap detail scan complete.")
    print(f"[!] Results saved to: {out_file}")

def parse_nmap_xml(xml_string, ip):
    """Simple parser to convert Nmap XML output to a dictionary."""
    host_info = {"ip": ip, "ports": []}
    try:
        root = ET.fromstring(xml_string)
        for port in root.findall(".//port"):
            p_data = {
                "portid": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": port.find("state").get("state") if port.find("state") is not None else "unknown",
                "service_name": "",
                "product": "",
                "version": "",
                "script_outputs": {}
            }
            
            service = port.find("service")
            if service is not None:
                p_data["service_name"] = service.get("name", "")
                p_data["product"] = service.get("product", "")
                p_data["version"] = service.get("version", "")
            
            for script in port.findall("script"):
                p_data["script_outputs"][script.get("id")] = script.get("output").strip()
                
            host_info["ports"].append(p_data)
    except Exception as e:
        host_info["error"] = f"XML Parsing failed: {str(e)}"
    
    return host_info

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_nmap_from_json(pathlib.Path(sys.argv[1]))
    else:
        print("Usage: python nmap_service_scanner.py <rustscan_json_file>")