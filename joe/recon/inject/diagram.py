import xml.etree.ElementTree as ET
import base64
import os
import json
import glob
import re
import argparse

# --- PATH RESOLUTION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

ICONS_DIR = os.path.join(SCRIPT_DIR, "icons")
INPUT_FILE = os.path.join(SCRIPT_DIR, "servers.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "competition_network.drawio")

# Path to ansible results: ../../ansible/results relative to script dir
ANSIBLE_RESULTS_DIR = os.path.join(SCRIPT_DIR, "..", "..", "ansible", "results")

ICON_MAP = {
    "ubuntu": "ubuntu.svg",
    "debian": "debian.svg",
    "rocky": "rocky.svg",
    "windows": "windows.svg",
    "pfsense": "pfsense.svg",
    "linux": "linux.svg",
    "generic": "linux.svg"
}

template_data = [
    # --- QUICK COPY TEMPLATES (one per available icon) ---
    {"hostname": "UBUNTU",   "ip": "15.15.15.1", "mac": "00:00:00", "os": "ubuntu",   "services": "Unknown"},
    {"hostname": "DEBIAN",   "ip": "15.15.15.2", "mac": "00:00:00", "os": "debian",   "services": "Unknown"},
    {"hostname": "ROCKY",    "ip": "15.15.15.3", "mac": "00:00:00", "os": "rocky",    "services": "Unknown"},
    {"hostname": "WINDOWS",  "ip": "15.15.15.4", "mac": "00:00:00", "os": "windows",  "services": "Unknown"},
    {"hostname": "PFSENSE",  "ip": "15.15.15.5", "mac": "00:00:00", "os": "pfsense",  "services": "Unknown"},
    {"hostname": "LINUX",    "ip": "15.15.15.6", "mac": "00:00:00", "os": "linux",    "services": "Unknown"},
]


def get_embedded_image(distro_name):
    """Reads local SVG and returns the Draw.io specific format: data:image/svg+xml,[base64]"""
    filename = ICON_MAP.get("generic")
    for key, val in ICON_MAP.items():
        if key.lower() in distro_name.lower():
            filename = val
            break
            
    path = os.path.join(ICONS_DIR, filename)
    if not os.path.exists(path):
        return ""

    with open(path, "rb") as f:
        b64_data = base64.b64encode(f.read()).decode('utf-8')
        return f"data:image/svg+xml,{b64_data}"


def find_latest_inventory(folder):
    """
    Inside `folder`, find all files matching system_inventory_* and return
    the path of the latest one.
    """
    pattern = os.path.join(folder, "system_inventory_*")
    matches = glob.glob(pattern)
    if not matches:
        return None
    return sorted(matches)[-1]


def parse_inventory_file(filepath):
    """
    Read a system_inventory_* file and extract the JSON block at the end.
    """
    with open(filepath, "r", errors="replace") as f:
        content = f.read()

    marker = "--- servers.json ENTRY (copy object into your array) ---"
    idx = content.find(marker)
    if idx == -1:
        print(f"  [warn] No JSON marker found in {filepath}")
        return []

    json_text = content[idx + len(marker):].strip()

    try:
        data = json.loads(json_text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError as e:
        print(f"  [warn] JSON parse error in {filepath}: {e}")

    return []


def load_from_ansible():
    """
    Walk every subfolder of ANSIBLE_RESULTS_DIR and aggregate all entries.
    """
    results_dir = os.path.normpath(ANSIBLE_RESULTS_DIR)
    if not os.path.isdir(results_dir):
        print(f"[auto] Ansible results directory not found: {results_dir}")
        return []

    all_servers = []

    for entry in sorted(os.scandir(results_dir), key=lambda e: e.name):
        if not entry.is_dir():
            continue
        latest = find_latest_inventory(entry.path)
        if not latest:
            print(f"  [skip] No system_inventory_* found in {entry.path}")
            continue
        print(f"  [read] {latest}")
        servers = parse_inventory_file(latest)
        all_servers.extend(servers)

    print(f"[auto] Collected {len(all_servers)} server(s) from ansible results.")
    return all_servers


def load_json_data():
    """Loads data from servers.json."""
    if not os.path.exists(INPUT_FILE):
        return []
    with open(INPUT_FILE, "r") as f:
        try:
            data = json.load(f)
            return data if data else []
        except json.JSONDecodeError:
            return []

def print_markdown_table(server_data):
    """Prints the server data in Markdown table format to the console."""
    if not server_data:
        return

    print("\n--- COPYABLE MARKDOWN TABLE ---")
    header = "| Host | IP | MAC | OS | Services |"
    separator = "| :--- | :--- | :--- | :--- | :--- |"
    print(header)
    print(separator)
    
    for s in server_data:
        # Get values and handle potential missing keys
        host = s.get("hostname", "N/A")
        ip = s.get("ip", "N/A")
        mac = s.get("mac", "N/A")
        os_val = s.get("os", "N/A")
        services = s.get("services", "N/A")
        
        print(f"| {host} | {ip} | {mac} | {os_val} | {services} |")
    print("-------------------------------\n")


def create_drawio(server_data, template_nodes=None):
    if template_nodes is None:
        template_nodes = []

    mxfile = ET.Element("mxfile", host="Electron", version="20.0.0")
    diagram = ET.SubElement(mxfile, "diagram", id="page1", name="Network Map")
    mxGraphModel = ET.SubElement(diagram, "mxGraphModel", dx="1426", dy="785", grid="1", gridSize="10")
    root = ET.SubElement(mxGraphModel, "root")
    
    ET.SubElement(root, "mxCell", id="0")
    ET.SubElement(root, "mxCell", id="1", parent="0")

    VERTICAL_SPACING = 150 
    TOP_PADDING = 60        
    NODE_HEIGHT = 70        

    subnets = {}
    for srv in server_data:
        net_addr = ".".join(srv['ip'].split('.')[:-1]) + ".0/24"
        if net_addr not in subnets:
            subnets[net_addr] = []
        subnets[net_addr].append(srv)

    start_x = 50
    for net_prefix, servers in subnets.items():
        subnet_id = f"net_{net_prefix}"
        box_h = TOP_PADDING + (len(servers) * VERTICAL_SPACING)
        
        subnet_style = "swimlane;whiteSpace=wrap;html=1;startSize=23;fillColor=#f9f9f9;strokeColor=#cccccc;"
        sb = ET.SubElement(root, "mxCell", id=subnet_id, value=f"Network: {net_prefix}", 
                           style=subnet_style, parent="1", vertex="1")
        
        geo = ET.SubElement(sb, "mxGeometry", x=str(start_x), y="50", width="240", height=str(box_h))
        geo.set("as", "geometry")

        for i, srv in enumerate(servers):
            srv_id = f"srv_{srv['ip'].replace('.', '_')}_{i}"
            img_data = get_embedded_image(srv.get('os', 'generic'))
            
            style = (f"shape=image;html=1;verticalLabelPosition=bottom;labelBackgroundColor=default;"
                     f"verticalAlign=top;aspect=fixed;imageAspect=0;image={img_data};")
            
            label = f"<b>{srv['hostname']}</b><br/>{srv['ip']}<br/>{srv['mac']}"
            current_y = TOP_PADDING + (i * VERTICAL_SPACING)
            
            node = ET.SubElement(root, "mxCell", id=srv_id, value=label, style=style, parent=subnet_id, vertex="1")
            node_geo = ET.SubElement(node, "mxGeometry", x="85", y=str(current_y), width="70", height=str(NODE_HEIGHT))
            node_geo.set("as", "geometry")
        
        start_x += 300

    # --- TEMPLATE SWIMLANE ---
    if template_nodes:
        tmpl_subnet_id = "__TEMPLATE_SWIMLANE__"
        box_h = TOP_PADDING + (len(template_nodes) * VERTICAL_SPACING)
        tmpl_style = "swimlane;whiteSpace=wrap;html=1;startSize=23;fillColor=#f9f9f9;strokeColor=#cccccc;"
        sb = ET.SubElement(root, "mxCell", id=tmpl_subnet_id, value="Templates for copy",
                           style=tmpl_style, parent="1", vertex="1")
        geo = ET.SubElement(sb, "mxGeometry", x=str(start_x), y="50", width="240", height=str(box_h))
        geo.set("as", "geometry")

        for i, srv in enumerate(template_nodes):
            srv_id = f"tmpl_{i}"
            img_data = get_embedded_image(srv.get('os', 'generic'))
            style = (f"shape=image;html=1;verticalLabelPosition=bottom;labelBackgroundColor=default;"
                     f"verticalAlign=top;aspect=fixed;imageAspect=0;image={img_data};")
            label = f"<b>{srv['hostname']}</b><br/>{srv['ip']}<br/>{srv['mac']}"
            current_y = TOP_PADDING + (i * VERTICAL_SPACING)
            node = ET.SubElement(root, "mxCell", id=srv_id, value=label, style=style, parent=tmpl_subnet_id, vertex="1")
            node_geo = ET.SubElement(node, "mxGeometry", x="85", y=str(current_y), width="70", height=str(NODE_HEIGHT))
            node_geo.set("as", "geometry")

    # --- SUMMARY TABLE (HTML for Draw.io) ---
    padding_val = "8"
    table_html = (
        f'<table border="1" cellpadding="{padding_val}" '
        'style="width:100%; border-collapse:collapse; background:#ffffff;">'
        f'<tr style="background:#eeeeee;"><th style="padding:{padding_val}px;">Host</th>'
        f'<th style="padding:{padding_val}px;">IP</th>'
        f'<th style="padding:{padding_val}px;">MAC</th>'
        f'<th style="padding:{padding_val}px;">OS</th>'
        f'<th style="padding:{padding_val}px;">Services</th>'
        f'</tr>'
    )
    for s in server_data:
        table_html += (
            f'<tr>'
            f'<td style="padding:{padding_val}px;">{s["hostname"]}</td>'
            f'<td style="padding:{padding_val}px;">{s["ip"]}</td>'
            f'<td style="padding:{padding_val}px;">{s["mac"]}</td>'
            f'<td style="padding:{padding_val}px;">{s["os"]}</td>'
            f'<td style="padding:{padding_val}px;">{s["services"]}</td>'
            f'</tr>'
        )
    table_html += "</table>"

    table_cell = ET.SubElement(root, "mxCell", id="summary_table", value=table_html, 
                               style="text;html=1;strokeColor=none;fillColor=none;overflow=hidden;whiteSpace=wrap;", 
                               parent="1", vertex="1")
    t_geo = ET.SubElement(table_cell, "mxGeometry", x="50", y="800", width="700", height="300")
    t_geo.set("as", "geometry")

    tree = ET.ElementTree(mxfile)
    with open(OUTPUT_FILE, "wb") as f:
        tree.write(f, encoding="utf-8", xml_declaration=True)
    
    print(f"Successfully generated {OUTPUT_FILE}")
    
    # --- ALSO PRINT MARKDOWN TO CONSOLE ---
    print_markdown_table(server_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Draw.io network diagram.")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-discover hosts from ../../ansible/results instead of servers.json")
    args = parser.parse_args()

    if args.auto:
        print("[mode] --auto: loading from ansible results")
        data = load_from_ansible()
    else:
        data = load_json_data()
        if not data:
            print("[mode] servers.json is missing or empty — falling back to ansible results")
            data = load_from_ansible()
        else:
            print(f"[mode] Loaded {len(data)} server(s) from servers.json")

    if not data:
        print("[warn] No server data found. Diagram will be empty except for templates.")

    create_drawio(data, template_nodes=template_data)

    if data and (args.auto or not load_json_data()):
        try:
            answer = input("\nSave collected data to servers.json? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer == "y":
            with open(INPUT_FILE, "w") as f:
                json.dump(data, f, indent=2)
            print(f"Saved {len(data)} server(s) to {INPUT_FILE}")