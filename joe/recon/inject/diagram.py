import xml.etree.ElementTree as ET
import base64
import os
import json

# --- PATH RESOLUTION ---
# This ensures that no matter where the script is called from, 
# it finds files relative to the script's location.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

ICONS_DIR = os.path.join(SCRIPT_DIR, "icons")
INPUT_FILE = os.path.join(SCRIPT_DIR, "servers.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "competition_network.drawio")

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
    # --- QUICK COPY TEMPLATES START HERE ---
    
    # Generic Linux Template (uses linux.svg)
    {"hostname": "LINUX-GENERIC", "ip": "15.15.15.1", "mac": "00:00:00", "os": "linux", "services": "Unknown"},
    
    # Generic Windows Template (uses windows.svg)
    {"hostname": "WIN-GENERIC", "ip": "15.15.15.2", "mac": "00:00:00", "os": "windows", "services": "Unknown"},

    # --- QUICK COPY TEMPLATES END HERE ---
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

def create_drawio(server_data, template_nodes=None):
    """
    server_data    — real hosts; appear in both the diagram and the summary table.
    template_nodes — copy-paste helper nodes; appear in the diagram only, NOT in the table.
    """
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
        # Group by first 3 octets (real hosts only)
        net_addr = ".".join(srv['ip'].split('.')[:-1]) + ".0/24"
        if net_addr not in subnets: subnets[net_addr] = []
        subnets[net_addr].append(srv)

    start_x = 50
    for net_prefix, servers in subnets.items():
        subnet_id = f"net_{net_prefix}"
        box_h = TOP_PADDING + (len(servers) * VERTICAL_SPACING)
        
        subnet_style = "swimlane;whiteSpace=wrap;html=1;startSize=23;fillColor=#f9f9f9;strokeColor=#cccccc;"
        sb = ET.SubElement(root, "mxCell", id=subnet_id, value=f"Network: {net_prefix}", 
                           style=subnet_style, parent="1", vertex="1")
        
        geo = ET.SubElement(sb, "mxGeometry", x=str(start_x), y="50", width="240", height=str(box_h), as_="geometry")
        geo.set("as", "geometry")
        del geo.attrib["as_"]

        for i, srv in enumerate(servers):
            srv_id = f"srv_{srv['ip'].replace('.', '_')}_{i}"
            img_data = get_embedded_image(srv.get('os', 'generic'))
            
            style = (f"shape=image;html=1;verticalLabelPosition=bottom;labelBackgroundColor=default;"
                     f"verticalAlign=top;aspect=fixed;imageAspect=0;image={img_data};")
            
            label = f"<b>{srv['hostname']}</b><br/>{srv['ip']}<br/>{srv['mac']}"
            current_y = TOP_PADDING + (i * VERTICAL_SPACING)
            
            node = ET.SubElement(root, "mxCell", id=srv_id, value=label, style=style, parent=subnet_id, vertex="1")
            node_geo = ET.SubElement(node, "mxGeometry", x="85", y=str(current_y), width="70", height=str(NODE_HEIGHT), as_="geometry")
            node_geo.set("as", "geometry")
            del node_geo.attrib["as_"]
        
        start_x += 300

    # --- TEMPLATE SWIMLANE (never collides with real subnets — fixed internal ID) ---
    if template_nodes:
        tmpl_subnet_id = "__TEMPLATE_SWIMLANE__"  # fixed, never derived from an IP
        box_h = TOP_PADDING + (len(template_nodes) * VERTICAL_SPACING)

        tmpl_style = ("swimlane;whiteSpace=wrap;html=1;startSize=23;"
                      "fillColor=#f9f9f9;strokeColor=#cccccc;")
        sb = ET.SubElement(root, "mxCell", id=tmpl_subnet_id, value="Templates for copy",
                           style=tmpl_style, parent="1", vertex="1")

        geo = ET.SubElement(sb, "mxGeometry", x=str(start_x), y="50", width="240", height=str(box_h), as_="geometry")
        geo.set("as", "geometry")
        del geo.attrib["as_"]

        for i, srv in enumerate(template_nodes):
            srv_id = f"tmpl_{i}"  # index-only ID, no IP in it
            img_data = get_embedded_image(srv.get('os', 'generic'))

            style = (f"shape=image;html=1;verticalLabelPosition=bottom;labelBackgroundColor=default;"
                     f"verticalAlign=top;aspect=fixed;imageAspect=0;image={img_data};")

            label = f"<b>{srv['hostname']}</b><br/>{srv['ip']}<br/>{srv['mac']}"
            current_y = TOP_PADDING + (i * VERTICAL_SPACING)

            node = ET.SubElement(root, "mxCell", id=srv_id, value=label, style=style, parent=tmpl_subnet_id, vertex="1")
            node_geo = ET.SubElement(node, "mxGeometry", x="85", y=str(current_y), width="70", height=str(NODE_HEIGHT), as_="geometry")
            node_geo.set("as", "geometry")
            del node_geo.attrib["as_"]

    # --- TABLE GENERATION (server_data only — templates excluded) ---
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
    
    for s in server_data:  # <-- real hosts only
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
    
    t_geo = ET.SubElement(table_cell, "mxGeometry", x="50", y="800", width="700", height="300", as_="geometry")
    t_geo.set("as", "geometry")
    del t_geo.attrib["as_"]

    tree = ET.ElementTree(mxfile)
    with open(OUTPUT_FILE, "wb") as f:
        tree.write(f, encoding="utf-8", xml_declaration=True)
    
    print(f"Successfully generated {OUTPUT_FILE}")

def load_json_data():
    """Loads data from servers.json in the script directory."""
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found.")
        return []

    with open(INPUT_FILE, "r") as f:
        return json.load(f)

if __name__ == "__main__":
    data = load_json_data()
    create_drawio(data, template_nodes=template_data)  # templates passed separately