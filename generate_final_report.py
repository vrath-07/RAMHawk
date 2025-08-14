import os
import datetime
from jinja2 import Environment, FileSystemLoader

# Paths
TEMPLATE_DIR = os.path.join("reports", "templates")
OUTPUT_HTML = os.path.join("reports", "ramhawk_final_report.html")

# All working plugins
PLUGIN_FILES = {
    "Process List (pslist)": "pslist_report.html",
    "Network Connections (netscan)": "netscan_report.html",
    "Malware Indicators (malfind)": "malfind_report.html",
    "DLLs Loaded (dlllist)": "dlllist_report.html",
    "Command-line Activity (cmdline)": "cmdline_report.html",
    "Loaded Modules": "modules_report.html",
    "File Scan": "filescan_report.html",
    "SSDT Table": "ssdt_report.html",
    "Service Scan": "svcscan_report.html",
}

# Case metadata
CASE_INFO = {
    "case_id": "RAMHawk-2025-001",
    "analyst": "Vansh Pradeep Singh Rathore",
    "tool_version": "RAMHawk v1.0",
    "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
}

def load_html_sections():
    sections = []
    for title, filename in PLUGIN_FILES.items():
        path = os.path.join("reports", filename)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content:  # Only include non-empty
                sections.append({"title": title, "content": content})
            else:
                print(f"[!] Skipping empty report file: {filename}")
        else:
            print(f"[!] Missing report file: {filename}")
    return sections

def generate_html():
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")
    
    html_out = template.render(
        case=CASE_INFO,
        sections=load_html_sections()
    )
    
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_out)
    print(f"[✔] Final HTML report saved to: {OUTPUT_HTML}")

if __name__ == "__main__":
    generate_html()
