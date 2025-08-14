import os
import pandas as pd

ANALYSIS_DIR = "analysis"
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# ------------------ Parsing Functions ------------------ #

def parse_pslist():
    path = os.path.join(ANALYSIS_DIR, "windows_pslist.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "Offset" in line or not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 6:
                pid = parts[2]
                ppid = parts[3]
                name = parts[-1]
                rows.append({"PID": pid, "PPID": ppid, "Process": name})
    return pd.DataFrame(rows)

def parse_netscan():
    path = os.path.join(ANALYSIS_DIR, "windows_netscan.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip() or line.startswith("Offset"):
                continue
            parts = line.strip().split()
            if len(parts) >= 8:
                proto = parts[1]
                local_addr = parts[2]
                foreign_addr = parts[3]
                state = parts[4]
                pid = parts[6]
                rows.append({
                    "Protocol": proto, "Local Address": local_addr,
                    "Foreign Address": foreign_addr, "State": state, "PID": pid
                })
    return pd.DataFrame(rows)

def parse_malfind():
    path = os.path.join(ANALYSIS_DIR, "windows_malfind.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "Process" in line and "Pid" in line:
                rows.append({"Details": line})
            elif line and rows:
                rows[-1]["Details"] += " " + line
    return pd.DataFrame(rows)

def parse_dlllist():
    path = os.path.join(ANALYSIS_DIR, "windows_dlllist.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "Base" in line and "Size" in line:
                continue
            parts = line.strip().split()
            if len(parts) >= 4:
                pid = parts[0]
                base = parts[1]
                size = parts[2]
                path = parts[-1]
                rows.append({"PID": pid, "Base": base, "Size": size, "Path": path})
    return pd.DataFrame(rows)

def parse_cmdline():
    path = os.path.join(ANALYSIS_DIR, "windows_cmdline.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip().startswith("Pid"):
                continue
            parts = line.strip().split(None, 2)
            if len(parts) == 3:
                pid, proc_name, cmdline = parts
                rows.append({"PID": pid, "Process": proc_name, "Cmdline": cmdline})
    return pd.DataFrame(rows)

def parse_driverscan():
    path = os.path.join(ANALYSIS_DIR, "windows_driverscan.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "Offset" in line and "File" in line:
                continue
            parts = line.strip().split()
            if len(parts) >= 2:
                offset = parts[0]
                name = parts[-1]
                rows.append({"Offset": offset, "Driver Name": name})
    return pd.DataFrame(rows)

def parse_handles():
    path = os.path.join(ANALYSIS_DIR, "windows_handles.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "Offset" in line and "Type" in line:
                continue
            parts = line.strip().split()
            if len(parts) >= 4:
                pid = parts[0]
                handle_type = parts[2]
                name = parts[-1]
                rows.append({"PID": pid, "Type": handle_type, "Name": name})
    return pd.DataFrame(rows)

def parse_filescan():
    path = os.path.join(ANALYSIS_DIR, "windows_filescan.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "Offset" in line and "Name" in line:
                continue
            parts = line.strip().split()
            if len(parts) >= 2:
                offset = parts[0]
                name = parts[-1]
                rows.append({"Offset": offset, "File Path": name})
    return pd.DataFrame(rows)

def parse_svcscan():
    path = os.path.join(ANALYSIS_DIR, "windows_svcscan.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "Service Name" in line:
                continue
            if line.strip():
                rows.append({"Service Info": line.strip()})
    return pd.DataFrame(rows)

def parse_ssdt():
    path = os.path.join(ANALYSIS_DIR, "windows_ssdt.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "Index" in line and "Address" in line:
                continue
            if line.strip():
                rows.append({"SSDT Entry": line.strip()})
    return pd.DataFrame(rows)

def parse_modules():
    path = os.path.join(ANALYSIS_DIR, "windows_modules.txt")
    if not os.path.exists(path): return pd.DataFrame()
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "Base" in line and "Size" in line:
                continue
            parts = line.strip().split()
            if len(parts) >= 4:
                base = parts[0]
                size = parts[1]
                path = parts[-1]
                rows.append({"Base": base, "Size": size, "Path": path})
    return pd.DataFrame(rows)

# ------------------ Report Generator ------------------ #

def generate_report():
    parsers = {
        "pslist_report.html": parse_pslist(),
        "netscan_report.html": parse_netscan(),
        "malfind_report.html": parse_malfind(),
        "dlllist_report.html": parse_dlllist(),
        "cmdline_report.html": parse_cmdline(),
        "driverscan_report.html": parse_driverscan(),
        "handles_report.html": parse_handles(),
        "filescan_report.html": parse_filescan(),
        "svcscan_report.html": parse_svcscan(),
        "ssdt_report.html": parse_ssdt(),
        "modules_report.html": parse_modules(),
    }

    for filename, df in parsers.items():
        if not df.empty:
            df.to_html(os.path.join(REPORT_DIR, filename), index=False)
            print(f"[✔] {filename} generated.")
        else:
            print(f"[!] {filename} skipped (no data).")

if __name__ == "__main__":
    generate_report()
