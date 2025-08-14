import subprocess
import os

# Paths
vol_path = r"volatility3/vol.py"
memdump_path = r"samples/memdump.mem"
analysis_dir = r"analysis"

# Ensure output directory exists
os.makedirs(analysis_dir, exist_ok=True)

# Likely non-empty plugins for Windows 7 SP1
plugins = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.psscan",
    "windows.dlllist",
    "windows.driverscan",
    "windows.handles",
    "windows.filescan",
    "windows.registry.hivelist",
    "windows.registry.printkey",
    "windows.registry.userassist",
    "windows.svcscan",
    "windows.ssdt",
    "windows.modules",
    "windows.malfind"
]

for plugin in plugins:
    out_file = os.path.join(analysis_dir, f"{plugin.replace('.', '_').lower()}.txt")
    print(f"[+] Running {plugin}...")
    try:
        with open(out_file, "w") as f:
            subprocess.run(
                ["python", vol_path, "-f", memdump_path, plugin],
                stdout=f,
                stderr=subprocess.PIPE,
                text=True
            )
        print(f"[+] Output saved to {out_file}")
    except Exception as e:
        print(f"[!] Error running {plugin}: {e}")

print("[+] Selected non-empty plugins completed.")
