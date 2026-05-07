#!/usr/bin/env python3
"""
DroidScan v1.0 - Android Malware Analysis Tool
Developer: Anupom
"""

import os
import subprocess
import hashlib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from tqdm import tqdm

console = Console()

# ================= CONFIGURATION =================
# এখানে সন্দেহজনক প্যাকেজ নেমের লিস্ট যুক্ত করতে পারেন
BLACKLISTED_PACKAGES = [
    "com.hidden.ads",
    "com.spyware.tracker",
    "com.malicious.payload"
]

def get_installed_apps():
    """Fetch third-party installed applications."""
    try:
        # -3 flag is for third-party apps only
        result = subprocess.run(['pm', 'list', 'packages', '-3'], capture_output=True, text=True)
        packages = [line.replace("package:", "").strip() for line in result.stdout.splitlines() if line.startswith("package:")]
        return packages
    except Exception as e:
        console.print(f"[bold red][!] Error fetching packages: {e}[/bold red]")
        return []

def get_apk_path(package_name):
    """Get the physical APK path of the package."""
    try:
        result = subprocess.run(['pm', 'path', package_name], capture_output=True, text=True)
        if result.stdout.startswith("package:"):
            return result.stdout.replace("package:", "").strip()
    except:
        pass
    return None

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of the APK for VirusTotal/Static analysis."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except PermissionError:
        return "Permission Denied"
    except Exception:
        return "Error reading file"

def banner():
    os.system("clear" if os.name == "posix" else "cls")
    banner_art = r"""
[bold green]
 ____ളroidScan___ 
|  _ \ _ __ ___ (_) __| |/ ___|  ___ __ _ _ __  
| | | | '__/ _ \| |/ _` |\___ \ / __/ _` | '_ \ 
| |_| | | | (_) | | (_| | ___) | (_| (_| | | | |
|____/|_|  \___/|_|\__,_||____/ \___\__,_|_| |_|
[/bold green]
    """
    console.print(banner_art)
    console.print("[bold cyan]      Basic Android Malware & App Analyzer[/bold cyan]")
    console.print("[bold yellow]      Developer: Anupom[/bold yellow]\n")

def main():
    banner()
    console.print("[yellow][*] Gathering installed third-party applications...[/yellow]")
    
    apps = get_installed_apps()
    if not apps:
        console.print("[red][!] No third-party apps found or 'pm' command failed.[/red]")
        return

    console.print(f"[green][+] Found {len(apps)} applications. Starting analysis...[/green]\n")
    
    results = []
    
    for app in tqdm(apps, desc="Scanning Apps", unit="app", ascii=True):
        status = "Safe"
        color = "green"
        
        # Check against blacklist
        if app in BLACKLISTED_PACKAGES or any(suspicious in app for suspicious in ["hack", "spy", "tracker"]):
            status = "Suspicious"
            color = "red"
            
        apk_path = get_apk_path(app)
        apk_hash = "N/A"
        
        if apk_path:
            # Termux usually has read access to /data/app/... base.apk
            apk_hash = calculate_sha256(apk_path)
            
        results.append({
            "package": app,
            "status": f"[{color}]{status}[/{color}]",
            "hash": apk_hash[:15] + "..." if len(apk_hash) > 15 else apk_hash
        })

    # Display Results in a Rich Table
    console.print("\n")
    table = Table(title="Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("Package Name", style="cyan", no_wrap=False)
    table.add_column("Status", justify="center")
    table.add_column("SHA-256 (Partial)", justify="right", style="dim")

    for res in results:
        table.add_row(res["package"], res["status"], res["hash"])

    console.print(table)
    
    console.print("\n[bold yellow][*] Note: For deeper analysis (VirusTotal API integration or memory scanning), root privileges or an external API key is required.[/bold yellow]")

if __name__ == "__main__":
    main()