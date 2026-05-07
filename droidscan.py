#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           DroidScan v2.1 - Premium Edition                   ║
║     Advanced Android Malware Analysis Tool                   ║
║                    Developer: Anupom                         ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import argparse
import subprocess
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import print as rprint
import requests

# ================== CONFIG ==================
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE", "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
]

SUSPICIOUS_KEYWORDS = ["spy", "hack", "track", "steal", "keylog", "rat", "trojan", "backdoor", "hidden", "secret"]

BLACKLISTED_PACKAGES = ["com.hidden.ads", "com.spyware.tracker", "com.malicious.payload"]

class Config:
    def __init__(self, path="config.json"):
        self.path = path
        self.data = {
            "blacklist": BLACKLISTED_PACKAGES,
            "suspicious_keywords": SUSPICIOUS_KEYWORDS,
            "dangerous_permissions": DANGEROUS_PERMISSIONS,
            "vt_api_key": "",
            "max_workers": 6,
            "log_file": "droidscan.log"
        }
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.data.update(json.load(f))
            except: pass

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4)

class DroidScanner:
    def __init__(self, config: Config):
        self.console = Console()
        self.config = config
        self.setup_logging()
        self.results = []

    def setup_logging(self):
        logging.basicConfig(filename=self.config.data["log_file"], level=logging.INFO,
                            format="%(asctime)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("DroidScan")

    def is_rooted(self):
        for p in ["/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su"]:
            if os.path.exists(p): return True
        try:
            subprocess.run(["su", "-c", "id"], capture_output=True, timeout=2)
            return True
        except: return False

    def get_installed_apps(self):
        try:
            result = subprocess.run(
                ["pm", "list", "packages", "-3", "-f"],
                capture_output=True, text=True, timeout=15
            )
            apps = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    content = line.replace("package:", "", 1).strip()
                    if "=" in content:
                        apk_path, package_name = content.rsplit("=", 1)
                        apps.append({
                            "package": package_name.strip(),
                            "apk_path": apk_path.strip()
                        })
            return apps
        except Exception as e:
            self.logger.error(f"Error: {e}")
            return []

    def get_apk_info(self, apk_path):
        info = {"permissions": [], "label": "Unknown", "version": "N/A", "error": None}
        if not os.path.exists(apk_path):
            info["error"] = "APK not accessible"
            return info
        try:
            result = subprocess.run(
                ["aapt", "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=20
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("package:") and "versionName='" in line:
                    info["version"] = line.split("versionName='")[1].split("'")[0]
                elif line.startswith("application-label:"):
                    info["label"] = line.split(":", 1)[1].strip().strip("'\"")
                elif line.startswith("uses-permission:") and "name='" in line:
                    perm = line.split("name='")[1].split("'")[0]
                    info["permissions"].append(perm)
        except FileNotFoundError:
            info["error"] = "aapt not installed (pkg install aapt)"
        except: pass
        return info

    def calculate_sha256(self, file_path):
        sha = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha.update(chunk)
            return sha.hexdigest()
        except: return None

    def check_virustotal(self, sha256):
        key = self.config.data.get("vt_api_key", "")
        if not key or not sha256: return {"status": "N/A", "detections": 0}
        try:
            resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                                headers={"x-apikey": key}, timeout=15)
            if resp.status_code == 200:
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
                mal = stats.get("malicious", 0)
                total = sum(stats.values())
                return {"status": f"{mal}/{total}", "detections": mal}
            return {"status": "Error", "detections": 0}
        except: return {"status": "Error", "detections": 0}

    def calculate_risk(self, app_info, vt):
        score = 0
        pkg = app_info.get("package", "")
        if pkg in self.config.data["blacklist"]: score += 45
        if any(kw in pkg.lower() for kw in self.config.data["suspicious_keywords"]): score += 25
        dangerous = sum(1 for p in app_info.get("permissions", []) 
                        if p in self.config.data["dangerous_permissions"])
        score += min(dangerous * 4, 30)
        if vt.get("detections", 0) > 0: score += min(vt["detections"] * 3, 25)
        return min(score, 100)

    def analyze_app(self, app):
        info = self.get_apk_info(app["apk_path"])
        sha = self.calculate_sha256(app["apk_path"])
        vt = self.check_virustotal(sha)
        risk = self.calculate_risk({**app, **info}, vt)

        if risk >= 70: status, color = "🔴 CRITICAL", "red"
        elif risk >= 50: status, color = "🟠 HIGH", "orange1"
        elif risk >= 30: status, color = "🟡 MEDIUM", "yellow"
        else: status, color = "🟢 LOW", "green"

        return {
            "package": app["package"],
            "label": info.get("label", "Unknown"),
            "version": info.get("version", "N/A"),
            "risk": risk,
            "status": status,
            "color": color,
            "dangerous_perms": len([p for p in info.get("permissions", []) 
                                    if p in self.config.data["dangerous_permissions"]]),
            "vt": vt["status"],
            "sha": sha[:16] + "..." if sha else "N/A"
        }

    def scan_all(self):
        apps = self.get_installed_apps()
        if not apps:
            self.console.print("[red]No third-party apps found![/red]")
            return []

        self.console.print(f"[cyan]Found {len(apps)} apps. Starting premium analysis...[/cyan]\n")

        results = []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("{task.percentage:>3.0f}%"), TimeElapsedColumn(),
                      console=self.console) as progress:
            task = progress.add_task("Scanning...", total=len(apps))
            with ThreadPoolExecutor(max_workers=self.config.data["max_workers"]) as executor:
                futures = {executor.submit(self.analyze_app, app): app for app in apps}
                for future in as_completed(futures):
                    results.append(future.result())
                    progress.update(task, advance=1)

        self.results = results
        return results

    def show_results(self, results):
        table = Table(title="DroidScan v2.1 - Premium Report", show_header=True, header_style="bold magenta")
        table.add_column("Package", style="cyan", no_wrap=False)
        table.add_column("Label", style="white")
        table.add_column("Risk", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("VT", justify="center")
        table.add_column("Dangerous", justify="right")

        for r in sorted(results, key=lambda x: x["risk"], reverse=True):
            table.add_row(r["package"], r["label"][:22], str(r["risk"]), 
                          f"[{r['color']}]{r['status']}[/{r['color']}]", r["vt"], str(r["dangerous_perms"]))

        self.console.print(table)

        high_risk = sum(1 for r in results if r["risk"] >= 50)
        self.console.print(Panel.fit(
            f"[bold green]Total Apps:[/bold green] {len(results)}   "
            f"[bold yellow]High Risk:[/bold yellow] {high_risk}   "
            f"[bold cyan]Scan Time:[/bold cyan] {datetime.now().strftime('%H:%M:%S')}",
            border_style="green"
        ))

    def generate_html(self, results, filename="droidscan_report.html"):
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>DroidScan v2.1 Premium Report</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white p-8">
<div class="max-w-7xl mx-auto">
<h1 class="text-5xl font-bold text-green-400 mb-2">DroidScan v2.1</h1>
<p class="text-gray-400 mb-8">Premium Android Malware Analyzer • {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
<table class="w-full"><thead><tr class="bg-gray-800">
<th class="p-4 text-left">Package</th><th>Risk</th><th>Status</th><th>VT</th><th>Dangerous</th>
</tr></thead><tbody>"""
        for r in sorted(results, key=lambda x: x["risk"], reverse=True):
            color = "red" if r["risk"] >= 70 else "orange" if r["risk"] >= 50 else "yellow" if r["risk"] >= 30 else "green"
            html += f"""<tr class="border-b border-gray-700 hover:bg-gray-800">
<td class="p-4 font-mono">{r['package']}</td>
<td class="p-4 text-center font-bold">{r['risk']}</td>
<td class="p-4 text-center"><span class="px-4 py-1 rounded-full bg-{color}-600">{r['status']}</span></td>
<td class="p-4 text-center">{r['vt']}</td>
<td class="p-4 text-center">{r['dangerous_perms']}</td></tr>"""
        html += "</tbody></table></div></body></html>"
        with open(filename, "w", encoding="utf-8") as f: f.write(html)
        self.console.print(f"[green]✅ Premium HTML Report saved: {filename}[/green]")

    def save_json(self, results, filename="droidscan_report.json"):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({"generated": datetime.now().isoformat(), "total": len(results), 
                       "results": results}, f, indent=2)
        self.console.print(f"[green]✅ JSON Report saved: {filename}[/green]")

def main():
    parser = argparse.ArgumentParser(description="DroidScan v2.1 Premium")
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--package", type=str)
    parser.add_argument("--export", choices=["json", "html", "both"], default="both")
    parser.add_argument("--vt-key", type=str)
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    config = Config(args.config)
    if args.vt_key:
        config.data["vt_api_key"] = args.vt_key
        config.save()

    scanner = DroidScanner(config)

    # ================== NEW BANNER ==================
    banner_art = r"""
[bold green]
 ____DroidScan___ 
| _ \ _ __ ___ (_) __| |/ ___| ___ __ _ _ __ 
| | | | '__/ _ \| |/ _ |\___ \ / __/ _ | '_ \ 
| |_| | | | (_) | | (_| | ___) | (_| (_| | | | | 
|____/|_| \___/|_|\__,_||____/ \___\__,_|_| |_| 
[/bold green]
"""
    scanner.console.print(banner_art)
    scanner.console.print(Panel.fit(
        "[bold cyan]DroidScan v2.1[/bold cyan] — Premium Android Malware Analyzer\n"
        "[bold yellow]Developer: Anupom[/bold yellow]",
        border_style="green"
    ))
    scanner.console.print()
    # ===============================================

    if scanner.is_rooted():
        scanner.console.print("[yellow]⚠️  ROOTED DEVICE DETECTED — Extra Caution Recommended[/yellow]")

    if args.scan:
        results = scanner.scan_all()
        if results:
            scanner.show_results(results)
            if args.export in ["json", "both"]: scanner.save_json(results)
            if args.export in ["html", "both"]: scanner.generate_html(results)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()