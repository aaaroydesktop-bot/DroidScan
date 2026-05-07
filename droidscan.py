#!/usr/bin/env python3
"""
DroidScan v2.0 - Advanced Android Malware Analysis Tool
Developer: Anupom (Upgraded by Grok)
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
    "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN"
]

SUSPICIOUS_KEYWORDS = [
    "spy", "hack", "track", "steal", "keylog", "rat", "trojan", "backdoor",
    "hidden", "secret", "monitor", "remote", "admin", "payload", "inject"
]

BLACKLISTED_PACKAGES = [
    "com.hidden.ads", "com.spyware.tracker", "com.malicious.payload",
    "com.android.system.update", "com.google.android.gms.update"
]

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
                with open(path, "r") as f:
                    loaded = json.load(f)
                    self.data.update(loaded)
            except:
                pass

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=4)

class DroidScanner:
    def __init__(self, config: Config):
        self.console = Console()
        self.config = config
        self.setup_logging()
        self.results = []

    def setup_logging(self):
        logging.basicConfig(
            filename=self.config.data["log_file"],
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger("DroidScan")

    def is_rooted(self):
        paths = ["/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su"]
        for p in paths:
            if os.path.exists(p):
                return True
        try:
            subprocess.run(["su", "-c", "id"], capture_output=True, timeout=2)
            return True
        except:
            return False

    def get_installed_apps(self):
        try:
            result = subprocess.run(
                ["pm", "list", "packages", "-3", "-f"],
                capture_output=True, text=True, timeout=15
            )
            apps = []
            for line in result.stdout.splitlines():
                if "package:" in line:
                    parts = line.replace("package:", "").strip().split()
                    if len(parts) >= 2:
                        apk_path = parts[0]
                        package = parts[1].replace("=", "")
                        apps.append({"package": package, "apk_path": apk_path})
            return apps
        except Exception as e:
            self.logger.error(f"Error getting apps: {e}")
            return []

    def get_apk_info(self, apk_path):
        info = {"permissions": [], "label": "Unknown", "version": "N/A", "error": None}
        if not os.path.exists(apk_path):
            info["error"] = "APK not found"
            return info

        try:
            result = subprocess.run(
                ["aapt", "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=20
            )
            output = result.stdout

            for line in output.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    if "name='" in line:
                        info["package"] = line.split("name='")[1].split("'")[0]
                    if "versionName='" in line:
                        info["version"] = line.split("versionName='")[1].split("'")[0]
                elif line.startswith("application-label:"):
                    info["label"] = line.split(":", 1)[1].strip().strip("'")
                elif line.startswith("uses-permission:"):
                    if "name='" in line:
                        perm = line.split("name='")[1].split("'")[0]
                        info["permissions"].append(perm)
        except FileNotFoundError:
            info["error"] = "aapt not found. Run: pkg install aapt"
        except Exception as e:
            info["error"] = str(e)
        return info

    def calculate_sha256(self, file_path):
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None

    def check_virustotal(self, sha256):
        api_key = self.config.data.get("vt_api_key", "")
        if not api_key or not sha256:
            return {"status": "N/A", "detections": 0, "total": 0}

        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": api_key}

        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                return {
                    "status": f"{malicious}/{total}",
                    "detections": malicious,
                    "total": total
                }
            elif resp.status_code == 404:
                return {"status": "Not Found", "detections": 0, "total": 0}
            else:
                return {"status": f"Error {resp.status_code}", "detections": 0, "total": 0}
        except Exception as e:
            self.logger.error(f"VT Error: {e}")
            return {"status": "Error", "detections": 0, "total": 0}

    def calculate_risk_score(self, app_info, vt_result):
        score = 0
        package = app_info.get("package", "")

        # Blacklist
        if package in self.config.data["blacklist"]:
            score += 45

        # Suspicious keywords
        for kw in self.config.data["suspicious_keywords"]:
            if kw.lower() in package.lower():
                score += 25
                break

        # Dangerous permissions
        dangerous_count = sum(
            1 for p in app_info.get("permissions", [])
            if p in self.config.data["dangerous_permissions"]
        )
        score += min(dangerous_count * 4, 30)

        # VirusTotal
        if vt_result.get("detections", 0) > 0:
            score += min(vt_result["detections"] * 3, 25)

        return min(score, 100)

    def analyze_app(self, app):
        package = app["package"]
        apk_path = app["apk_path"]

        apk_info = self.get_apk_info(apk_path)
        sha256 = self.calculate_sha256(apk_path) if apk_path else None
        vt_result = self.check_virustotal(sha256) if sha256 else {"status": "N/A", "detections": 0}

        risk = self.calculate_risk_score({**app, **apk_info}, vt_result)

        if risk >= 70:
            status = "CRITICAL"
            color = "bold red"
        elif risk >= 50:
            status = "HIGH"
            color = "red"
        elif risk >= 30:
            status = "MEDIUM"
            color = "yellow"
        else:
            status = "LOW"
            color = "green"

        result = {
            "package": package,
            "label": apk_info.get("label", "Unknown"),
            "version": apk_info.get("version", "N/A"),
            "risk_score": risk,
            "status": status,
            "color": color,
            "permissions_count": len(apk_info.get("permissions", [])),
            "dangerous_permissions": [p for p in apk_info.get("permissions", []) 
                                      if p in self.config.data["dangerous_permissions"]],
            "vt_result": vt_result,
            "sha256": sha256[:16] + "..." if sha256 else "N/A",
            "apk_path": apk_path
        }
        return result

    def scan_all(self):
        apps = self.get_installed_apps()
        if not apps:
            self.console.print("[red]No third-party apps found![/red]")
            return []

        self.console.print(f"[cyan]Found {len(apps)} apps. Starting advanced analysis...[/cyan]\n")

        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("Scanning...", total=len(apps))

            with ThreadPoolExecutor(max_workers=self.config.data["max_workers"]) as executor:
                future_to_app = {executor.submit(self.analyze_app, app): app for app in apps}
                for future in as_completed(future_to_app):
                    result = future.result()
                    results.append(result)
                    progress.update(task, advance=1)

        self.results = results
        return results

    def display_results(self, results):
        table = Table(title="DroidScan v2.0 - Advanced Report", show_header=True, header_style="bold magenta")
        table.add_column("Package", style="cyan", no_wrap=False)
        table.add_column("Label", style="white")
        table.add_column("Risk", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("VT", justify="center")
        table.add_column("Dangerous Perms", justify="right")

        for r in sorted(results, key=lambda x: x["risk_score"], reverse=True):
            table.add_row(
                r["package"],
                r["label"][:25],
                f"[bold]{r['risk_score']}[/bold]",
                f"[{r['color']}]{r['status']}[/{r['color']}]",
                r["vt_result"]["status"],
                str(len(r["dangerous_permissions"]))
            )
        self.console.print(table)

    def generate_html_report(self, results, filename="droidscan_report.html"):
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>DroidScan v2.0 Report</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
</head><body class="bg-gray-900 text-white">
<div class="max-w-7xl mx-auto p-8">
<h1 class="text-4xl font-bold mb-4 text-green-400">DroidScan v2.0 Report</h1>
<p class="mb-6 text-gray-400">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Developer: Anupom</p>

<table class="w-full table-auto border-collapse">
<thead><tr class="bg-gray-800">
<th class="px-4 py-3 text-left">Package</th>
<th class="px-4 py-3">Risk</th>
<th class="px-4 py-3">Status</th>
<th class="px-4 py-3">VT</th>
<th class="px-4 py-3">Dangerous Perms</th>
</tr></thead><tbody>"""

        for r in sorted(results, key=lambda x: x["risk_score"], reverse=True):
            color = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "yellow", "LOW": "green"}.get(r["status"], "gray")
            html += f"""<tr class="border-b border-gray-700 hover:bg-gray-800">
<td class="px-4 py-3 font-mono text-sm">{r['package']}</td>
<td class="px-4 py-3 text-center font-bold">{r['risk_score']}</td>
<td class="px-4 py-3 text-center"><span class="px-3 py-1 rounded-full bg-{color}-600">{r['status']}</span></td>
<td class="px-4 py-3 text-center">{r['vt_result']['status']}</td>
<td class="px-4 py-3 text-center">{len(r['dangerous_permissions'])}</td>
</tr>"""

        html += "</tbody></table></div></body></html>"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        self.console.print(f"[green]HTML report saved: {filename}[/green]")

    def save_json(self, results, filename="droidscan_report.json"):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.now().isoformat(),
                "total_apps": len(results),
                "rooted": self.is_rooted(),
                "results": results
            }, f, indent=2, ensure_ascii=False)
        self.console.print(f"[green]JSON report saved: {filename}[/green]")

def main():
    parser = argparse.ArgumentParser(description="DroidScan v2.0 - Advanced Android Malware Analyzer")
    parser.add_argument("--scan", action="store_true", help="Scan all third-party apps")
    parser.add_argument("--package", type=str, help="Scan single package")
    parser.add_argument("--export", choices=["json", "html", "both"], default="both", help="Export format")
    parser.add_argument("--vt-key", type=str, help="VirusTotal API Key")
    parser.add_argument("--config", default="config.json", help="Config file path")
    args = parser.parse_args()

    config = Config(args.config)
    if args.vt_key:
        config.data["vt_api_key"] = args.vt_key
        config.save()

    scanner = DroidScanner(config)

    scanner.console.print(Panel.fit(
        "[bold green]DroidScan v2.0[/bold green]\nAdvanced Android Malware Analyzer\nDeveloper: Anupom",
        border_style="green"
    ))

    if scanner.is_rooted():
        scanner.console.print("[yellow]⚠️  Device is ROOTED — extra caution recommended[/yellow]")

    if args.package:
        app = {"package": args.package, "apk_path": None}  # can enhance later
        result = scanner.analyze_app(app)
        scanner.display_results([result])
    elif args.scan:
        results = scanner.scan_all()
        scanner.display_results(results)

        if args.export in ["json", "both"]:
            scanner.save_json(results)
        if args.export in ["html", "both"]:
            scanner.generate_html_report(results)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()