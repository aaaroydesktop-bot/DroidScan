# DroidScan v1.0

A lightweight, terminal-based Android application analyzer built for Termux. 

## Features
- Extracts all installed third-party applications.
- Identifies the physical APK paths of the apps.
- Calculates SHA-256 hashes for static analysis.
- Flags potentially suspicious packages based on naming conventions and basic blacklists.

## Setup & Installation

1. Clone or download this repository to your Termux.
2. Ensure you have given Termux storage permission (if needed):
   ```bash
   termux-setup-storage