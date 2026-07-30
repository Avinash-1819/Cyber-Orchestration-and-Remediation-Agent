#!/usr/bin/env python3
"""
Sentinel AI — MITRE ATT&CK Dataset Refresh Script
Downloads the latest enterprise-attack.json STIX bundle from MITRE.
Run at Docker build time or on a schedule (e.g. weekly).

Usage: python data/mitre/refresh_mitre.py
"""
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTPUT_PATH = Path(__file__).parent / "enterprise-attack.json"
CHUNK_SIZE = 8192 * 10  # 80KB chunks


def download_mitre():
    print(f"[MITRE Refresh] Downloading from: {MITRE_STIX_URL}")
    print(f"[MITRE Refresh] Output: {OUTPUT_PATH}")

    try:
        req = urllib.request.Request(
            MITRE_STIX_URL,
            headers={"User-Agent": "sentinel-ai-mitre-refresh/1.0"},
        )
        with urllib.request.urlopen(req, timeout=120) as response:
            total_size = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            sha256 = hashlib.sha256()

            with open(OUTPUT_PATH, "wb") as f:
                while True:
                    chunk = response.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
                    sha256.update(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        pct = (downloaded / total_size) * 100
                        print(f"\r[MITRE Refresh] {downloaded / 1024 / 1024:.1f} MB / {total_size / 1024 / 1024:.1f} MB ({pct:.0f}%)", end="", flush=True)

        print(f"\n[MITRE Refresh] Download complete. SHA256: {sha256.hexdigest()[:16]}...")

        # Validate it's valid JSON with expected structure
        with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        objects = data.get("objects", [])
        techniques = [o for o in objects if o.get("type") == "attack-pattern"]
        print(f"[MITRE Refresh] Validated: {len(techniques)} attack techniques found.")

        # Write metadata
        meta_path = OUTPUT_PATH.parent / "mitre_meta.json"
        with open(meta_path, "w") as f:
            json.dump({
                "downloaded_at": __import__("datetime").datetime.utcnow().isoformat(),
                "technique_count": len(techniques),
                "sha256": sha256.hexdigest(),
                "source": MITRE_STIX_URL,
            }, f, indent=2)

        print("[MITRE Refresh] Done!")
        return True

    except Exception as e:
        print(f"\n[MITRE Refresh] ERROR: {e}", file=sys.stderr)
        print("[MITRE Refresh] Will use existing dataset if available.", file=sys.stderr)
        return False


if __name__ == "__main__":
    success = download_mitre()
    sys.exit(0 if success else 1)
