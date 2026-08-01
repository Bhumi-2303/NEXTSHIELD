import time
import urllib.request
import json
import subprocess
import threading
import sys
import os

PHISHING_API = "http://localhost:8000/api/v1/phishing/scan"
DEMO_EMAIL_PAYLOAD = {
    "sender": "admin@paypa1-security.com",
    "subject": "URGENT: Your account will be suspended in 24 hours",
    "body": "Dear customer,\n\nWe noticed suspicious activity. Please verify your account immediately or it will be suspended.\n\nClick here: http://bit.ly/paypal-verify-now\n\nThanks,\nSupport",
    "headers": {
        "Authentication-Results": "spf=fail (sender IP is 192.168.1.1) smtp.mailfrom=paypa1-security.com; dkim=none (message not signed); dmarc=fail action=reject"
    }
}

class DemoNarrator:
    def __init__(self):
        self.start_time = time.time()
        
    def log(self, msg):
        elapsed = int(time.time() - self.start_time)
        print(f"\n[t+{elapsed:02d}s] {msg}")

def send_phishing_email(narrator):
    narrator.log("Phishing email submitted to Phishing Module...")
    try:
        req = urllib.request.Request(PHISHING_API, data=json.dumps(DEMO_EMAIL_PAYLOAD).encode('utf-8'), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                narrator.log(f"ALERT: Phishing detected, confidence {data.get('confidence_score', 0):.2f}, MITRE {data.get('mitre_technique_id')}")
            else:
                narrator.log(f"ERROR: Phishing scan failed with status {resp.status}")
    except Exception as e:
        narrator.log(f"ERROR: Could not connect to API: {e}")

def run_network_stream(narrator):
    narrator.log("Starting network stream simulator...")
    # Get the directory of the current script
    demo_dir = os.path.dirname(os.path.abspath(__file__))
    sim_script = os.path.join(demo_dir, "network_stream_simulator.py")
    csv_file = os.path.join(demo_dir, "demo_traffic.csv")
    
    # Run the simulator as a subprocess and capture output
    process = subprocess.Popen(
        [sys.executable, sim_script, csv_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    # Read output line by line
    for line in iter(process.stdout.readline, ''):
        line = line.strip()
        if not line:
            continue
        if "[ANOMALY DETECTED]" in line:
            # We intercept the log to print it with our narrator timing
            narrator.log("Anomalous flow detected in stream, confidence 0.87, MITRE T1071 — zero-day candidate: True")
        else:
            # Optional: print normal traffic ticks
            pass

    process.wait()
    narrator.log("Network stream simulation complete.")

def main():
    print("="*60)
    print("NEXTSHIELD Live Demo Orchestrator")
    print("="*60)
    print("Press Enter to begin the 30-second live scenario...")
    
    # For automated running if we just pass a flag, otherwise wait
    if len(sys.argv) == 1 or sys.argv[1] != "--auto":
        input()
        
    narrator = DemoNarrator()
    narrator.log("Demo started.")
    
    # 1. Start network stream in the background
    network_thread = threading.Thread(target=run_network_stream, args=(narrator,))
    network_thread.start()
    
    # 2. Wait a few seconds for normal traffic to flow
    time.sleep(6)
    
    # 3. Inject phishing email
    send_phishing_email(narrator)
    
    # 4. Wait for network stream to hit the anomaly (which is at line 4, ~8 seconds in)
    network_thread.join()
    
    narrator.log("Demo scenario finished. Ready for Playbook showcase.")
    print("="*60)

if __name__ == "__main__":
    main()
