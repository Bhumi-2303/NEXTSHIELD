#!/usr/bin/env python3
"""
NEXTSHIELD Network Stream Simulator

Replays CSV flow records to the NEXTSHIELD API to simulate live network traffic.
Provides colored terminal output showing analysis results.
"""

import argparse
import os
import random
import sys
import time
from pathlib import Path

import httpx
import pandas as pd

COLORS = {
    'low': '\033[92m',        # green
    'medium': '\033[93m',     # yellow
    'high': '\033[38;5;208m', # orange
    'critical': '\033[91m',   # red
    'zero_day': '\033[95m',   # purple
    'reset': '\033[0m',
    'bold': '\033[1m',
    'dim': '\033[2m',
}

def print_banner():
    banner = f"""{COLORS['bold']}
╔══════════════════════════════════════════════════════╗
║  🛡️  NEXTSHIELD — Network Stream Simulator          ║
╚══════════════════════════════════════════════════════╝{COLORS['reset']}
"""
    print(banner)

def generate_sample_csv(filepath: str):
    """Generate a sample CSV file with mixed benign and malicious flows."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    columns = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_duration",
        "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "fin_flag_count",
        "syn_flag_count", "rst_flag_count", "psh_flag_count", "ack_flag_count",
        "urg_flag_count", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min"
    ]
    
    flows = []
    
    def rand_public():
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    
    def rand_internal():
        return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    
    # ~35 benign flows
    for _ in range(35):
        flows.append([
            rand_internal(), rand_public(), random.randint(1024, 65535), random.choice([80, 443, 8080]), 6,
            random.uniform(0.1, 5.0), random.randint(5, 50), random.randint(5, 50),
            random.randint(100, 5000), random.randint(1000, 20000), 
            random.choice([0, 1]), random.choice([0, 1]), 0, random.choice([0, 1]), 1, 0,
            random.uniform(0.01, 0.1), random.uniform(0.001, 0.05), random.uniform(0.05, 0.2), random.uniform(0.001, 0.01)
        ])
        
    # ~5 DoS flows
    for _ in range(5):
        flows.append([
            rand_public(), rand_internal(), random.randint(1024, 65535), 80, 6,
            random.uniform(10.0, 50.0), random.randint(1000, 5000), random.randint(10, 50),
            random.randint(50000, 200000), random.randint(100, 1000),
            0, 1, 0, 0, 0, 0,
            random.uniform(0.0001, 0.001), random.uniform(0.0001, 0.001), random.uniform(0.001, 0.01), random.uniform(0.00001, 0.0001)
        ])
        
    # ~3 PortScan flows
    src_ip = rand_internal()
    for _ in range(3):
        flows.append([
            src_ip, rand_public(), random.randint(1024, 65535), random.randint(1, 1024), 6,
            random.uniform(0.01, 0.1), 1, 1, 40, 40,
            0, 1, 1, 0, 0, 0,
            0.0, 0.0, 0.0, 0.0
        ])
        
    # ~3 SSH brute-force flows
    src_ip = rand_public()
    dst_ip = rand_internal()
    for _ in range(3):
        flows.append([
            src_ip, dst_ip, random.randint(1024, 65535), 22, 6,
            random.uniform(1.0, 5.0), random.randint(20, 50), random.randint(20, 50),
            random.randint(1000, 3000), random.randint(2000, 5000),
            0, 1, 0, 1, 1, 0,
            random.uniform(0.01, 0.1), random.uniform(0.01, 0.05), random.uniform(0.1, 0.5), random.uniform(0.001, 0.01)
        ])
        
    # ~2 DDoS flows
    for _ in range(2):
        flows.append([
            rand_public(), rand_internal(), random.randint(1024, 65535), 80, 17,
            random.uniform(20.0, 100.0), random.randint(5000, 20000), 0,
            random.randint(500000, 2000000), 0,
            0, 0, 0, 0, 0, 0,
            random.uniform(0.00001, 0.0001), random.uniform(0.00001, 0.0001), random.uniform(0.0001, 0.001), random.uniform(0.000001, 0.00001)
        ])
        
    # ~2 zero-day candidates (weird protocol, flags, sizes)
    for _ in range(2):
        flows.append([
            rand_public(), rand_internal(), random.randint(1024, 65535), random.randint(1024, 65535), 255, # reserved proto
            random.uniform(100.0, 500.0), random.randint(1, 5), random.randint(1, 5),
            random.randint(100000, 500000), random.randint(100000, 500000),
            1, 1, 1, 1, 1, 1, # all flags set (XMAS)
            random.uniform(5.0, 10.0), random.uniform(1.0, 5.0), random.uniform(10.0, 20.0), random.uniform(0.1, 1.0)
        ])
        
    random.shuffle(flows)
    
    df = pd.DataFrame(flows, columns=columns)
    df.to_csv(filepath, index=False)
    print(f"{COLORS['bold']}{COLORS['low']}✅ Generated 50-row sample CSV at {filepath}{COLORS['reset']}")


def _protocol_name(val) -> str:
    """Convert numeric protocol to name if needed."""
    _map = {6: "TCP", 17: "UDP", 1: "ICMP", 255: "UNKNOWN"}
    if isinstance(val, (int, float)):
        return _map.get(int(val), str(int(val)))
    return str(val)


def send_batch(batch, endpoint: str):
    """Send a batch of flows to the API and print results."""
    records = batch.to_dict(orient="records")
    # Ensure protocol is a string (CSV may store numeric IANA numbers)
    for r in records:
        r["protocol"] = _protocol_name(r.get("protocol", "TCP"))
    payload = {"flows": records}
    
    try:
        response = httpx.post(endpoint, json=payload, timeout=10.0)
        response.raise_for_status()
        
        results = response.json()  # API returns a list directly
        if isinstance(results, dict):
            results = results.get("results", [])
        
        for res in results:
            severity = res.get("severity", "low").lower()
            score = res.get("anomaly_score", 0.0)
            conf = res.get("confidence_score", 0.0)
            mitre = res.get("mitre_technique_id", "N/A")
            src = res.get("src_ip", "unknown")
            dst = res.get("dst_ip", "unknown")
            is_zero_day = res.get("is_zero_day_candidate", False)
            
            color = COLORS.get(severity, COLORS['reset'])
            prefix = ""
            if is_zero_day:
                color = COLORS['zero_day']
                prefix = f"🔮 {COLORS['bold']}ZERO-DAY CANDIDATE{COLORS['reset']} "
                
            print(f"{color}[{severity.upper():^8}]{COLORS['reset']} {prefix}{src} → {dst} | Score: {score:.2f} | Conf: {conf:.2f} | MITRE: {mitre}")
            
    except httpx.ConnectError:
        print(f"{COLORS['critical']}❌ Connection error: Could not reach {endpoint}. Retrying...{COLORS['reset']}")
    except httpx.HTTPStatusError as e:
        print(f"{COLORS['critical']}❌ HTTP error {e.response.status_code}: {e.response.text}{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['critical']}❌ Error: {str(e)}{COLORS['reset']}")

def main():
    parser = argparse.ArgumentParser(description="NEXTSHIELD Network Stream Simulator")
    parser.add_argument('-c', '--csv', default='data/network/demo_flows.csv', help='Path to a CSV file of flow records')
    parser.add_argument('-e', '--endpoint', default='http://localhost:8000/api/v1/anomaly/analyze', help='API endpoint URL')
    parser.add_argument('-b', '--batch-size', type=int, default=5, help='Number of flows per batch')
    parser.add_argument('-i', '--interval', type=float, default=2.0, help='Seconds between batches')
    parser.add_argument('-g', '--generate-sample', action='store_true', help='Generate a sample CSV and exit')
    parser.add_argument('-l', '--loops', type=int, default=1, help='Number of times to loop through the CSV (0 = infinite)')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.generate_sample:
        generate_sample_csv(args.csv)
        sys.exit(0)
        
    if not os.path.exists(args.csv):
        print(f"{COLORS['critical']}❌ Error: CSV file '{args.csv}' not found.{COLORS['reset']}")
        print(f"{COLORS['dim']}💡 Suggestion: Run with --generate-sample to create it.{COLORS['reset']}")
        sys.exit(1)
        
    print(f"{COLORS['bold']}📡 Loading flows from {args.csv}...{COLORS['reset']}")
    try:
        df = pd.read_csv(args.csv)
    except Exception as e:
        print(f"{COLORS['critical']}❌ Failed to read CSV: {e}{COLORS['reset']}")
        sys.exit(1)
        
    total_flows = len(df)
    print(f"{COLORS['dim']}Loaded {total_flows} flows.{COLORS['reset']}")
    
    loops = args.loops
    loop_count = 0
    
    try:
        while loops == 0 or loop_count < loops:
            if loops != 1:
                print(f"\n{COLORS['bold']}🔄 Starting loop {loop_count + 1}{COLORS['reset']}")
                
            for i in range(0, total_flows, args.batch_size):
                batch = df.iloc[i:i + args.batch_size]
                
                print(f"\n{COLORS['dim']}Sending batch {i // args.batch_size + 1}... ({len(batch)} flows){COLORS['reset']}")
                send_batch(batch, args.endpoint)
                
                time.sleep(args.interval)
                
            loop_count += 1
            
    except KeyboardInterrupt:
        print(f"\n{COLORS['bold']}{COLORS['medium']}🛑 Simulation stopped by user.{COLORS['reset']}")
        sys.exit(0)
        
    print(f"\n{COLORS['bold']}{COLORS['low']}✅ Simulation complete.{COLORS['reset']}")

if __name__ == "__main__":
    main()
