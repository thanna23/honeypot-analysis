"""Make a small anonymized sample of the logs that is safe to publish on GitHub.

Reads data/raw/cowrie.json*, writes data/sample/cowrie.json (~500 events).

- Whole sessions are sampled (not single events), so each session keeps its
  connect, login and command events together and classify.py still works.
- Every IPv4 address anywhere in an event is masked: 185.220.101.7 -> 185.220.x.x
  (src_ip, but also connection messages, download URLs, etc.).
- The sensor name (which contains the server's private IP) is replaced.
- Your own IPs are dropped completely: 127.0.0.1 (tests on the server) and any
  IPs in MY_IPS, set in .env (comma-separated, never committed):
      MY_IPS=203.0.113.7,198.51.100.4

Run from the project root:
    python analysis/make_sample.py
"""
import glob
import json
import os
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "sample" / "cowrie.json"
TARGET_EVENTS = 500
SEED = 0  # fixed, so running it twice on the same logs gives the same sample

# an IPv4 address; group 1 keeps the first two parts
IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b")


def my_ips():
    """IPs to drop: localhost plus MY_IPS from the environment or .env."""
    value = os.environ.get("MY_IPS", "")
    env_file = ROOT / ".env"
    if not value and env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("MY_IPS="):
                value = line.split("=", 1)[1]
    return {"127.0.0.1"} | {ip.strip() for ip in value.split(",") if ip.strip()}


def mask(value):
    """Mask every IPv4 address in a value (strings, and lists/dicts of them)."""
    if isinstance(value, str):
        return IPV4.sub(r"\1.x.x", value)
    if isinstance(value, list):
        return [mask(v) for v in value]
    if isinstance(value, dict):
        return {k: mask(v) for k, v in value.items()}
    return value  # numbers and booleans can't contain an IP


def anonymize(event):
    event = mask(event)
    if "sensor" in event:
        event["sensor"] = "honeypot"  # e.g. ip-172-31-44-174 -> honeypot
    return event


def sample_sessions(events, exclude_ips, target=TARGET_EVENTS, seed=SEED):
    """Pick random whole sessions until about `target` events are collected."""
    sessions = {}
    for e in events:
        sessions.setdefault(e.get("session"), []).append(e)

    # drop any session that came from one of my own IPs
    kept = [evs for evs in sessions.values()
            if not any(e.get("src_ip") in exclude_ips for e in evs)]

    random.Random(seed).shuffle(kept)
    picked = []
    for evs in kept:
        if len(picked) >= target:
            break
        picked += evs
    return sorted(picked, key=lambda e: e.get("timestamp", ""))


def main():
    events = []
    for f in sorted(glob.glob(str(RAW / "cowrie.json*"))):
        with open(f) as fh:
            events += [json.loads(line) for line in fh if line.strip()]
    if not events:
        raise SystemExit(f"No logs found in {RAW}. Run ./setup/fetch_logs.sh first.")

    sample = [anonymize(e) for e in sample_sessions(events, my_ips())]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as fh:
        for e in sample:
            fh.write(json.dumps(e) + "\n")

    n_sessions = len({e.get("session") for e in sample})
    print(f"Wrote {len(sample)} events from {n_sessions} sessions to {OUT}")


if __name__ == "__main__":
    main()
