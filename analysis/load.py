"""Load all Cowrie JSON logs into one pandas DataFrame."""
import glob, json, os
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"        # real logs, on my laptop only (not on GitHub)
SAMPLE = ROOT / "data" / "sample"  # small anonymized sample, published on GitHub

# fields the analysis scripts use; always present after loading
COLUMNS = ["eventid", "session", "src_ip", "timestamp",
           "username", "password", "input", "url", "shasum"]


def my_ips():
    """My own IPs, whose sessions are my tests and not attacks.

    Always 127.0.0.1 (testing Cowrie from the server itself), plus MY_IPS
    from the environment or from .env (comma-separated, never committed):
        MY_IPS=203.0.113.7,198.51.100.4
    """
    value = os.environ.get("MY_IPS", "")
    env_file = ROOT / ".env"
    if not value and env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("MY_IPS="):
                value = line.split("=", 1)[1]
    return {"127.0.0.1"} | {ip.strip() for ip in value.split(",") if ip.strip()}


def default_path():
    """Use the real logs if they're here, otherwise the published sample.

    So my own runs use data/raw/, and anyone who clones the repo can still
    run everything on data/sample/.
    """
    if glob.glob(str(RAW / "cowrie.json*")):
        return RAW
    print(f"No logs in {RAW}, using the anonymized sample in {SAMPLE}")
    return SAMPLE


def load_events(path=None, exclude_mine=True):
    """Read every Cowrie log file in `path` and return one row per event.

    Cowrie writes the current day to cowrie.json and older days to rotated
    files (cowrie.json.YYYY-MM-DD), so the glob picks up all of them.
    Without a path, uses data/raw/ or falls back to data/sample/.
    With exclude_mine, events from my own IPs (see my_ips) are dropped.
    """
    if path is None:
        path = default_path()

    rows = []
    for f in glob.glob(f"{path}/cowrie.json*"):
        with open(f) as fh:
            # each line is one JSON event (JSON Lines format)
            rows += [json.loads(line) for line in fh]

    # events have different fields depending on their type; pandas fills
    # the missing ones with NaN (e.g. "password" only exists on login events)
    df = pd.DataFrame(rows)

    # a column only exists if at least one event has that field, so on a quiet
    # day (e.g. bots only connected, nobody logged in) "username" or "input"
    # would be missing and the other scripts would crash; add them as empty
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA

    # my own test sessions aren't attacks, so leave them out of every stat
    if exclude_mine:
        df = df[~df.src_ip.isin(my_ips())].reset_index(drop=True)

    # turn the timestamp text into real datetimes so we can group by hour
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df
