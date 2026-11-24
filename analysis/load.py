"""Load all Cowrie JSON logs into one pandas DataFrame."""
import glob, json
import pandas as pd

# TODO (Part 6): let people who clone the repo run the code without raw logs.
#   1. Write a script that makes data/sample/sample.json: ~500 random events
#      with masked IPs (e.g. 185.220.x.x), from the guide's Part 6 step 3.
#   2. Here, fall back to data/sample/ when data/raw/ has no cowrie.json* files,
#      and print which folder is being used. My own runs keep using data/raw/.


def load_events(path="data/raw"):
    """Read every Cowrie log file in `path` and return one row per event.

    Cowrie writes the current day to cowrie.json and older days to rotated
    files (cowrie.json.YYYY-MM-DD), so the glob picks up all of them.
    The path is relative, so run the scripts from the project root.
    """
    rows = []
    for f in glob.glob(f"{path}/cowrie.json*"):
        with open(f) as fh:
            # each line is one JSON event (JSON Lines format)
            rows += [json.loads(line) for line in fh]

    # events have different fields depending on their type; pandas fills
    # the missing ones with NaN (e.g. "password" only exists on login events)
    df = pd.DataFrame(rows)

    # turn the timestamp text into real datetimes so we can group by hour
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df
