"""Tests for reading Cowrie log files in analysis/load.py."""
import json

import pandas as pd

from load import load_events


def write_jsonl(path, events):
    """Write events the way Cowrie does: one JSON object per line."""
    path.write_text("".join(json.dumps(e) + "\n" for e in events))


def test_reads_current_and_rotated_files(tmp_path):
    # today's file plus one rotated day, like Cowrie leaves them
    write_jsonl(tmp_path / "cowrie.json", [
        {"eventid": "cowrie.session.connect", "src_ip": "1.1.1.1",
         "timestamp": "2026-11-24T11:09:41.491783Z"},
    ])
    write_jsonl(tmp_path / "cowrie.json.2026-11-23", [
        {"eventid": "cowrie.session.connect", "src_ip": "2.2.2.2",
         "timestamp": "2026-11-23T08:00:00.000000Z"},
        {"eventid": "cowrie.login.failed", "src_ip": "2.2.2.2",
         "username": "root", "password": "123456",
         "timestamp": "2026-11-23T08:00:01.000000Z"},
    ])
    # the plain-text log must be ignored
    (tmp_path / "cowrie.log").write_text("not json\n")

    df = load_events(str(tmp_path))

    assert len(df) == 3
    assert set(df.src_ip) == {"1.1.1.1", "2.2.2.2"}


def test_timestamps_are_datetimes(tmp_path):
    write_jsonl(tmp_path / "cowrie.json", [
        {"eventid": "cowrie.session.connect", "timestamp": "2026-11-24T11:09:41.491783Z"},
    ])
    df = load_events(str(tmp_path))

    assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])
    assert df.timestamp.iloc[0].hour == 11


def test_columns_exist_even_when_no_event_has_them(tmp_path):
    # bots only connected: no username, password or input anywhere
    write_jsonl(tmp_path / "cowrie.json", [
        {"eventid": "cowrie.session.connect", "session": "a", "src_ip": "1.1.1.1",
         "timestamp": "2026-11-24T11:00:00Z"},
    ])
    df = load_events(str(tmp_path))

    for col in ["username", "password", "input", "url", "shasum"]:
        assert col in df.columns
        assert df[col].isna().all()


def test_drops_my_own_ips(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_IPS", "203.0.113.7")
    write_jsonl(tmp_path / "cowrie.json", [
        {"eventid": "cowrie.session.connect", "src_ip": "203.0.113.7",
         "timestamp": "2026-11-24T11:00:00Z"},
        {"eventid": "cowrie.session.connect", "src_ip": "127.0.0.1",
         "timestamp": "2026-11-24T11:00:01Z"},
        {"eventid": "cowrie.session.connect", "src_ip": "185.220.101.7",
         "timestamp": "2026-11-24T11:00:02Z"},
    ])
    assert load_events(str(tmp_path)).src_ip.tolist() == ["185.220.101.7"]
    # and they can still be kept on purpose
    assert len(load_events(str(tmp_path), exclude_mine=False)) == 3


def test_missing_fields_become_nan(tmp_path):
    # "password" only exists on login events
    write_jsonl(tmp_path / "cowrie.json", [
        {"eventid": "cowrie.session.connect", "timestamp": "2026-11-24T11:00:00Z"},
        {"eventid": "cowrie.login.failed", "password": "admin",
         "timestamp": "2026-11-24T11:00:01Z"},
    ])
    df = load_events(str(tmp_path))

    assert df.password.isna().sum() == 1
    assert df.password.dropna().tolist() == ["admin"]
