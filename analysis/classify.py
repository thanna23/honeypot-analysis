"""Label each session with one attack type, based on the commands typed in it.

Run it directly to print the attack-type counts:
    python analysis/classify.py
plots.py also imports classify_sessions() for the attack-types chart.
"""
import pandas as pd

# Each rule is (label, keywords). A session gets the label if any of its
# commands contains one of the keywords.
# Checked in order: the first matching rule wins, so the most specific
# (and most serious) behaviour goes first. For example a session that
# downloads xmrig with curl is a "crypto-miner", not a "malware download".
RULES = [
    ("crypto-miner", ["xmrig", "miner"]),                  # mining software
    ("persistence", ["authorized_keys"]),                  # adds their SSH key as a backdoor
    ("malware download", ["wget", "curl", "tftp"]),        # fetches a file from the internet
    ("reconnaissance", ["uname", "/proc/cpuinfo", "free -m", "whoami", "/etc/passwd"]),  # looks around the system
]

# commands that fetch a file, used for the separate "downloaded" column
DOWNLOAD_KEYWORDS = ["wget", "curl", "tftp"]


def label_commands(commands):
    """Return one label for a list of commands from a single session."""
    # join all the session's commands into one lowercase string to search
    text = " ".join(commands).lower()
    for label, keywords in RULES:
        if any(k in text for k in keywords):
            return label
    # ran commands, but none matched a rule (e.g. only "ls" or "exit")
    return "other"


def classify_sessions(df):
    """Return a DataFrame with one row per session that ran commands:
    session, src_ip, n_commands, attack_type, downloaded."""
    cmds = df[df.eventid == "cowrie.command.input"]

    # nobody ran a command (e.g. no bot managed to log in yet): pandas then
    # has no "input" column at all, so return an empty table instead of crashing
    if cmds.empty or "input" not in df.columns:
        return pd.DataFrame(columns=["session", "src_ip", "n_commands",
                                     "attack_type", "downloaded"])

    # group the command events by session: one row per session,
    # with all its commands collected into a list
    sessions = cmds.groupby("session").agg(
        src_ip=("src_ip", "first"),       # a session always has one source IP
        n_commands=("input", "size"),     # how many commands were typed
        commands=("input", list),         # the commands themselves
    )

    sessions["attack_type"] = sessions.commands.map(label_commands)

    # tried to download anything, whatever the final label (a miner is usually
    # downloaded too), so the "share that downloaded malware" finding is accurate
    sessions["downloaded"] = sessions.commands.map(
        lambda c: any(k in " ".join(c).lower() for k in DOWNLOAD_KEYWORDS)
    )

    # the full command lists are only needed for labelling, so drop them
    return sessions.drop(columns="commands").reset_index()


if __name__ == "__main__":
    from load import load_events

    df = load_events()
    sessions = classify_sessions(df)

    # sessions where the attacker got past the fake login
    logged_in = df[df.eventid == "cowrie.login.success"].session.nunique()

    print(len(sessions), "sessions ran commands, out of", logged_in, "successful logins")
    print(sessions.attack_type.value_counts())

    # share of sessions that tried to download something (avoid dividing by zero)
    downloads = sessions.downloaded.sum()
    if len(sessions):
        print(f"{downloads / len(sessions):.0%} of command sessions tried to download malware")
