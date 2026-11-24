"""Make the 4 charts for the README and save them to figures/.

Run from the project root:
    python analysis/plots.py
"""
from pathlib import Path

import matplotlib

# "Agg" draws straight to image files instead of opening a window,
# which WSL usually can't do. Must be set before importing pyplot.
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

from classify import classify_sessions
from geo import country
from load import load_events

# figures/ next to analysis/, found from this file's location so the charts
# land in the right place whatever folder you run the script from
FIGURES = Path(__file__).resolve().parent.parent / "figures"
FIGURES.mkdir(exist_ok=True)


def save(fig, name):
    """Save a chart to figures/<name> and free its memory."""
    fig.tight_layout()                       # stop labels getting cut off
    fig.savefig(FIGURES / name, dpi=150)     # 150 dpi looks sharp in a README
    plt.close(fig)
    print("saved", FIGURES / name)


def bar(series, title, xlabel, name):
    """Horizontal bar chart, biggest at the top.

    `series` is a value_counts() result: labels as the index, counts as values.
    Horizontal bars leave room for long labels like passwords.
    """
    fig, ax = plt.subplots(figsize=(8, 5))
    if series.empty:
        # e.g. no attacker logged in yet, so no commands to classify
        ax.text(0.5, 0.5, "No data yet", ha="center", va="center", fontsize=14)
        ax.set_axis_off()
        ax.set_title(title)
        save(fig, name)
        return
    # barh draws the first item at the bottom, so sort smallest-first
    # to put the biggest bar on top
    series.sort_values().plot.barh(ax=ax, color="#4C72B0")
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))  # counts: no 0.5 ticks
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("")  # the labels on the bars already say what they are
    save(fig, name)


df = load_events()
conns = df[df.eventid == "cowrie.session.connect"]
logins = df[df.eventid.isin(["cowrie.login.failed", "cowrie.login.success"])]

# 1. Connections per hour (line)
# resample("1h") puts the connections into one-hour buckets and size() counts
# them; hours with no connections show up as 0 instead of disappearing
per_hour = conns.set_index("timestamp").resample("1h").size()
fig, ax = plt.subplots(figsize=(10, 4))
ax.plot(per_hour.index, per_hour.values, color="#4C72B0", marker="o", markersize=3)
ax.set_ylim(bottom=0)    # start at 0 so small changes don't look huge
ax.yaxis.set_major_locator(MaxNLocator(integer=True))
fig.autofmt_xdate()      # tilt the date labels so they don't overlap
ax.set_title("Connections per hour")
ax.set_xlabel("Time (UTC)")  # Cowrie logs in UTC
ax.set_ylabel("Connections")
save(fig, "connections_per_hour.png")

# 2. Top 10 passwords (bar)
# dropna: some login events have no password; astype(str): numeric
# passwords like 123456 must be text to count them alongside the others
passwords = logins.password.dropna().astype(str).value_counts().head(10)
bar(passwords, "Top 10 passwords tried", "Login attempts", "top_passwords.png")

# 3. Top 10 countries (bar)
countries = conns.src_ip.map(country).value_counts().head(10)
bar(countries, "Top 10 countries by connections", "Connections", "top_countries.png")

# 4. Attack types (bar) -- one label per session, from classify.py
attack_types = classify_sessions(df).attack_type.value_counts()
bar(attack_types, "Attack types (one label per session)", "Sessions", "attack_types.png")
