# SSH Honeypot on AWS — Attack Analysis

A real SSH honeypot running on AWS and open to the internet, plus Python code that analyzes what attackers do once they think they're in: the passwords they try, the commands they run, the malware they fetch, and where they come from.

**Status:** honeypot live since 24 Nov 2026 · collecting data · the findings below are a first snapshot and will be updated in a few weeks.

---

## Key findings

> **Early snapshot: 24 Nov 2026, 11:37–14:54 UTC (about 3 hours after going live).**
> This is a very small first sample. The honeypot keeps running and these findings will be updated in a few weeks with much more data. My own test sessions are excluded.

| Metric | Value |
| --- | --- |
| Connections | 10 |
| Unique attacker IPs | 6 |
| Countries | 5 |
| Login attempts | 0 |
| Commands captured | 0 |

- **Found within 30 minutes:** the first stranger connected at 11:37 UTC, less than 30 minutes after my first test from outside, although the server's address was never published anywhere.
- **Scanners, not attackers (yet):** all 10 connections opened and closed without trying a single password. 9 of them never even sent an SSH version string, which is typical of port scanners mapping which machines run SSH.
- **Where they came from:** Uzbekistan (4 connections), Argentina (2), Russia (2), the United States (1) and Ukraine (1).
- **Automated tools:** the only client that identified itself sent `SSH-2.0-Go`, a scanner written in Go rather than a human using a normal SSH client.
- **Still to come:** passwords, commands, malware downloads and attack types, once bots start logging in to the fake shell.

## Charts

_Same early snapshot (24 Nov 2026). The password and attack-type charts will appear once bots start logging in._

| | |
| --- | --- |
| ![Connections per hour](figures/connections_per_hour.png) | ![Top countries](figures/top_countries.png) |

---

## Architecture

```text
 Internet bots
      │  SSH, port 22
      ▼
┌──────────────────────────── AWS EC2 (Ubuntu 24.04) ────────────────────────────┐
│                                                                                │
│  iptables: port 22 ──► 2222        Cowrie honeypot (fake shell, fake files)    │
│                                          │                                     │
│  real admin SSH: port 22222              ▼                                     │
│  (my IP only)                     cowrie.json (one JSON event per line)        │
└──────────────────────────────────────────┬─────────────────────────────────────┘
                                           │  download logs
                                           ▼
                         Python analysis (pandas, matplotlib)
                   load ─► add country ─► classify ─► stats & charts
```

**How it works**

1. **The trap.** [Cowrie](https://github.com/cowrie/cowrie), a medium-interaction SSH honeypot, runs on an EC2 instance. iptables redirects port 22 to Cowrie, so bots scanning the internet for SSH land in a fake Linux shell. Nothing they type actually runs.
2. **Isolation.** The real admin SSH runs on a separate port that the AWS security group opens only to my IP. The honeypot machine holds no real data or credentials.
3. **Logging.** Cowrie records every connection, login attempt, command and file download as JSON.
4. **Analysis.** The Python code loads the logs, looks up each attacker's country, labels each session by attack type, and produces the numbers and charts above.

## Attack classification

`analysis/classify.py` gives each session that ran commands one label. The rules are checked in this order and the first match wins, so a session that downloads a miner with `curl` counts as a crypto-miner:

| Label | Matched when the commands contain |
| --- | --- |
| Crypto-miner | `xmrig`, `miner` |
| Persistence (backdoor key) | `authorized_keys` |
| Malware download | `wget`, `curl`, `tftp` |
| Reconnaissance | `uname`, `/proc/cpuinfo`, `free -m`, `whoami`, `/etc/passwd` |
| Other | none of the above (e.g. only `ls` or `exit`) |

Download attempts are also counted separately from the label, so the download share includes miner sessions.

---

## Project structure

```text
honeypot-analysis/
├── analysis/
│   ├── load.py        # load Cowrie JSON logs into a DataFrame
│   ├── geo.py         # IP → country lookup
│   ├── stats.py       # summary statistics
│   ├── classify.py    # label sessions by attack type
│   ├── plots.py       # charts saved to figures/
│   └── make_sample.py # builds the anonymized sample from the raw logs
├── data/sample/       # small anonymized sample (IPs masked)
├── figures/           # generated charts
├── setup/
│   ├── install.sh     # installs Cowrie, moves SSH to 22222, redirects port 22
│   └── fetch_logs.sh  # downloads the latest logs from the honeypot
├── tests/             # pytest tests for loading, classification, sampling and country lookup
└── requirements.txt
```

## Run it yourself

Requires Python 3.11+.

```bash
git clone https://github.com/thanna23/honeypot-analysis.git
cd honeypot-analysis
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Download the free [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite) database and unzip it into the project root as `dbip-country-lite.mmdb`, then run from the project root. The scripts use your own Cowrie logs if you put them (`cowrie.json*`) in `data/raw/`, and the anonymized sample in `data/sample/` otherwise:

```bash
python analysis/stats.py      # connections, usernames, passwords, commands, countries
python analysis/classify.py   # attack types and download share
python analysis/plots.py      # writes the 4 charts to figures/
pytest                        # runs the tests (country tests skip without the .mmdb file)
```

Raw logs are not published. `data/sample/` holds whole attacker sessions with every IP address masked (`185.220.x.x`), so country lookups in the sample show as "Unknown". Rebuild it from your raw logs with `python analysis/make_sample.py`.

## Privacy and safety

- Only aggregated statistics and a small sample with **masked IP addresses** are published. My own test sessions are removed from the sample entirely.
- No credentials, keys or server addresses are stored in this repository.
- The honeypot only emulates a shell: attackers can't run real commands or use it to attack other machines.

## What I'd improve next

- Automate log shipping with S3 + Lambda + DynamoDB for a live dashboard
- Define the whole infrastructure in Terraform so it deploys with one command
- Run honeypots in several AWS regions and compare attack patterns

## Tech stack

AWS EC2 · Ubuntu · Cowrie · iptables · Python · pandas · matplotlib · geoip2 · pytest

## Credits
- Built with help from [Claude](https://claude.ai) (Anthropic) as a coding assistant: it helped write parts of the analysis code (classification mostly), and the setup scripts. I deployed and secured the AWS infrastructure, set up and ran the honeypot, then reviewed and ran all code myself.
- [Cowrie](https://github.com/cowrie/cowrie) SSH honeypot
- IP geolocation by [DB-IP](https://db-ip.com), licensed under CC BY 4.0
