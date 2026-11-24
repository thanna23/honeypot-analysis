"""Print the headline numbers: connections, usernames, passwords, commands, countries."""
from load import load_events
from geo import country

df = load_events()

# split the events by type (the "eventid" column)
logins = df[df.eventid.isin(["cowrie.login.failed", "cowrie.login.success"])]  # username, password
cmds = df[df.eventid == "cowrie.command.input"]    # input = the command typed
conns = df[df.eventid == "cowrie.session.connect"]  # src_ip = who connected

# how many connections, and from how many different attackers
print(len(conns), "connections from", conns.src_ip.nunique(), "unique IPs")

# most-tried usernames and passwords
print(logins.username.value_counts().head(10))
print(logins.password.value_counts().head(10))

# most-typed commands
# clean commands: trim spaces, drop empty ones, cut long junk to 60 chars
# (otherwise one very long line pushes the whole table off the screen)
if cmds.empty:
    print("No commands yet (no attacker has logged in)")
else:
    cmd_text = cmds.input.str.strip()
    cmd_text = cmd_text[cmd_text != ""].str.slice(0, 60)
    print(cmd_text.value_counts().head(15))

# where the connections come from
conns = conns.assign(country=conns.src_ip.map(country))
print(conns.country.value_counts().head(10))
