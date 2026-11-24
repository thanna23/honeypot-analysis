"""Look up which country an IP address comes from."""
import geoip2.database

# Free IP-to-country database (DB-IP Lite, same format as MaxMind GeoLite2).
# Its licence doesn't allow committing it, so *.mmdb is in .gitignore.
# Opened once here and reused for every lookup.
reader = geoip2.database.Reader("dbip-country-lite.mmdb")


def country(ip):
    """Return the country name for `ip`, or "Unknown" if it can't be found.

    Private and local addresses (127.0.0.1, 172.31.x.x) aren't in the
    database and raise an error, so they come back as "Unknown".
    """
    try:
        return reader.country(ip).country.name
    except Exception:
        return "Unknown"
