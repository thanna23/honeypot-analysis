"""Tests for the IP-to-country lookup in analysis/geo.py.

The country database isn't in the repo (its licence doesn't allow it), so
these tests are skipped when dbip-country-lite.mmdb isn't in the project root.
"""
from pathlib import Path

import pytest

DB = Path(__file__).resolve().parent.parent / "dbip-country-lite.mmdb"

if not DB.exists():
    pytest.skip("dbip-country-lite.mmdb not downloaded", allow_module_level=True)

# geo.py opens the database with a relative path, so run pytest from the project root
from geo import country  # noqa: E402


def test_public_ip_has_a_country():
    # Google's public DNS, registered in the United States
    assert country("8.8.8.8") == "United States"


@pytest.mark.parametrize("ip", ["127.0.0.1", "172.31.44.174", "10.0.0.1"])
def test_private_ips_are_unknown(ip):
    assert country(ip) == "Unknown"


@pytest.mark.parametrize("ip", ["not-an-ip", "", None])
def test_bad_input_is_unknown(ip):
    assert country(ip) == "Unknown"
