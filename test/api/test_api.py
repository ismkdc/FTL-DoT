"""
Pi-hole FTL API integration tests — stats, lists, search, history,
config validation (API-side), HTTP errors, and Lua server pages.

These tests replace the equivalent curl-based BATS tests with native
Python assertions against a live FTL instance.

Usage:
    pytest test/api/test_api.py -v
"""

import json

import pytest

FTL_URL = "http://127.0.0.1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _j(response):
    """Return parsed JSON, stripping the volatile ``took`` field.

    Attach the raw text so pytest prints the full body on assertion
    failure (via ``__repr__``).
    """
    data = response.json()
    data.pop("took", None)
    return data


def set_config(api_session, dotted_key, value):
    """Set a FTL config item via the API.

    Builds the nested JSON payload from a dotted key, e.g.
    ``set_config(s, "webserver.serve_all", True)`` sends
    ``PATCH /api/config/webserver/serve_all``
    with ``{"config": {"webserver": {"serve_all": true}}}``.
    """
    parts = dotted_key.split(".")
    api_path = f"{FTL_URL}/api/config/" + "/".join(parts)

    payload = value
    for part in reversed(parts):
        payload = {part: payload}
    payload = {"config": payload}

    r = api_session.patch(api_path, json=payload, timeout=20)
    assert r.status_code == 200, \
        f"Failed to set {dotted_key}: {r.status_code} {r.text}"
    return r


# ---------------------------------------------------------------------------
# HTTP error responses
# ---------------------------------------------------------------------------

class TestHTTPErrors:

    def test_api_404_returns_json(self, api_session):
        """HTTP server responds with JSON error 404 to unknown API path."""
        data = _j(api_session.get(f"{FTL_URL}/api/undefined", timeout=5))
        assert data["error"] == {
            "key": "not_found",
            "message": "Not found",
            "hint": "/api/undefined",
        }, json.dumps(data, indent=2)

    def test_non_admin_path_returns_404(self, api_session):
        """HTTP server responds with 404 to path outside /admin."""
        r = api_session.head(f"{FTL_URL}/undefined", timeout=5)
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Config validation via API (type-based)
# ---------------------------------------------------------------------------

class TestConfigValidationAPIType:

    def test_blockESNI_rejects_float(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"blockESNI": 15.5}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item is invalid",
            "hint": "dns.blockESNI: not of type bool",
        }, json.dumps(data, indent=2)

    def test_piholePTR_rejects_invalid_option(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"piholePTR": "something_else"}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item is invalid",
            "hint": "dns.piholePTR: invalid option",
        }, json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Config validation via API (validator-based)
# ---------------------------------------------------------------------------

class TestConfigValidationAPIValidator:

    def test_files_pcap_rejects_invalid_path(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"files": {"pcap": "%gh4b"}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item validation failed",
            "hint": 'files.pcap: not a valid file path ("%gh4b")',
        }, json.dumps(data, indent=2)

    def test_cnameRecords_rejects_too_few_elements(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"cnameRecords": ["a"]}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item validation failed",
            "hint": "dns.cnameRecords[0]: not a valid CNAME definition (too few elements)",
        }, json.dumps(data, indent=2)

    def test_cnameRecords_rejects_empty_string_position(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"cnameRecords": ["a,b,c", "a,b,c,,c"]}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item validation failed",
            "hint": "dns.cnameRecords[1]: contains an empty string at position 3",
        }, json.dumps(data, indent=2)

    def test_cnameRecords_rejects_non_string_element(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"cnameRecords": ["a,b,c", "a,b,c", 5]}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item is invalid",
            "hint": "dns.cnameRecords: array has invalid elements",
        }, json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Envvar-protected config: cannot change via API
# ---------------------------------------------------------------------------

class TestEnvvarProtectedConfig:

    def test_api_rejects_envvar_override(self, api_session):
        """API cannot change misc.nice when set via FTLCONF_misc_nice."""
        data = _j(api_session.patch(f"{FTL_URL}/api/config/misc/nice",
                                    json={"config": {"misc": {"nice": -12}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config items set via environment variables cannot be changed via the API",
            "hint": "misc.nice",
        }, json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Domain search
# ---------------------------------------------------------------------------

class TestDomainSearch:

    def test_nonexistent_domain(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/search/non.existent", timeout=5))
        search = data["search"]
        assert search["domains"] == []
        assert search["gravity"] == []
        assert search["results"] == {
            "domains": {"exact": 0, "regex": 0},
            "gravity": {"allow": 0, "block": 0},
            "total": 0,
        }, json.dumps(data, indent=2)
        assert search["parameters"] == {
            "N": 20,
            "partial": False,
            "domain": "non.existent",
            "debug": False,
        }, json.dumps(data, indent=2)

    def test_antigravity_domain(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/search/antigravity.ftl", timeout=5))
        search = data["search"]
        assert search["results"] == {
            "domains": {"exact": 0, "regex": 0},
            "gravity": {"allow": 2, "block": 1},
            "total": 3,
        }, json.dumps(data, indent=2)
        assert search["domains"] == []

        gravity = search["gravity"]
        assert len(gravity) == 3, json.dumps(gravity, indent=2)

        # Block list match
        g0 = gravity[0]
        assert g0["domain"] == "antigravity.ftl"
        assert g0["type"] == "block"
        assert g0["address"] == "https://pi-hole.net/block.txt"
        assert g0["comment"] == "Fake block-list"
        assert g0["enabled"] is True
        assert g0["id"] == 1
        assert g0["number"] == 2000
        assert g0["invalid_domains"] == 2
        assert g0["groups"] == [0, 2]

        # Allow list match (exact domain)
        g1 = gravity[1]
        assert g1["domain"] == "antigravity.ftl"
        assert g1["type"] == "allow"
        assert g1["address"] == "https://pi-hole.net/allow.txt"
        assert g1["comment"] == "Fake allow-list"
        assert g1["id"] == 2
        assert g1["groups"] == [0]

        # Allow list match (ABP-style antigravity entry)
        g2 = gravity[2]
        assert g2["domain"] == "@@||antigravity.ftl^"
        assert g2["type"] == "allow"
        assert g2["id"] == 2

    def test_punycode_normalization(self, api_session):
        """Internationalized domain names should be normalized to punycode."""
        data = _j(api_session.get(f"{FTL_URL}/api/search/\u00e4BC.com",
                                  params={"debug": "true"}, timeout=5))
        assert data["search"]["debug"]["punycode"] == "xn--bc-uia.com", \
            json.dumps(data, indent=2)
        assert data["search"]["results"]["total"] == 0


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

class TestHistory:

    def test_history_returns_24h(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/history", timeout=5))
        assert len(data["history"]) == 145, \
            f"Expected 145 history entries (24h in 10-min slots), got {len(data['history'])}"
        # Verify each slot has the expected structure
        slot = data["history"][0]
        for key in ("timestamp", "total", "cached", "blocked", "forwarded"):
            assert key in slot, f"Missing key '{key}' in history slot: {slot}"

    def test_history_clients_returns_24h(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/history/clients", timeout=5))
        assert len(data["history"]) == 145, \
            f"Expected 145 history entries, got {len(data['history'])}"
        assert "clients" in data, f"Missing 'clients' key:\n{json.dumps(data, indent=2)}"


# ---------------------------------------------------------------------------
# Lists
# ---------------------------------------------------------------------------

class TestLists:

    def test_block_lists_only(self, api_session):
        lists = _j(api_session.get(f"{FTL_URL}/api/lists?type=block", timeout=5))["lists"]
        assert len(lists) == 1, f"Expected 1 block list:\n{json.dumps(lists, indent=2)}"
        bl = lists[0]
        assert bl["type"] == "block"
        assert bl["address"] == "https://pi-hole.net/block.txt"
        assert bl["comment"] == "Fake block-list"
        assert bl["enabled"] is True
        assert bl["id"] == 1
        assert bl["number"] == 2000
        assert bl["invalid_domains"] == 2
        assert bl["abp_entries"] == 0
        assert bl["status"] == 1
        assert bl["groups"] == [0, 2]

    def test_allow_lists_only(self, api_session):
        lists = _j(api_session.get(f"{FTL_URL}/api/lists?type=allow", timeout=5))["lists"]
        assert len(lists) == 1, f"Expected 1 allow list:\n{json.dumps(lists, indent=2)}"
        al = lists[0]
        assert al["type"] == "allow"
        assert al["address"] == "https://pi-hole.net/allow.txt"
        assert al["comment"] == "Fake allow-list"
        assert al["enabled"] is True
        assert al["id"] == 2
        assert al["number"] == 2000
        assert al["invalid_domains"] == 2
        assert al["abp_entries"] == 0
        assert al["status"] == 1
        assert al["groups"] == [0]

    def test_all_lists_includes_both_types(self, api_session):
        lists = _j(api_session.get(f"{FTL_URL}/api/lists", timeout=5))["lists"]
        assert len(lists) == 2, f"Expected 2 lists:\n{json.dumps(lists, indent=2)}"
        types = {lst["type"] for lst in lists}
        assert types == {"block", "allow"}


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

class TestQueries:

    def test_no_unknown_reply(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries?reply=UNKNOWN", timeout=5))
        assert data["queries"] == []
        assert data["recordsFiltered"] == 0, json.dumps(data, indent=2)

    def test_no_unknown_status(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries?status=UNKNOWN", timeout=5))
        assert data["queries"] == []
        assert data["recordsFiltered"] == 0, json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Lua server pages
# ---------------------------------------------------------------------------

class TestLuaServerPages:

    def test_lua_page_outside_admin_not_served_by_default(self, api_session):
        """Lua server page outside /admin is not served when serve_all is off."""
        set_config(api_session, "webserver.serve_all", False)
        r = api_session.head(f"{FTL_URL}/broken_lua", timeout=5)
        assert r.status_code == 404

    def test_lua_page_generates_proper_backtrace(self, api_session):
        """Lua server page generates proper backtrace on error."""
        set_config(api_session, "webserver.serve_all", True)
        r = api_session.get(f"{FTL_URL}/broken_lua", timeout=5)
        lines = r.text.splitlines()
        assert lines[0] == "Hello, world 1!", f"Unexpected response:\n{r.text}"
        assert lines[1] == "Hello, world 2!"
        assert 'Cannot include [/var/www/html/does_not_exist.lp]: not found' in lines[2]
        assert lines[3] == "stack traceback:"

    def test_lua_page_outside_webhome_served_without_login(self, api_session):
        """After serve_all is enabled, Lua pages are served without login."""
        r = api_session.get(f"{FTL_URL}/broken_lua", timeout=5)
        lines = r.text.splitlines()
        assert lines[0] == "Hello, world 1!", f"Unexpected response:\n{r.text}"
