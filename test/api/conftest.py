"""
Shared pytest fixtures for FTL API integration tests.
"""

import sys
import os

import pytest
import requests

# Add test/api to the path so libs/ can be imported
sys.path.insert(0, os.path.dirname(__file__))

FTL_URL = "http://127.0.0.1"


@pytest.fixture(scope="session")
def ftl_url():
    """Base URL for the FTL API."""
    return FTL_URL


@pytest.fixture(scope="session")
def api_session():
    """Shared authenticated requests.Session for the entire test run.

    If no password is set, the session works without authentication.
    If a password is set, logs in with "ABC" and stores the SID in
    the session headers so all subsequent requests are authenticated.
    """
    session = requests.Session()
    session.headers["Accept"] = "application/json"
    try:
        r = session.get(f"{FTL_URL}/api/auth", timeout=5)
        if r.status_code not in (200, 401):
            r.raise_for_status()
    except requests.ConnectionError:
        pytest.skip("FTL is not running at " + FTL_URL)

    data = r.json()
    if not data.get("session", {}).get("valid"):
        # Password is set — login with "ABC"
        r = session.post(f"{FTL_URL}/api/auth",
                         json={"password": "ABC"}, timeout=10)
        sid = r.json().get("session", {}).get("sid")
        if sid:
            session.headers["X-FTL-SID"] = sid
    return session


@pytest.fixture(scope="session")
def openapi():
    """Parsed OpenAPI specifications (session-scoped, parsed once)."""
    from libs.openAPI import openApi
    specs = openApi(base_path="src/api/docs/content/specs/", api_root="/api")
    assert specs.parse("main.yaml"), "Failed to parse OpenAPI specs"
    return specs


@pytest.fixture(scope="session")
def ftl():
    """FTLAPI client with endpoints loaded (session-scoped).

    Authenticates with password "ABC" if a password is set, otherwise
    connects without authentication.
    """
    from libs.FTLAPI import FTLAPI
    # Check if authentication is required
    r = requests.get(f"{FTL_URL}/api/auth", timeout=5)
    data = r.json()
    if data.get("session", {}).get("valid"):
        client = FTLAPI(FTL_URL)
    else:
        client = FTLAPI(FTL_URL, "ABC")
    client.get_endpoints()
    return client
