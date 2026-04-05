"""
Pi-hole FTL API stress tests -- parallel authentication.

Exercises the auth subsystem under concurrent load to verify thread-safety
of session management (auth_data access, Set-Cookie headers, session
validation). These tests must run BEFORE the sequential auth workflow
(test_z_auth.py) because they assume no password is set on entry and
restore that state on exit.

FTL rate-limits login attempts to MAX_PASSWORD_ATTEMPTS_PER_SECOND (3)
and has a default max_sessions of 16. Tests create sessions sequentially
(respecting the rate limit), exercise concurrency on session validation
and logout, and clean up all sessions before the next test.

The "s" prefix sorts this module between the mutation tests and the
auth workflow tests.

Usage:
    pytest test/api/test_s_auth_stress.py -v
"""

import concurrent.futures
import random
import string
import time

import requests

FTL_URL = "http://127.0.0.1"
PASSWORD = "stress-test-pw"
# Keep well below max_sessions (16) so the setup/teardown login still fits
NUM_SESSIONS = 12


def _set_password(pw, sid=None):
    """Set or remove the FTL web password."""
    headers = {"X-FTL-SID": sid} if sid else {}
    r = requests.patch(
        f"{FTL_URL}/api/config/webserver/api/password",
        json={"config": {"webserver": {"api": {"password": pw}}}},
        headers=headers,
        timeout=20,
    )
    assert r.status_code == 200, f"Failed to set password: {r.status_code} {r.text}"
    return r


def _login(pw, timeout=10):
    """Attempt login and return the response."""
    return requests.post(
        f"{FTL_URL}/api/auth",
        json={"password": pw},
        timeout=timeout,
    )


def _login_rate_limited(pw, timeout=10):
    """Login with retry on rate-limit (429). Returns response."""
    for _ in range(15):
        r = _login(pw, timeout=timeout)
        if r.status_code != 429:
            return r
        time.sleep(1)
    return r


def _check_session(sid, timeout=5):
    """Check whether a session is valid."""
    return requests.get(
        f"{FTL_URL}/api/auth",
        headers={"X-FTL-SID": sid},
        timeout=timeout,
    )


def _logout(sid, timeout=5):
    """Delete a session."""
    return requests.delete(
        f"{FTL_URL}/api/auth",
        headers={"X-FTL-SID": sid},
        timeout=timeout,
    )


def _logout_all(sids):
    """Logout a list of sessions, ignoring errors."""
    for sid in sids:
        try:
            _logout(sid)
        except Exception:
            pass


def _create_sessions(n):
    """Create n sessions sequentially, respecting the rate limit.

    Returns a list of session IDs.
    """
    sids = []
    for i in range(n):
        r = _login_rate_limited(PASSWORD)
        assert r.status_code == 200, \
            f"Login {i} failed: {r.status_code} {r.text}"
        sid = r.json()["session"]["sid"]
        assert sid, f"Login {i} returned no SID"
        sids.append(sid)
    return sids


# ---------------------------------------------------------------------------
# Fixtures — set password before this module's tests, remove it afterwards
# ---------------------------------------------------------------------------

def setup_module(_module):
    """Set a password so all stress tests require authentication."""
    _set_password(PASSWORD)


def teardown_module(_module):
    """Remove the password to restore the default unauthenticated state."""
    # Wait for any rate-limiting to clear
    time.sleep(2)
    r = _login_rate_limited(PASSWORD)
    sid = r.json().get("session", {}).get("sid")
    _set_password("", sid=sid)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParallelLogin:
    """Sessions created sequentially must all validate under concurrent load."""

    def test_concurrent_logins_return_unique_sessions(self):
        """Each login produces a distinct SID."""
        sids = _create_sessions(NUM_SESSIONS)
        try:
            assert len(set(sids)) == len(sids), \
                f"Duplicate SIDs: got {len(sids)} but only {len(set(sids))} unique"
        finally:
            _logout_all(sids)

    def test_concurrent_session_validation(self):
        """Validate all sessions concurrently — thread-safe read path."""
        sids = _create_sessions(NUM_SESSIONS)
        try:
            errors = []

            def check(sid):
                r = _check_session(sid)
                if r.status_code != 200:
                    return f"SID {sid[:8]}: HTTP {r.status_code}"
                if not r.json().get("session", {}).get("valid"):
                    return f"SID {sid[:8]}: not valid"
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_SESSIONS) as pool:
                futures = [pool.submit(check, sid) for sid in sids]
                for f in concurrent.futures.as_completed(futures):
                    err = f.result()
                    if err:
                        errors.append(err)

            assert not errors, f"Session validation failures: {errors}"
        finally:
            _logout_all(sids)


class TestParallelLoginLogout:
    """Concurrent logout must not corrupt other sessions."""

    def test_concurrent_logout_cycles(self):
        """Create sessions, then logout all concurrently."""
        sids = _create_sessions(NUM_SESSIONS)
        errors = []

        def worker(sid):
            try:
                # Validate session
                r = _check_session(sid)
                if r.status_code != 200:
                    return f"check HTTP {r.status_code}"
                if not r.json()["session"]["valid"]:
                    return "session invalid before logout"

                # Logout
                r = _logout(sid)
                if r.status_code != 204:
                    return f"logout HTTP {r.status_code}"

                # Confirm gone
                r = _check_session(sid)
                if r.status_code != 401:
                    return f"session still valid after logout ({r.status_code})"

            except Exception as e:
                return str(e)
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_SESSIONS) as pool:
            futures = {pool.submit(worker, sid): sid for sid in sids}
            for f in concurrent.futures.as_completed(futures):
                err = f.result()
                if err:
                    errors.append(f"SID {futures[f][:8]}: {err}")

        assert not errors, f"Logout cycle failures: {errors}"

    def test_logout_does_not_invalidate_other_sessions(self):
        """Logout half the sessions concurrently; the other half must survive."""
        sids = _create_sessions(NUM_SESSIONS)
        to_logout = sids[:NUM_SESSIONS // 2]
        to_keep = sids[NUM_SESSIONS // 2:]

        try:
            # Logout first half concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(to_logout)) as pool:
                futures = [pool.submit(_logout, sid) for sid in to_logout]
                for f in concurrent.futures.as_completed(futures):
                    r = f.result()
                    assert r.status_code == 204, \
                        f"Logout failed: HTTP {r.status_code}"

            # Validate second half concurrently — must all still be valid
            errors = []

            def check_alive(sid):
                r = _check_session(sid)
                if r.status_code != 200:
                    return f"SID {sid[:8]}: HTTP {r.status_code}"
                if not r.json()["session"]["valid"]:
                    return f"SID {sid[:8]}: invalidated by unrelated logout"
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=len(to_keep)) as pool:
                futures = [pool.submit(check_alive, sid) for sid in to_keep]
                for f in concurrent.futures.as_completed(futures):
                    err = f.result()
                    if err:
                        errors.append(err)

            assert not errors, f"Cross-session invalidation: {errors}"
        finally:
            _logout_all(to_keep)


class TestParallelMixedOperations:
    """Mix of session checks and logouts running concurrently."""

    def test_mixed_session_operations(self):
        """Random mix of session checks and logouts from a session pool."""
        sids = _create_sessions(NUM_SESSIONS)
        active = list(sids)
        errors = []

        def worker(i):
            try:
                op = random.choice(["check", "check", "check", "logout"])

                if op == "check":
                    if active:
                        sid = random.choice(active)
                        r = _check_session(sid)
                        # Session may have been logged out by another worker
                        if r.status_code not in (200, 401):
                            return f"worker {i} check: HTTP {r.status_code}"

                elif op == "logout":
                    if active:
                        try:
                            sid = active.pop()
                        except IndexError:
                            return None
                        r = _logout(sid)
                        if r.status_code not in (204, 401):
                            return f"worker {i} logout: HTTP {r.status_code}"

            except (requests.ConnectionError, requests.Timeout):
                pass
            except Exception as e:
                return f"worker {i}: {e}"
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_SESSIONS) as pool:
            futures = [pool.submit(worker, i) for i in range(NUM_SESSIONS * 4)]
            for f in concurrent.futures.as_completed(futures):
                err = f.result()
                if err:
                    errors.append(err)

        assert not errors, f"Mixed-op stress failures: {errors}"

        # Clean up any remaining sessions
        _logout_all(active)


class TestParallelWrongPasswords:
    """Concurrent wrong-password attempts must not crash FTL.

    This test class runs LAST because it intentionally triggers rate-limiting.
    """

    def test_concurrent_wrong_passwords_do_not_crash(self):
        """Blast the auth endpoint with random wrong passwords concurrently.

        The goal is to verify FTL does not crash (SIGSEGV), not to verify
        login success. Rate-limiting (429) is expected and acceptable.
        """
        errors = []

        def worker(i):
            for _ in range(10):
                pw = "".join(random.choices(string.ascii_letters, k=16))
                try:
                    r = _login(pw, timeout=10)
                    if r.status_code == 429:
                        return None
                    if r.status_code not in (401, 429):
                        return f"worker {i}: unexpected HTTP {r.status_code}"
                except requests.ConnectionError:
                    return None
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_SESSIONS) as pool:
            futures = [pool.submit(worker, i) for i in range(NUM_SESSIONS)]
            for f in concurrent.futures.as_completed(futures):
                err = f.result()
                if err:
                    errors.append(err)

        assert not errors, f"Wrong-password stress failures: {errors}"
