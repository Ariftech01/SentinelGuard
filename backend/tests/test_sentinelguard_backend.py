"""SentinelGuard backend regression suite.
Tests: secure/chat pipeline (MASK/BLOCK/ALLOW multi-provider), events, dashboard,
policies CRUD, audit logs, settings.
"""
import os
import uuid
import time
import pytest
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") if os.environ.get("REACT_APP_BACKEND_URL") \
    else "https://runtime-protection.preview.emergentagent.com"
API = f"{BASE_URL}/api"
AUTH_HEADERS = {"Authorization": "Bearer test_session_sentinelguard_qa"}


@pytest.fixture(scope="session")
def s():
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json", **AUTH_HEADERS})
    return session


# --------- secure/chat pipeline ---------
class TestSecureChat:
    def test_email_masked(self, s):
        r = s.post(f"{API}/v1/secure/chat", json={
            "message": "contact me at jane@acme.com and say hello",
            "provider": "Gemini",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["decision"]["action"] == "MASKED"
        assert d["decision"]["policy"] == "PII standard protection"
        assert "[EMAIL_MASKED]" in (d["masked_message"] or "")
        assert d["response"], f"AI response empty: {d}"
        detected = d["decision"]["detected"]
        assert any(x["type"] == "email" for x in detected)
        assert any(x["original"] == "jane@acme.com" and x["masked"] == "[EMAIL_MASKED]" for x in detected)

    def test_api_key_blocked(self, s):
        r = s.post(f"{API}/v1/secure/chat", json={
            "message": "my key is sk-test_abcdefghij1234567890",
            "provider": "OpenAI",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["decision"]["action"] == "BLOCKED"
        assert d["decision"]["policy"] == "Secrets critical block"
        assert d["response"] is None

    def test_clean_allowed_claude(self, s):
        r = s.post(f"{API}/v1/secure/chat", json={
            "message": "Say hi in one short sentence.",
            "provider": "Claude",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["decision"]["action"] == "ALLOWED"
        assert d["decision"]["score"] == 0
        assert d["response"]

    def test_clean_allowed_openai(self, s):
        r = s.post(f"{API}/v1/secure/chat", json={
            "message": "What is 2+2? One word.",
            "provider": "OpenAI",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["decision"]["action"] == "ALLOWED"
        assert d["response"]

    def test_credit_card_blocked(self, s):
        r = s.post(f"{API}/v1/secure/chat", json={
            "message": "my card is 4111 1111 1111 1111 please charge",
            "provider": "Gemini",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=60)
        d = r.json()
        assert d["decision"]["action"] == "BLOCKED"
        assert d["decision"]["policy"] == "PCI data block"

    def test_phone_masked(self, s):
        r = s.post(f"{API}/v1/secure/chat", json={
            "message": "call me at +1 415 555 7788",
            "provider": "Gemini",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=60)
        d = r.json()
        assert d["decision"]["action"] == "MASKED"
        assert "[PHONE_MASKED]" in d["masked_message"]

    def test_combo_higher_risk(self, s):
        r_single = s.post(f"{API}/v1/secure/chat", json={
            "message": "my email is a@b.co",
            "provider": "Gemini",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=60).json()
        r_combo = s.post(f"{API}/v1/secure/chat", json={
            "message": "my email is a@b.co and password is Secret123",
            "provider": "Gemini",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=60).json()
        assert r_combo["decision"]["score"] > r_single["decision"]["score"]

    def test_local_ai_error(self, s):
        r = s.post(f"{API}/v1/secure/chat", json={
            "message": "Say hi",
            "provider": "Local AI",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["error"] and "Local AI endpoint is not configured" in d["error"]

    def test_multi_turn_same_session(self, s):
        sid = f"pytest_multi_{uuid.uuid4().hex[:6]}"
        for msg in ["Remember the word 'purple'.", "What word did I ask you to remember?"]:
            r = s.post(f"{API}/v1/secure/chat", json={
                "message": msg, "provider": "Gemini", "session_id": sid,
            }, timeout=60)
            assert r.status_code == 200

    def test_empty_message_400(self, s):
        r = s.post(f"{API}/v1/secure/chat", json={
            "message": "  ", "provider": "Gemini", "session_id": "x",
        }, timeout=15)
        assert r.status_code == 400


# --------- events ---------
class TestEvents:
    def test_events_no_raw_pii(self, s):
        r = s.get(f"{API}/v1/events?limit=100", timeout=15)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) > 0
        text = str(items)
        # No raw email or API keys should be present
        assert "jane@acme.com" not in text
        assert "sk-test_abcdefghij1234567890" not in text
        # Only labels
        found_labels = any("Email address" in i.get("data", "") for i in items)
        assert found_labels

    def test_events_search(self, s):
        r = s.get(f"{API}/v1/events?search=BLOCKED", timeout=15)
        assert r.status_code == 200


# --------- dashboard ---------
class TestDashboard:
    def test_stats_shape(self, s):
        r = s.get(f"{API}/v1/dashboard/stats", timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert "totals" in d
        for k in ("requests", "threats", "blocked", "sensitive"):
            assert k in d["totals"]
            assert f"{k}_change" in d["totals"]
        assert len(d["trend"]) == 8
        assert len(d["risk_distribution"]) == 4
        providers = {p["name"]: p["status"] for p in d["providers"]}
        assert providers["Gemini"] == "connected"
        assert providers["OpenAI"] == "connected"
        assert providers["Claude"] == "connected"
        assert providers["Local AI"] == "not-configured"


# --------- policies CRUD ---------
class TestPolicies:
    def test_list_defaults(self, s):
        r = s.get(f"{API}/v1/policies", timeout=15)
        items = r.json()["items"]
        names = {p["name"] for p in items}
        assert {"PII standard protection", "PCI data block", "Secrets critical block", "Identity document masking"} <= names

    def test_policy_crud_and_effect(self, s):
        # Create BLOCK policy for email at Low risk
        cr = s.post(f"{API}/v1/policies", json={
            "name": "TEST_email_block", "when": ["email"], "risk": "Low", "then": "BLOCK", "enabled": True,
        }, timeout=15)
        assert cr.status_code == 200, cr.text
        pid = cr.json()["id"]
        try:
            # Verify secure/chat blocks email now
            r = s.post(f"{API}/v1/secure/chat", json={
                "message": "email me at x@y.co",
                "provider": "Gemini",
                "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
            }, timeout=60).json()
            assert r["decision"]["action"] == "BLOCKED"
            assert r["decision"]["policy"] == "TEST_email_block"

            # Toggle disabled
            up = s.put(f"{API}/v1/policies/{pid}", json={"enabled": False}, timeout=15)
            assert up.status_code == 200
            assert up.json()["enabled"] is False
        finally:
            dr = s.delete(f"{API}/v1/policies/{pid}", timeout=15)
            assert dr.status_code == 200

        # After delete, email should be MASKED again
        r2 = s.post(f"{API}/v1/secure/chat", json={
            "message": "email me at x@y.co",
            "provider": "Gemini",
            "session_id": f"pytest_{uuid.uuid4().hex[:6]}",
        }, timeout=60).json()
        assert r2["decision"]["action"] == "MASKED"
        assert r2["decision"]["policy"] == "PII standard protection"

    def test_delete_missing_404(self, s):
        r = s.delete(f"{API}/v1/policies/pol_doesnotexist", timeout=15)
        assert r.status_code == 404


# --------- audit logs ---------
class TestAuditLogs:
    def test_pagination_and_filter(self, s):
        r = s.get(f"{API}/v1/audit-logs?page=1&page_size=5", timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert d["page"] == 1 and d["page_size"] == 5
        assert isinstance(d["total"], int)
        assert len(d["items"]) <= 5

        rb = s.get(f"{API}/v1/audit-logs?action=BLOCKED&page=1&page_size=10", timeout=15).json()
        for item in rb["items"]:
            assert item["action"] == "BLOCKED"

    def test_search(self, s):
        r = s.get(f"{API}/v1/audit-logs?search=Gemini", timeout=15).json()
        for item in r["items"]:
            assert "gemini" in str(item).lower()


# --------- settings ---------
class TestSettings:
    def test_get_and_persist(self, s):
        original = s.get(f"{API}/v1/settings", timeout=15).json()
        assert "block_critical" in original and "theme" in original
        new_theme = "Dark" if original.get("theme") != "Dark" else "Light"
        upd = s.put(f"{API}/v1/settings", json={"theme": new_theme, "daily_digest": not original.get("daily_digest", False)}, timeout=15).json()
        assert upd["theme"] == new_theme
        # Verify persistence
        again = s.get(f"{API}/v1/settings", timeout=15).json()
        assert again["theme"] == new_theme
        # Restore
        s.put(f"{API}/v1/settings", json={"theme": original.get("theme", "Light"), "daily_digest": original.get("daily_digest", False)}, timeout=15)
