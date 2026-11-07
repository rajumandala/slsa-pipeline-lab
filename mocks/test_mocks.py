import sqlite3

import pytest
from fastapi.testclient import TestClient

from mocks import main

CI, DEV, CR = "ci-test-token", "dev-test-token", "cr-test-token"
GOOD = "sha256:" + "a" * 64
FORGED = "sha256:" + "f" * 64
CLEAN = {"fixable": {"critical": 0, "secrets": 0}}


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "mock.db"
    monkeypatch.setenv("MOCK_DB", str(db))
    monkeypatch.setenv("MOCK_SDE_CI_TOKEN", CI)
    monkeypatch.setenv("MOCK_SDE_DEV_TOKEN", DEV)
    monkeypatch.setenv("MOCK_CR_TOKEN", CR)
    # Only GOOD has a verified, clean scan attestation; anything else fails verification.
    monkeypatch.setattr(main, "verifier", lambda digest, kind: CLEAN if digest == GOOD else None)
    main.db().close()  # create schema + seed countermeasures
    c = TestClient(main.app)
    c.db = db
    return c


def status(c, cid):
    return next(r for r in c.get("/sde/countermeasures").json() if r["id"] == cid)["status"]


def test_developer_marking_t_sast_complete_is_blocked(client):
    r = client.put("/sde/countermeasures/T-SAST", headers={"Authorization": f"Bearer {DEV}"},
                   json={"status": "Complete", "note": "trust me", "digest": GOOD})
    assert r.status_code == 403
    assert status(client, "T-SAST") == "Incomplete"
    assert any("developer tried to set T-SAST=Complete" in a["msg"] for a in client.get("/sde/alerts").json())


def test_developer_direct_db_edit_is_reverted_by_reconcile(client):
    # Developer bypasses the API and edits the backing store directly.
    con = sqlite3.connect(client.db)
    con.execute("UPDATE cm SET status='Complete', changed_by='developer', digest=NULL WHERE id='T-SAST'")
    con.commit()
    assert status(client, "T-SAST") == "Complete"

    r = client.post("/sde/reconcile").json()
    assert r["reverted"] == [{"id": "T-SAST", "from": "Complete", "to": "Incomplete"}]
    assert status(client, "T-SAST") == "Incomplete"
    assert any(a["msg"].startswith("ALERT T-SAST") for a in client.get("/sde/alerts").json())


def test_ci_update_with_verified_attestation_survives_reconcile(client):
    r = client.put("/sde/countermeasures/T-SAST", headers={"Authorization": f"Bearer {CI}"},
                   json={"status": "Complete", "note": "run https://x digest " + GOOD, "digest": GOOD})
    assert r.status_code == 200 and r.json()["verified"] is True
    assert client.post("/sde/reconcile").json()["reverted"] == []
    assert status(client, "T-SAST") == "Complete"


def test_ci_token_with_forged_digest_is_reverted(client):
    # Even a leaked CI token cannot make a status stick without a real attestation.
    r = client.put("/sde/countermeasures/T-SCA", headers={"Authorization": f"Bearer {CI}"},
                   json={"status": "Complete", "note": "forged", "digest": FORGED})
    assert r.json()["verified"] is False
    assert client.post("/sde/reconcile").json()["reverted"][0]["id"] == "T-SCA"
    assert status(client, "T-SCA") == "Incomplete"


def test_unknown_token_is_401(client):
    r = client.put("/sde/countermeasures/T-SAST", headers={"Authorization": "Bearer nope"},
                   json={"status": "Complete", "note": "", "digest": GOOD})
    assert r.status_code == 401


def test_change_request_flow(client):
    h = {"Authorization": f"Bearer {CR}"}
    body = {"digest": GOOD, "decision": "manual", "reasons": ["sensitive path changed: auth/x.py"],
            "run_url": "https://x", "evidence": {"digest": GOOD}}
    created = client.post("/snow/change", headers=h, json=body).json()
    assert created["state"] == "pending_approval"
    assert client.get(f"/snow/change/{created['id']}").json()["decision"] == "manual"
    upd = client.patch(f"/snow/change/{created['id']}", headers=h,
                       json={"state": "approved", "approver": "rajumandala", "run_url": "https://x"})
    assert upd.json()["state"] == "approved"
    # developer token cannot open changes
    assert client.post("/snow/change", headers={"Authorization": f"Bearer {DEV}"}, json=body).status_code == 403
