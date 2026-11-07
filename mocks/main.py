"""Mock ServiceNow (/snow) + mock SD Elements (/sde) in one process, so one tunnel URL serves both.

Tokens come from env (never committed):
  MOCK_CR_TOKEN       - CI token for ServiceNow
  MOCK_SDE_CI_TOKEN   - CI token for SD Elements (the only token allowed to change countermeasures)
  MOCK_SDE_DEV_TOKEN  - a "developer" token: can read, gets 403 on writes
Run: uvicorn mocks.main:app --port 8000
"""
import base64, json, os, sqlite3, subprocess, uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

REPO = os.environ.get("LAB_REPO", "rajumandala/slsa-pipeline-lab")
IMAGE = f"ghcr.io/{REPO}"
SCAN_IDENTITY = f"https://github.com/{REPO}/.github/workflows/build.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
PRED = "https://slsa-pipeline-lab/attestations/{}/v1"
CM = {"T-SAST": "sast", "T-SCA": "sca", "T-SECRETS": "secrets"}  # countermeasure -> scan kind

app = FastAPI(title="supply-chain lab mocks")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def db():
    con = sqlite3.connect(os.environ.get("MOCK_DB", "mocks/mock.db"))
    con.row_factory = sqlite3.Row
    con.executescript("""
      CREATE TABLE IF NOT EXISTS changes(id TEXT PRIMARY KEY, created TEXT, state TEXT, body TEXT);
      CREATE TABLE IF NOT EXISTS cm(id TEXT PRIMARY KEY, status TEXT, note TEXT, digest TEXT, changed_by TEXT, updated TEXT,
                                    verified_status TEXT);  -- last status backed by a verified attestation
      CREATE TABLE IF NOT EXISTS log(ts TEXT, kind TEXT, msg TEXT);
    """)
    for cid in CM:
        con.execute("INSERT OR IGNORE INTO cm VALUES(?, 'Incomplete', 'initial', NULL, 'system', ?, 'Incomplete')", (cid, now()))
    con.commit()
    return con


def bearer(authorization: str = Header(default="")) -> str:
    tok = authorization.removeprefix("Bearer ").strip()
    roles = {os.environ.get("MOCK_CR_TOKEN"): "cr-ci", os.environ.get("MOCK_SDE_CI_TOKEN"): "sde-ci",
             os.environ.get("MOCK_SDE_DEV_TOKEN"): "developer"}
    roles.pop(None, None)
    if tok not in roles:
        raise HTTPException(401, "unknown token")
    return roles[tok]


# ------------------------------------------------------------------ ServiceNow
class ChangeIn(BaseModel):
    digest: str
    decision: str  # auto_approve | manual | reject
    reasons: list[str]
    run_url: str
    evidence: dict


class ChangeUpdate(BaseModel):
    state: str  # approved | rejected
    approver: str
    run_url: str


@app.post("/snow/change", status_code=201)
def create_change(c: ChangeIn, role: str = Depends(bearer)):
    if role != "cr-ci":
        raise HTTPException(403, "only CI may open change requests")
    state = {"auto_approve": "approved", "manual": "pending_approval", "reject": "rejected"}.get(c.decision)
    if not state:
        raise HTTPException(422, "bad decision")
    cid = "CHG" + uuid.uuid4().hex[:8].upper()
    con = db()
    con.execute("INSERT INTO changes VALUES(?,?,?,?)", (cid, now(), state, c.model_dump_json()))
    con.commit()
    return {"id": cid, "state": state}


@app.patch("/snow/change/{cid}")
def update_change(cid: str, u: ChangeUpdate, role: str = Depends(bearer)):
    if role != "cr-ci":
        raise HTTPException(403, "only CI may update change requests")
    con = db()
    row = con.execute("SELECT * FROM changes WHERE id=?", (cid,)).fetchone()
    if not row:
        raise HTTPException(404)
    if row["state"] != "pending_approval":
        raise HTTPException(409, f"change is {row['state']}")
    body = json.loads(row["body"]) | {"approval": u.model_dump()}
    con.execute("UPDATE changes SET state=?, body=? WHERE id=?", (u.state, json.dumps(body), cid))
    con.commit()
    return {"id": cid, "state": u.state}


@app.get("/snow/change/{cid}")
def get_change(cid: str):
    row = db().execute("SELECT * FROM changes WHERE id=?", (cid,)).fetchone()
    if not row:
        raise HTTPException(404)
    return {"id": row["id"], "created": row["created"], "state": row["state"], **json.loads(row["body"])}


# ------------------------------------------------------------------ SD Elements
class CMUpdate(BaseModel):
    status: str  # Complete | Incomplete
    note: str
    digest: str  # image digest whose scan attestation justifies this status


def cosign_verify(digest: str, kind: str) -> dict | None:
    """Return the verified predicate of the scan attestation, or None. Replaced in unit tests."""
    try:
        out = subprocess.run(
            ["cosign", "verify-attestation", "--type", PRED.format(kind),
             "--certificate-identity", SCAN_IDENTITY, "--certificate-oidc-issuer", ISSUER,
             f"{IMAGE}@{digest}"], capture_output=True, text=True, timeout=120, check=True)
    except (subprocess.SubprocessError, OSError):
        return None
    # one line per attestation; take the newest matching statement
    for line in reversed(out.stdout.strip().splitlines()):
        stmt = json.loads(base64.b64decode(json.loads(line)["payload"]))
        if stmt.get("predicateType") == PRED.format(kind):
            return stmt["predicate"]
    return None


verifier = cosign_verify  # indirection so tests can swap it


def status_justified(status: str, pred: dict | None) -> bool:
    """A status is justified only by a verified attestation whose content agrees with it."""
    if pred is None:
        return False
    f = pred.get("fixable", {})
    passed = f.get("critical", 0) == 0 and f.get("secrets", 0) == 0
    return (status == "Complete") == passed


def cm_row(con, cid):
    row = con.execute("SELECT * FROM cm WHERE id=?", (cid,)).fetchone()
    if not row:
        raise HTTPException(404, "unknown countermeasure")
    return dict(row)


@app.get("/sde/countermeasures")
def list_cm():
    return [dict(r) for r in db().execute("SELECT * FROM cm ORDER BY id")]


@app.put("/sde/countermeasures/{cid}")
def put_cm(cid: str, u: CMUpdate, role: str = Depends(bearer)):
    if role != "sde-ci":
        con = db()
        con.execute("INSERT INTO log VALUES(?,?,?)", (now(), "alert", f"{role} tried to set {cid}={u.status} via API: denied"))
        con.commit()
        raise HTTPException(403, "CI-owned countermeasure: only the CI token may change it")
    if u.status not in ("Complete", "Incomplete"):
        raise HTTPException(422, "status must be Complete or Incomplete")
    con = db()
    cm_row(con, cid)
    # CI is trusted to call us, but the status still has to match a verified attestation.
    verified = status_justified(u.status, verifier(u.digest, CM[cid]))
    con.execute("UPDATE cm SET status=?, note=?, digest=?, changed_by='ci', updated=?, verified_status=CASE WHEN ? THEN ? ELSE verified_status END WHERE id=?",
                (u.status, u.note, u.digest, now(), verified, u.status, cid))
    con.execute("INSERT INTO log VALUES(?,?,?)", (now(), "info", f"ci set {cid}={u.status} digest={u.digest} verified={verified}"))
    con.commit()
    return cm_row(con, cid) | {"verified": verified}


@app.post("/sde/reconcile")
def reconcile():
    """Revert any status that is not backed by a matching, verified scan attestation."""
    con = db()
    reverted = []
    for row in [dict(r) for r in con.execute("SELECT * FROM cm")]:
        pred = verifier(row["digest"], CM[row["id"]]) if row["digest"] else None
        if row["changed_by"] in ("system", "reconciler") and row["status"] == row["verified_status"]:
            continue  # initial or already-reconciled state
        if row["changed_by"] == "ci" and status_justified(row["status"], pred):
            continue
        msg = (f"ALERT {row['id']}: status {row['status']} (changed_by={row['changed_by']}, digest={row['digest']}) "
               f"has no matching verified attestation; reverting to {row['verified_status']}")
        con.execute("UPDATE cm SET status=?, note=?, changed_by='reconciler', updated=? WHERE id=?",
                    (row["verified_status"], "reverted by reconciler", now(), row["id"]))
        con.execute("INSERT INTO log VALUES(?,?,?)", (now(), "alert", msg))
        reverted.append({"id": row["id"], "from": row["status"], "to": row["verified_status"]})
    con.commit()
    return {"reverted": reverted}


@app.get("/sde/alerts")
def alerts():
    return [dict(r) for r in db().execute("SELECT * FROM log WHERE kind='alert' ORDER BY ts")]


@app.get("/healthz")
def healthz():
    return {"ok": True}
