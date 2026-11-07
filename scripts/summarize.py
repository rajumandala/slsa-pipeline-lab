#!/usr/bin/env python3
"""Turn raw scanner JSON into a small, signed-attestation predicate.

usage: summarize.py <sast|sca|secrets> <tool-version> <out.json> <raw.json> [raw.json ...]
env:   GIT_SHA, RUN_URL, CHANGED_PATHS_FILE (optional, newline separated)

The predicate records *counts*; whether those counts are acceptable is decided
by OPA (policy/scan_gate.rego at build time, policy/release.rego at release).
"""
import hashlib, json, os, sys
from datetime import datetime, timezone

SEV = {"CRITICAL": "critical", "HIGH": "high", "ERROR": "high",
       "MEDIUM": "medium", "WARNING": "medium", "LOW": "low", "INFO": "low", "UNKNOWN": "low"}
TOOLS = {"sast": "semgrep", "sca": "trivy", "secrets": "gitleaks"}


def zero():
    return {"critical": 0, "high": 0, "medium": 0, "low": 0}


def semgrep(doc, all_, fixable, findings):
    for r in doc.get("results", []):
        s = SEV.get(r["extra"].get("severity", "INFO").upper(), "low")
        all_[s] += 1
        fixable[s] += 1  # code findings are always actionable
        findings.append({"id": r["check_id"], "severity": s, "location": f'{r["path"]}:{r["start"]["line"]}'})


def trivy(doc, all_, fixable, findings, seen):
    for res in doc.get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            key = (v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion"))
            if key in seen:  # fs + image overlap (requirements.txt and site-packages)
                continue
            seen.add(key)
            s = SEV.get(v["Severity"], "low")
            all_[s] += 1
            if v.get("FixedVersion"):
                fixable[s] += 1
            if s in ("critical", "high"):
                findings.append({"id": v["VulnerabilityID"], "severity": s, "package": v["PkgName"],
                                 "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion") or None})


def main():
    kind, version, out, *raws = sys.argv[1:]
    all_, fixable, findings, seen, digests = zero(), zero(), [], set(), {}
    secrets = 0
    for path in raws:
        data = open(path, "rb").read()
        digests[os.path.basename(path)] = hashlib.sha256(data).hexdigest()
        doc = json.loads(data or b"null")
        if kind == "sast":
            semgrep(doc, all_, fixable, findings)
        elif kind == "sca":
            trivy(doc, all_, fixable, findings, seen)
        elif kind == "secrets":
            for f in doc or []:  # gitleaks: list of findings; never echo the secret itself
                secrets += 1
                findings.append({"id": f["RuleID"], "location": f'{f["File"]}:{f["StartLine"]}', "commit": f.get("Commit", "")})
        else:
            sys.exit(f"unknown kind {kind}")

    changed = []
    if os.environ.get("CHANGED_PATHS_FILE"):
        changed = [l.strip() for l in open(os.environ["CHANGED_PATHS_FILE"]) if l.strip()]

    pred = {
        "kind": kind,
        "tool": {"name": TOOLS[kind], "version": version},
        "commit": os.environ.get("GIT_SHA", "local"),
        "run_url": os.environ.get("RUN_URL", "local"),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": all_ if kind != "secrets" else {**zero(), "secrets": secrets},
        "fixable": fixable if kind != "secrets" else {**zero(), "secrets": secrets},
        "findings": findings[:50],
        "raw_sha256": digests,
        "changed_paths": changed,
    }
    json.dump(pred, open(out, "w"), indent=2)
    print(f"{kind}: counts={pred['counts']} fixable={pred['fixable']}")


if __name__ == "__main__":
    main()
