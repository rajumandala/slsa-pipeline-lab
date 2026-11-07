#!/usr/bin/env python3
"""Build the OPA input (evidence bundle) from files written by scripts/verify.sh.

Only payloads that passed signature + identity verification exist in the evidence dir,
so anything absent here is treated as missing by policy/release.rego.
usage: bundle.py <evidence-dir> <digest> > evidence.json
"""
import base64, json, os, sys

PRED = "https://slsa-pipeline-lab/attestations/{}/v1"


def provenance(ev):
    path = os.path.join(ev, "provenance.json")
    if not os.path.exists(path):
        return {"verified": False} if os.path.exists(os.path.join(ev, "provenance.invalid.json")) else None
    stmt = json.load(open(path))
    p = stmt["predicate"]
    if "buildDefinition" in p:  # SLSA v1
        builder = p["runDetails"]["builder"]["id"]
        wf = p["buildDefinition"]["externalParameters"]["workflow"]
        repo, commit = wf["repository"], p["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"]
    else:  # SLSA v0.2 (generator_container_slsa3 v2.x)
        builder = p["builder"]["id"]
        src = p["invocation"]["configSource"]
        repo, commit = src["uri"].split("@")[0], src["digest"]["sha1"]
    return {"verified": True, "builder_id": builder, "source_repo": repo, "commit": commit,
            "predicate_type": stmt["predicateType"]}


def scan(ev, kind):
    path = os.path.join(ev, f"{kind}.dsse.jsonl")
    if not os.path.exists(path):
        return None
    preds = []
    for line in open(path):
        if line.strip():
            stmt = json.loads(base64.b64decode(json.loads(line)["payload"]))
            if stmt.get("predicateType") == PRED.format(kind):
                preds.append(stmt["predicate"])
    # re-runs can attach several; the most recent scan wins
    return max(preds, key=lambda p: p.get("scanned_at", "")) if preds else None


def main():
    ev, digest = sys.argv[1], sys.argv[2]
    out = {"digest": digest, "scans": {}}
    prov = provenance(ev)
    if prov is not None:
        out["provenance"] = prov
    for kind in ("sast", "sca", "secrets"):
        s = scan(ev, kind)
        if s is not None:
            out["scans"][kind] = s
    log = os.path.join(ev, "verify.log")
    out["verification_log"] = [l.rstrip() for l in open(log) if l.startswith(("PASS", "FAIL"))] if os.path.exists(log) else []
    json.dump(out, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
