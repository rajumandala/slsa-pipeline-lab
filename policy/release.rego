# Release decision. input = evidence bundle built ONLY from verified attestations (scripts/bundle.py):
# {
#   "digest": "sha256:...",
#   "provenance": {"verified": bool, "builder_id": str, "source_repo": str, "commit": str} | absent,
#   "scans": {"sast"|"sca"|"secrets": <verified predicate>}   (unverified ones are absent)
# }
package release

import rego.v1

t := data.thresholds

counts(p) := p.counts if t.count_unfixed
counts(p) := p.fixable if not t.count_unfixed

# ---------- reject ----------
reject contains "provenance: missing" if not input.provenance

reject contains "provenance: signature/verification failed" if {
	input.provenance
	not input.provenance.verified
}

reject contains msg if {
	b := input.provenance.builder_id
	not startswith(b, sprintf("%s@refs/tags/v", [t.builder_id]))
	msg := sprintf("provenance: untrusted builder %q", [b])
}

reject contains msg if {
	r := input.provenance.source_repo
	not r in {t.repo, sprintf("github.com/%s", [t.repo]), sprintf("git+https://github.com/%s", [t.repo])}
	msg := sprintf("provenance: source repo %q is not %q", [r, t.repo])
}

reject contains msg if {
	some kind in t.required_scans
	not input.scans[kind]
	msg := sprintf("%s: verified scan attestation missing", [kind])
}

reject contains msg if {
	some kind, p in input.scans
	p.commit != input.provenance.commit
	msg := sprintf("%s: scanned commit %s != built commit %s", [kind, p.commit, input.provenance.commit])
}

reject contains msg if {
	some kind, p in input.scans
	n := counts(p).critical
	n > 0
	msg := sprintf("%s: %d critical finding(s)", [kind, n])
}

reject contains msg if {
	n := input.scans.secrets.counts.secrets
	n > 0
	msg := sprintf("secrets: %d secret(s) found", [n])
}

# ---------- manual ----------
manual contains msg if {
	some kind, p in input.scans
	n := counts(p).high
	n > t.release_manual_if_high_over
	msg := sprintf("%s: %d high finding(s) need human review", [kind, n])
}

manual contains msg if {
	some path in changed_paths
	some prefix in t.sensitive_paths
	startswith(path, prefix)
	msg := sprintf("sensitive path changed: %s", [path])
}

changed_paths contains p if {
	some kind, s in input.scans
	some p in s.changed_paths
}

# ---------- decision ----------
default decision := {"decision": "auto_approve", "reasons": ["all controls passed"]}

decision := {"decision": "reject", "reasons": sort(reject)} if count(reject) > 0

decision := {"decision": "manual", "reasons": sort(manual)} if {
	count(reject) == 0
	count(manual) > 0
}
