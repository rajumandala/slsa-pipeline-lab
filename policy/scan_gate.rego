# Build-time gate: fail the build on findings the policy forbids.
# input = {"sast": <predicate>, "sca": <predicate>, "secrets": <predicate>}
package scan_gate

import rego.v1

t := data.thresholds

counts(p) := p.counts if t.count_unfixed
counts(p) := p.fixable if not t.count_unfixed

deny contains msg if {
	some kind, p in input
	n := counts(p).critical
	n > t.build_max.critical
	msg := sprintf("%s: %d critical finding(s) (max %d)", [kind, n, t.build_max.critical])
}

deny contains msg if {
	n := input.secrets.counts.secrets
	n > t.build_max.secrets
	msg := sprintf("secrets: %d secret(s) detected (max %d)", [n, t.build_max.secrets])
}

deny contains msg if {
	some kind in t.required_scans
	not input[kind]
	msg := sprintf("%s: scan result missing", [kind])
}
