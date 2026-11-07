package scan_gate_test

import rego.v1

import data.scan_gate

z := {"critical": 0, "high": 0, "medium": 0, "low": 0, "secrets": 0}

clean := {"sast": {"counts": z, "fixable": z}, "sca": {"counts": z, "fixable": z}, "secrets": {"counts": z, "fixable": z}}

test_clean_passes if count(scan_gate.deny) == 0 with input as clean

test_high_does_not_fail_build if {
	h := object.union(z, {"high": 3})
	count(scan_gate.deny) == 0 with input as object.union(clean, {"sca": {"counts": h, "fixable": h}})
}

test_fixable_critical_fails if {
	c := object.union(z, {"critical": 1})
	count(scan_gate.deny) == 1 with input as object.union(clean, {"sca": {"counts": c, "fixable": c}})
}

test_unfixed_critical_ignored_by_policy if {
	c := object.union(z, {"critical": 1})
	count(scan_gate.deny) == 0 with input as object.union(clean, {"sca": {"counts": c, "fixable": z}})
}

test_secret_fails if {
	s := object.union(z, {"secrets": 1})
	scan_gate.deny["secrets: 1 secret(s) detected (max 0)"] with input as object.union(clean, {"secrets": {"counts": s, "fixable": s}})
}

test_missing_scan_fails if {
	scan_gate.deny["sast: scan result missing"] with input as object.remove(clean, ["sast"])
}
