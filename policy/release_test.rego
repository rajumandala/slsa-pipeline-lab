package release_test

import rego.v1

import data.release

z := {"critical": 0, "high": 0, "medium": 0, "low": 0, "secrets": 0}

scan(kind) := {"kind": kind, "commit": "abc", "counts": z, "fixable": z, "changed_paths": ["app/app.py"]}

good := {
	"digest": "sha256:1",
	"provenance": {
		"verified": true,
		"builder_id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0",
		"source_repo": "github.com/rajumandala/slsa-pipeline-lab",
		"commit": "abc",
	},
	"scans": {"sast": scan("sast"), "sca": scan("sca"), "secrets": scan("secrets")},
}

with_scan(kind, patch) := object.union(good, {"scans": {kind: object.union(scan(kind), patch)}})

is(d) if release.decision.decision == d

# ---- auto_approve ----
test_clean_is_auto_approve if is("auto_approve") with input as good

test_unfixed_high_alone_is_auto_approve if {
	is("auto_approve") with input as with_scan("sca", {"counts": object.union(z, {"high": 49})})
}

# ---- reject ----
test_missing_provenance_rejects if is("reject") with input as object.remove(good, ["provenance"])

test_invalid_provenance_rejects if {
	is("reject") with input as object.union(good, {"provenance": {"verified": false}})
}

test_builder_mismatch_rejects if {
	is("reject") with input as object.union(good, {"provenance": {"builder_id": "https://github.com/evil/gen/.github/workflows/x.yml@refs/tags/v1"}})
}

test_builder_branch_ref_rejects if {
	is("reject") with input as object.union(good, {"provenance": {"builder_id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/heads/main"}})
}

test_repo_mismatch_rejects if {
	is("reject") with input as object.union(good, {"provenance": {"source_repo": "github.com/someone/fork"}})
}

test_missing_scan_rejects if {
	inp := object.union(object.remove(good, ["scans"]), {"scans": {"sast": scan("sast"), "sca": scan("sca")}})
	is("reject") with input as inp
	release.reject["secrets: verified scan attestation missing"] with input as inp
}

test_scan_for_other_commit_rejects if is("reject") with input as with_scan("sast", {"commit": "def"})

test_critical_rejects if {
	c := object.union(z, {"critical": 1})
	is("reject") with input as with_scan("sca", {"counts": c, "fixable": c})
}

test_secrets_reject if {
	s := object.union(z, {"secrets": 1})
	is("reject") with input as with_scan("secrets", {"counts": s, "fixable": s})
}

test_reject_beats_manual if {
	inp := object.union(with_scan("secrets", {"counts": object.union(z, {"secrets": 1})}), {"scans": {"sast": object.union(scan("sast"), {"changed_paths": ["auth/login.py"]})}})
	is("reject") with input as inp
}

# ---- manual ----
test_fixable_high_is_manual if {
	h := object.union(z, {"high": 1})
	is("manual") with input as with_scan("sca", {"counts": h, "fixable": h})
}

test_auth_path_is_manual if is("manual") with input as with_scan("sast", {"changed_paths": ["auth/login.py"]})

test_payments_path_is_manual if is("manual") with input as with_scan("sast", {"changed_paths": ["payments/x.py"]})

test_migrations_path_is_manual if {
	is("manual") with input as with_scan("sast", {"changed_paths": ["migrations/0001.sql"]})
	release.decision.reasons == ["sensitive path changed: migrations/0001.sql"] with input as with_scan("sast", {"changed_paths": ["migrations/0001.sql"]})
}

test_lookalike_path_is_not_manual if is("auto_approve") with input as with_scan("sast", {"changed_paths": ["app/auth_helper.py"]})
