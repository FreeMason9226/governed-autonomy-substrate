package policy

import rego.v1

dependency_manifest_names := {
	"Cargo.toml",
	"Cargo.lock",
	"package.json",
	"package-lock.json",
	"npm-shrinkwrap.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"go.mod",
	"go.sum",
	"pyproject.toml",
	"poetry.lock",
	"requirements-ci.txt",
}

infra_path_change if {
	some path in input.changed_files
	startswith(path, "helm/")
}

infra_path_change if {
	some path in input.changed_files
	startswith(path, "deploy/")
}

infra_path_change if {
	some path in input.changed_files
	startswith(path, "runtime/")
}

default infra_path_change := false

dependency_bump if {
	some path in input.changed_files
	parts := split(path, "/")
	filename := parts[count(parts) - 1]
	filename in dependency_manifest_names
}

default dependency_bump := false

risk_score := score if {
	score := (5 * bool_to_number(infra_path_change)) + (3 * bool_to_number(dependency_bump))
}

bool_to_number(value) := 1 if value
bool_to_number(value) := 0 if not value

rules_triggered := ["infra-path-change", "dependency-bump"] if {
	infra_path_change
	dependency_bump
}

rules_triggered := ["infra-path-change"] if {
	infra_path_change
	not dependency_bump
}

rules_triggered := ["dependency-bump"] if {
	dependency_bump
	not infra_path_change
}

rules_triggered := [] if {
	not infra_path_change
	not dependency_bump
}

rationale := "Infrastructure paths and dependency files changed." if {
	infra_path_change
	dependency_bump
}

rationale := "High-risk infrastructure paths changed." if {
	infra_path_change
	not dependency_bump
}

rationale := "Dependency manifests or lockfiles changed." if {
	dependency_bump
	not infra_path_change
}

rationale := "No high-risk infrastructure or dependency files changed." if {
	not infra_path_change
	not dependency_bump
}

result := {
	"risk_score": risk_score,
	"rules_triggered": rules_triggered,
	"rationale": rationale,
}
