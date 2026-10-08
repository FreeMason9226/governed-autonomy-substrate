package policy

import rego.v1

test_infra_path_change_flags_helm_deploy_and_runtime if {
	data.policy.infra_path_change with input as {"changed_files": ["helm/values.yaml"]}
	data.policy.infra_path_change with input as {"changed_files": ["deploy/helm/values.yaml"]}
	data.policy.infra_path_change with input as {"changed_files": ["runtime/worker.py"]}
}

test_dependency_bump_flags_manifests if {
	data.policy.dependency_bump with input as {"changed_files": ["Cargo.toml"]}
	data.policy.dependency_bump with input as {"changed_files": ["web/package.json"]}
	data.policy.dependency_bump with input as {"changed_files": ["service/go.mod"]}
	data.policy.dependency_bump with input as {"changed_files": ["pyproject.toml"]}
	data.policy.dependency_bump with input as {"changed_files": ["poetry.lock"]}
	data.policy.dependency_bump with input as {"changed_files": ["requirements-ci.txt"]}
}

test_risk_score_for_no_triggered_rules if {
	data.policy.risk_score == 0 with input as {"changed_files": ["README.md"]}
	data.policy.rules_triggered == [] with input as {"changed_files": ["README.md"]}
}

test_risk_score_for_each_category if {
	data.policy.risk_score == 5 with input as {"changed_files": ["runtime/app.py"]}
	data.policy.risk_score == 3 with input as {"changed_files": ["Cargo.lock"]}
}

test_risk_score_combines_categories if {
	data.policy.risk_score == 8 with input as {"changed_files": ["helm/values.yaml", "package.json"]}
	data.policy.rules_triggered == ["infra-path-change", "dependency-bump"] with input as {"changed_files": ["helm/values.yaml", "package.json"]}
}
