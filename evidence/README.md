# Review Evidence Bundle

Run `python scripts/collect_evidence.py` from the repository root to generate focused
test output, independent anchoring verification output, and SHA-256 provenance records.
The generated logs are review artifacts and should be attached to the CI run and counsel
package together with the actual KMS/HSM audit export and externally published checkpoint
hash. This repository does not claim that an external pen test or model-weight publication
has already occurred.