# RFC-NNNN: [Short Title]

**Status:** Draft | Under Review | Accepted | Rejected  
**Author(s):**  
**Created:** YYYY-MM-DD  
**Updated:** YYYY-MM-DD  
**Protocol Version Impact:** None | Patch | Minor | Major

---

## Summary

One paragraph explaining what this RFC proposes and why.

---

## Motivation

What problem does this solve? What is the current behavior and why is it
insufficient? Include concrete examples of the issue this addresses.

---

## Proposed Change

Describe the change precisely. For wire format changes, include before/after
diffs of the relevant SPEC.md sections.

### SPEC.md Changes

```diff
- old field semantics
+ new field semantics
```

### Behavior Changes

Describe any changes to invariants, error codes, or conformance requirements.

---

## Backward Compatibility

- **Breaking:** Does this require a protocol version bump? (yes/no)
- **Migration path:** How do existing implementations update?
- **Graceful degradation:** Can old and new implementations interoperate
  during a transition?

---

## Conformance Test Impact

List test vectors that must be added, modified, or removed in
`tests/conformance/vectors/`.

| Vector file | Change |
|---|---|
| `gaa_basic.json` | Add field `X` to expected output |

---

## Alternatives Considered

What other approaches were evaluated? Why were they rejected?

---

## Open Questions

List any unresolved design questions for reviewers to address.

---

## References

Links to relevant issues, prior art, or external specifications.
