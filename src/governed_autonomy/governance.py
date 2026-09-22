import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .policy import Policy


@dataclass(frozen=True)
class GovernanceRule:
    """A single machine-enforceable governing constraint for one action."""

    action: str
    required_fields: tuple[str, ...] = ()
    exact_fields: dict[str, Any] = field(default_factory=dict)
    required_context: tuple[str, ...] = ()
    exact_context: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    required_approvals: int = 0

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "GovernanceRule":
        action = str(payload.get("action") or payload.get("name") or payload.get("rule"))
        if not action:
            raise ValueError("governance rule must include an action")

        required_fields = tuple(
            str(field)
            for field in payload.get("required_fields", ())
        )
        exact_fields_raw = payload.get("exact_fields", {})
        if not isinstance(exact_fields_raw, Mapping):
            raise ValueError("exact_fields must be a mapping of field->value")
        exact_fields = {str(field): value for field, value in exact_fields_raw.items()}

        required_context_raw = payload.get("required_context", ())
        if required_context_raw is None:
            required_context_raw = ()
        required_context = tuple(sorted({str(field) for field in required_context_raw}))

        exact_context_raw = payload.get("exact_context", {})
        if exact_context_raw is None:
            exact_context_raw = {}
        if not isinstance(exact_context_raw, Mapping):
            raise ValueError("exact_context must be a mapping of field->value")
        exact_context = {str(field): value for field, value in exact_context_raw.items()}

        raw_approvals = payload.get(
            "required_approvals",
            payload.get("approval_threshold", payload.get("approvals_required", 0)),
        )
        if raw_approvals is None:
            raw_approvals = 0
        if not isinstance(raw_approvals, int) or isinstance(raw_approvals, bool):
            raise ValueError("required_approvals must be a non-negative integer")
        if raw_approvals < 0:
            raise ValueError("required_approvals must be non-negative")

        return cls(
            action=action,
            required_fields=required_fields,
            exact_fields=exact_fields,
            required_context=required_context,
            exact_context=exact_context,
            description=str(payload.get("description", "")),
            required_approvals=raw_approvals,
        )


class GovernanceRuleTranslator:
    """Convert governance statements into the machine-enforceable Policy model."""

    def __init__(self, policy_id: str = "governed-autonomy-rules") -> None:
        self.policy_id = policy_id

    def translate(
        self,
        source: Mapping[str, Any] | Iterable[str] | Iterable[Mapping[str, Any]],
        *,
        policy_id: str | None = None,
    ) -> Policy:
        if isinstance(source, Mapping):
            rules = source.get("rules")
            if rules is None:
                raise ValueError("source mapping must include a 'rules' collection")
            effective_policy_id = str(source.get("policy_id") or policy_id or self.policy_id)
            policy = self.translate(rules, policy_id=effective_policy_id)
            required_context = tuple(
                str(field)
                for field in source.get("required_context", ())
            )
            exact_context_raw = source.get("exact_context", {})
            if exact_context_raw is None:
                exact_context_raw = {}
            if not isinstance(exact_context_raw, Mapping):
                raise ValueError("exact_context must be a mapping of field->value")
            exact_context = {str(field): value for field, value in exact_context_raw.items()}
            required_approvals_raw = source.get("required_approvals", {})
            if isinstance(required_approvals_raw, Mapping):
                required_approvals = {
                    str(action): int(value)
                    for action, value in required_approvals_raw.items()
                }
            elif isinstance(required_approvals_raw, int) and not isinstance(required_approvals_raw, bool):
                required_approvals = {action: required_approvals_raw for action in policy.allowed_actions}
            else:
                required_approvals = {}
            if not required_context and not exact_context and not required_approvals:
                return policy
            merged_required_context = tuple(
                sorted(dict.fromkeys((*policy.required_context, *required_context)))
            )
            merged_exact_context = {**policy.exact_context, **exact_context}
            merged_required_approvals = {**policy.required_approvals, **required_approvals}
            return Policy(
                policy_id=policy.policy_id,
                allowed_actions=policy.allowed_actions,
                required_fields=policy.required_fields,
                exact_fields=policy.exact_fields,
                required_context=merged_required_context,
                exact_context=merged_exact_context,
                max_request_bytes=policy.max_request_bytes,
                max_ttl_seconds=policy.max_ttl_seconds,
                required_approvals=merged_required_approvals,
            )

        effective_policy_id = str(policy_id or self.policy_id)
        normalized: dict[str, GovernanceRule] = {}
        for item in source:
            rule = self._coerce_rule(item)
            current = normalized.get(rule.action)
            if current is None:
                normalized[rule.action] = rule
                continue
            merged_required = tuple(dict.fromkeys((*current.required_fields, *rule.required_fields)))
            merged_exact = {**current.exact_fields, **rule.exact_fields}
            merged_required_context = tuple(
                sorted(dict.fromkeys((*current.required_context, *rule.required_context)))
            )
            merged_exact_context = {**current.exact_context, **rule.exact_context}
            merged_required_approvals = max(current.required_approvals, rule.required_approvals)
            normalized[rule.action] = GovernanceRule(
                action=rule.action,
                required_fields=merged_required,
                exact_fields=merged_exact,
                required_context=merged_required_context,
                exact_context=merged_exact_context,
                description=current.description or rule.description,
                required_approvals=merged_required_approvals,
            )

        if not normalized:
            raise ValueError("no governance rules were provided")

        required_fields: dict[str, tuple[str, ...]] = {}
        exact_fields: dict[str, dict[str, Any]] = {}
        required_context: set[str] = set()
        exact_context: dict[str, Any] = {}
        required_approvals: dict[str, int] = {}
        for action, rule in sorted(normalized.items()):
            required_fields[action] = rule.required_fields
            exact_fields[action] = rule.exact_fields
            required_context.update(rule.required_context)
            exact_context.update(rule.exact_context)
            if rule.required_approvals > 0:
                required_approvals[action] = rule.required_approvals

        allowed_actions = tuple(sorted(normalized))
        return Policy(
            policy_id=effective_policy_id,
            allowed_actions=allowed_actions,
            required_fields=required_fields,
            exact_fields=exact_fields,
            required_context=tuple(sorted(required_context)),
            exact_context=exact_context,
            required_approvals=required_approvals,
        )

    def _coerce_rule(self, item: str | Mapping[str, Any]) -> GovernanceRule:
        if isinstance(item, Mapping):
            return GovernanceRule.from_mapping(item)
        if not isinstance(item, str):
            raise ValueError("governance rule items must be mappings or strings")
        text = item.strip()
        if not text:
            raise ValueError("governance rule strings must not be empty")

        match = re.match(r"^(?:allow|require)\s+([A-Za-z0-9_]+)\s+(?:when|if|for)\s+(.*)$", text, re.IGNORECASE)
        if match:
            action, remainder = match.groups()
            required_fields: list[str] = []
            exact_fields: dict[str, Any] = {}
            required_approvals = 0

            presence_fields = re.findall(
                r"([A-Za-z0-9_]+)\s+(?:is|are)\s+present",
                remainder,
                re.IGNORECASE,
            )
            if presence_fields:
                required_fields.extend(self._split_fields(" ".join(presence_fields)))

            approval_match = re.search(
                r"(?:approvals?|approval_count)\s*(?:>=|==|=|>)\s*(\d+)",
                remainder,
                re.IGNORECASE,
            )
            if approval_match:
                required_approvals = int(approval_match.group(1))

            for match_exact in re.finditer(
                r"([A-Za-z0-9_]+)\s*(?:==|=)\s*(?:\"([^\"]*)\"|'([^']*)'|([A-Za-z0-9@._-]+))",
                remainder,
                re.IGNORECASE,
            ):
                field_name, quoted_double, quoted_single, bare = match_exact.groups()
                value = next(v for v in (quoted_double, quoted_single, bare) if v is not None)
                exact_fields[field_name] = self._normalize_literal(value)

            if not required_fields and not exact_fields and required_approvals == 0:
                raise ValueError(f"unsupported governance rule: {text}")
            return GovernanceRule(
                action=action,
                required_fields=tuple(dict.fromkeys(required_fields)),
                exact_fields=exact_fields,
                description=text,
                required_approvals=required_approvals,
            )

        match = re.match(r"^require\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*(?:==|=|is)\s*(.+)$", text, re.IGNORECASE)
        if match:
            action, field, value = match.groups()
            value = self._normalize_literal(value)
            return GovernanceRule(
                action=action,
                required_fields=(),
                exact_fields={field: value},
                description=text,
            )

        raise ValueError(f"unsupported governance rule syntax: {text}")

    @staticmethod
    def _split_fields(text: str) -> list[str]:
        if not text:
            return []
        parts = re.split(r"\s*,\s*|\s+and\s+|\s+", text.strip())
        fields = [part.strip() for part in parts if part.strip()]
        return [field for field in fields if field]

    @staticmethod
    def _normalize_literal(value: str) -> Any:
        value = value.strip()
        if not value:
            return value
        for quote in ('"', "'"):
            if value.startswith(quote) and value.endswith(quote):
                return value[1:-1]
        if value.lower() in {"true", "false"}:
            return value.lower() == "true"
        if re.fullmatch(r"-?\d+", value):
            return int(value)
        return value
