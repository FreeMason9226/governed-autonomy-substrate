from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..policy import Policy, policy_from_dict


class ProblemDetail(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: str
    request_id: str


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str
    request: dict[str, Any]
    ttl_seconds: int = 300
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    mesh_inputs: list[dict[str, Any]] = Field(default_factory=list)
    max_attempts: int = 3


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorization_id: str


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor_id: str | None = None
    rationale: str | None = None


class PolicyUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: dict[str, Any]

    def to_policy(self) -> Policy:
        return policy_from_dict(self.policy)


class PolicyPublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int | None = None


class PrincipalUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    tenant_id: str | None = None
    roles: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_environments: list[str] = Field(default_factory=list)
    allowed_sources: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    public_key: str | None = None


class PrincipalRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = None


class TenantCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    name: str | None = None
