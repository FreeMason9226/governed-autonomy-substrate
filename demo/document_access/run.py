"""Run governed operations against safe local SharePoint/OneDrive/S3 fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    repo_root = Path(__file__).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

from governed_autonomy import Policy

from demo._shared import DemoRuntime, build_runtime, identity_context

DOCUMENTS: dict[str, dict[str, Any]] = {
    "public-handbook": {
        "classification": "public",
        "owner": "hr",
        "content": "Public employee handbook fixture",
    },
    "confidential-plan": {
        "classification": "confidential",
        "owner": "finance",
        "content": "Confidential planning fixture",
    },
    "restricted-key": {
        "classification": "restricted",
        "owner": "security",
        "content": "Restricted secret fixture",
    },
}
PROVIDERS = ("sharepoint", "onedrive", "s3")


def build_demo() -> DemoRuntime:
    state: dict[str, Any] = {"documents": {key: dict(value) for key, value in DOCUMENTS.items()}, "shares": []}

    def execute_document_operation(request: dict[str, Any]) -> dict[str, Any]:
        provider = request["provider"]
        if provider not in PROVIDERS:
            raise ValueError("provider is not supported by the local fixture adapter")
        document_id = request["document_id"]
        operation = request["action"]
        documents = state["documents"]
        if operation == "Read":
            return {"provider": provider, "document_id": document_id, "content": documents[document_id]["content"]}
        if operation == "Write":
            documents[document_id]["content"] = request["content"]
            return {"provider": provider, "document_id": document_id, "written": True}
        if operation == "Delete":
            del documents[document_id]
            return {"provider": provider, "document_id": document_id, "deleted": True}
        if operation == "Share":
            share = {"provider": provider, "document_id": document_id, "recipient": request["recipient"]}
            state["shares"].append(share)
            return share
        raise ValueError("unsupported document operation")

    policies = (
        Policy(
            "PublicReadPolicy-v1",
            ("Read",),
            {"Read": ("document_id", "provider")},
            {"Read": {"classification": "public"}},
            required_context=("identity_source", "subject", "tenant_id"),
        ),
        Policy(
            "ConfidentialReadPolicy-v1",
            ("Read",),
            {"Read": ("document_id", "provider")},
            {"Read": {"classification": "confidential", "approved_reader": True}},
            required_context=("identity_source", "subject", "tenant_id"),
        ),
        Policy(
            "RestrictedDeletePolicy-v1",
            (),
            {},
            {},
            required_context=("identity_source", "subject", "tenant_id"),
        ),
        Policy(
            "ExternalSharePolicy-v1",
            ("Share",),
            {"Share": ("document_id", "provider", "recipient")},
            {"Share": {"external": False}},
            required_context=("identity_source", "subject", "tenant_id"),
        ),
        Policy(
            "DocumentWritePolicy-v1",
            ("Write",),
            {"Write": ("document_id", "provider", "content")},
            {"Write": {"classification": "public"}},
            required_context=("identity_source", "subject", "tenant_id"),
        ),
    )
    return build_runtime(
        scenario="document-access",
        policies=policies,
        actions=("Read", "Write", "Delete", "Share"),
        handler=execute_document_operation,
        state=state,
    )


def run_demo() -> tuple[DemoRuntime, dict[str, Any]]:
    runtime = build_demo()
    actor = identity_context("agent:document-assistant")
    public_read = runtime.run(
        {
            "action": "Read",
            "document_id": "public-handbook",
            "provider": "sharepoint",
            "classification": "public",
            "context": actor,
        },
        "PublicReadPolicy-v1",
    )
    confidential_denied = runtime.run(
        {
            "action": "Read",
            "document_id": "confidential-plan",
            "provider": "onedrive",
            "classification": "confidential",
            "approved_reader": False,
            "context": actor,
        },
        "ConfidentialReadPolicy-v1",
    )
    delete_denied = runtime.run(
        {
            "action": "Delete",
            "document_id": "restricted-key",
            "provider": "s3",
            "context": actor,
        },
        "RestrictedDeletePolicy-v1",
    )
    share_denied = runtime.run(
        {
            "action": "Share",
            "document_id": "confidential-plan",
            "provider": "onedrive",
            "recipient": "external@example.net",
            "external": True,
            "context": actor,
        },
        "ExternalSharePolicy-v1",
    )
    return runtime, {
        "runs": [public_read, confidential_denied, delete_denied, share_denied],
        "providers": list(PROVIDERS),
        "audit": runtime.audit_report(),
    }


def main() -> int:
    _runtime, result = run_demo()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
