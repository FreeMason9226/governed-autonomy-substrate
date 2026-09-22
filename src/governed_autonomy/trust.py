import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import b64decode, b64encode


class TrustStore:
    """Explicit issuer-key registry with durable revocation state."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._revoked: set[str] = set()
        if self.path and self.path.exists():
            self._load()

    def add(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        if not key_id:
            raise ValueError("key_id must not be empty")
        if key_id in self._keys and key_id not in self._revoked:
            raise ValueError(f"issuer key already exists: {key_id}")
        self._keys[key_id] = public_key
        self._revoked.discard(key_id)
        self._save()

    def revoke(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise KeyError(f"unknown issuer key: {key_id}")
        self._revoked.add(key_id)
        self._save()

    def resolve(self, key_id: str) -> Ed25519PublicKey | None:
        if key_id in self._revoked:
            return None
        return self._keys.get(key_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "keys": {
                key_id: b64encode(key.public_bytes_raw())
                for key_id, key in sorted(self._keys.items())
            },
            "revoked": sorted(self._revoked),
        }

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict()
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if (
                not isinstance(payload, dict)
                or set(payload) != {"keys", "revoked"}
                or not isinstance(payload["keys"], dict)
                or not isinstance(payload["revoked"], list)
                or any(not isinstance(item, str) for item in payload["revoked"])
            ):
                raise ValueError("trust store has an invalid schema")
            keys = {}
            for key_id, encoded in payload["keys"].items():
                if not isinstance(key_id, str) or not key_id:
                    raise ValueError("trust store contains an invalid key ID")
                if not isinstance(encoded, str):
                    raise ValueError("trust store contains an invalid public key")
                keys[key_id] = Ed25519PublicKey.from_public_bytes(b64decode(encoded))
            revoked = set(payload["revoked"])
            if not revoked.issubset(keys):
                raise ValueError("trust store revokes an unknown key")
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError("trust store could not be loaded safely") from exc
        self._keys = keys
        self._revoked = revoked
