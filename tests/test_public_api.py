import governed_autonomy


def test_all_exports_resolve_and_are_unique():
    assert len(governed_autonomy.__all__) == len(set(governed_autonomy.__all__))
    for name in governed_autonomy.__all__:
        assert hasattr(governed_autonomy, name), name


def test_stale_exports_removed_from_package_root():
    for name in ("JWTValidator", "IdentityValidationError", "Role", "TLSConfig", "OperatorKeyStore"):
        assert name not in governed_autonomy.__all__
