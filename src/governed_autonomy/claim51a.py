"""Deterministic entropy-normalized confidence metric for Claim 51A."""

from __future__ import annotations

import math
from collections.abc import Sequence


def entropy_normalized_confidence(probabilities: Sequence[float]) -> float:
    """Return ``Cpred = 1 - H(Ppred) / log2(|D|)``.

    ``Ppred`` is a finite probability distribution over ``|D| >= 2`` outcomes.
    The metric is one for a deterministic prediction and zero for a uniform
    prediction over the declared domain.
    """
    if len(probabilities) < 2 or any(not math.isfinite(value) or value < 0 for value in probabilities):
        raise ValueError("probabilities must contain at least two finite non-negative values")
    total = sum(probabilities)
    if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError("probabilities must sum to 1")
    entropy_bits = -sum(value * math.log2(value) for value in probabilities if value > 0)
    return 1.0 - entropy_bits / math.log2(len(probabilities))