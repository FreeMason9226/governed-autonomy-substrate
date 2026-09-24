# Reproducibility Artifacts

## GIR fine-tuning

`training/train_gir.py` fine-tunes `distilbert-base-uncased` for governance-obligation
classification. The pinned dependencies, deterministic seed, redacted JSONL examples,
and dataset manifest are in `training/`. The redacted examples are structural fixtures,
not a claim that they reproduce a proprietary corpus. A real run must record the base-model
revision, licensed dataset digest, training arguments, and output checkpoint digest.

Run from the repository root:

```powershell
python -m pip install -r training/requirements.txt
python training/train_gir.py
```

Weights are intentionally not committed. `training/checkpoints/README.md` defines the
checkpoint reference record required for publishing a resulting model.

## Cryptographic anchoring

`docs/cryptographic_vectors.json` contains a UUID-bound frame hash and CIDv1 raw-codec
vector. An independent verifier needs only canonical JSON, SHA-256, and lowercase base32.
The implementation and tests are in `src/governed_autonomy/anchoring.py` and
`tests/test_anchoring_claim51a.py`.

## Claim 51A metric

The repository uses the explicit deterministic definition

`Cpred = 1 - H(Ppred) / log2(|D|)`,

where `Ppred` is a probability distribution over `|D| >= 2` outcomes. Zero entropy
yields `1` and a uniform distribution yields `0`. The implementation is in
`src/governed_autonomy/claim51a.py` and should be reviewed against prosecution-approved
claim language before legal reliance.