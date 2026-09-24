# GIR Model Provenance

The published GIR pipeline fine-tunes `distilbert-base-uncased` for obligation-label
classification. The source corpus is represented by redacted, licensed-data-safe JSONL
fixtures in `training/data/`; production runs must replace them only with legally usable
regulatory or legal text and record its digest.

Preprocessing is deterministic: UTF-8 input, Unicode case folding, whitespace collapse,
tokenizer truncation at 256 tokens, sorted label IDs, seed `20260923`, AdamW learning rate
`2e-5`, batch size `8`, and `3` epochs. The transformer tokenizer and model revision must
be pinned by the run record; the default model name alone is not a reproducible revision.

`inference_regression.jsonl` defines canonical inputs and expected obligation labels for
the lightweight preprocessing/inference contract. A transformer checkpoint must reproduce
the same label vocabulary and publish its model-directory SHA-256 in
`checkpoints/checkpoint_manifest.json`. Weights are not committed to this repository.