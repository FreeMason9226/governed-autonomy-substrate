"""Reproducible transformer fine-tuning entry point for GIR classification."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path("training/dataset_manifest.json"))
    parser.add_argument("--output", type=Path, default=Path("training/checkpoints/gir-distilbert"))
    parser.add_argument("--model", default="distilbert-base-uncased")
    parser.add_argument("--seed", type=int, default=20260923)
    parser.add_argument("--epochs", type=float, default=3.0)
    args = parser.parse_args()

    random.seed(args.seed)
    try:
        import numpy as np
        import torch
        from datasets import load_dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            DataCollatorWithPadding,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        raise SystemExit(
            "Install training/requirements.txt to run the reproducible GIR recipe"
        ) from exc

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest["task"] != "governance-obligation-classification":
        raise ValueError("manifest task does not match the GIR training task")
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    dataset = load_dataset("json", data_files=manifest["data_files"])
    labels = sorted({row["label"] for row in dataset["train"]})
    label_to_id = {label: index for index, label in enumerate(labels)}
    tokenizer = AutoTokenizer.from_pretrained(args.model)

    def tokenize(batch):
        encoded = tokenizer(batch["text"], truncation=True, max_length=256)
        encoded["labels"] = [label_to_id[label] for label in batch["label"]]
        return encoded

    tokenized = dataset.map(tokenize, batched=True, remove_columns=dataset["train"].column_names)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model,
        num_labels=len(labels),
        label2id=label_to_id,
        id2label={v: k for k, v in label_to_id.items()},
    )
    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(args.output),
            learning_rate=2e-5,
            per_device_train_batch_size=8,
            num_train_epochs=args.epochs,
            seed=args.seed,
            data_seed=args.seed,
            save_strategy="epoch",
            report_to=[],
        ),
        train_dataset=tokenized["train"],
        eval_dataset=tokenized.get("validation"),
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
    )
    trainer.train()
    trainer.save_model(args.output)
    (args.output / "labels.json").write_text(json.dumps(label_to_id, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()