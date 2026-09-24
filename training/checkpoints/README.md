# Checkpoint Reference

The repository intentionally does not vendor model weights. Run `training/train_gir.py`
with the pinned `training/requirements.txt` and the manifest to create a local checkpoint.
The default base model is `distilbert-base-uncased`; record the downloaded model revision,
dataset digest, and generated directory digest in the experiment record before publication.