# GIR Training Recipe

Run `bash gir/train/train.sh` or `python gir/train/train.py`. The recipe fixes the seed,
label ordering, preprocessing, model name, learning rate, batch size, and epoch count.
The synthetic dataset is for CI smoke tests only. Legal/regulatory training data must be
licensed and its digest recorded before publishing a transformer checkpoint. The smoke
metadata artifact is intentionally not represented as transformer weights.