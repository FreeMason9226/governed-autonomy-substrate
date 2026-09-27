FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY tools/verify-replay ./tools/verify-replay
RUN pip install --no-cache-dir .
ENTRYPOINT ["python", "tools/verify-replay/verify_replay.py"]