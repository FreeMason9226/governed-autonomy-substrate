FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[postgres]'
USER 65532:65532
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD python -c "import os,urllib.request; r=urllib.request.Request('http://127.0.0.1:8000/livez',headers={'Authorization':'Bearer '+os.environ.get('GOVERNED_AUTONOMY_BEARER_TOKEN','')}); urllib.request.urlopen(r)"
ENTRYPOINT ["gas-server"]
