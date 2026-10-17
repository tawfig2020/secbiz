# Aegis reference image (stdlib core; optional integrations installed).
FROM python:3.12-slim

WORKDIR /app

# Install the package in editable mode with dev extras (tests, lint, crypto).
COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests
COPY requirements.lock requirements.txt ./
RUN pip install --no-cache-dir -e ".[dev]"

# Command center + web assets (served by server.py).
COPY server.py ./
COPY web ./web

# Runtime entrypoint: the stdlib command center.
# Cloud Run injects PORT; server.py binds 0.0.0.0 automatically on GCP
# (K_SERVICE). Required env for the BFSI demo tier:
#   AEGIS_PUBLIC_DEMO=1            (unauthenticated, IP-rate-limited UI)
#   AEGIS_GEMINI_API_KEY=...       (optional Gemini judge)
#   AEGIS_FIRESTORE_PROJECT=...    (optional durable evidence sink)
EXPOSE 8090
CMD ["python", "server.py"]
