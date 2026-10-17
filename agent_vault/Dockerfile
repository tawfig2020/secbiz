# Aegis Agent Vault — single-plugin Cloud Run image (stdlib core).
#
# The Vertex AI SDK (Gemini judge) is opt-in to keep the default image lean:
#   docker build --build-arg INSTALL_VERTEX=true -f agent_vault/Dockerfile .
FROM python:3.12-slim

WORKDIR /app

ARG INSTALL_VERTEX=false

# Install the Aegis core package (src layout); optionally add the Vertex SDK.
COPY pyproject.toml README.md ./
COPY src ./src
RUN if [ "$INSTALL_VERTEX" = "true" ]; then \
        pip install --no-cache-dir -e ".[vertex]"; \
    else \
        pip install --no-cache-dir -e .; \
    fi

# The prototype package + entrypoint.
COPY agent_vault ./agent_vault

ENV PORT=8080
EXPOSE 8080
CMD ["python", "-m", "agent_vault.server"]
