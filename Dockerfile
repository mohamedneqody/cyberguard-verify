FROM python:3.12-slim

ARG INSTALL_BROWSER=false

LABEL org.opencontainers.image.title="CyberGuard Verify" \
      org.opencontainers.image.description="Evidence-based, non-destructive web application security verification engine" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY pyproject.toml README.md ./
COPY cyberguard_verify ./cyberguard_verify

RUN pip install --no-cache-dir -e . && \
    if [ "$INSTALL_BROWSER" = "true" ]; then \
      pip install --no-cache-dir ".[browser]" && \
      playwright install --with-deps chromium; \
    fi

WORKDIR /workspace
ENTRYPOINT ["cyberguard-verify"]
CMD ["--help"]
