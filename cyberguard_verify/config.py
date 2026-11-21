"""Configuration and scope policy defaults for CyberGuard Verify."""

import os
from typing import Dict, List


def _csv_env(name: str, default: List[str]) -> List[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return list(default)
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


DEFAULT_REQUEST_TIMEOUT: int = int(os.getenv("CYBERGUARD_TIMEOUT", "10"))
PLAYWRIGHT_SERVICE_URL: str = os.getenv("CYBERGUARD_PLAYWRIGHT_URL", "").strip()

ALLOWED_HOSTS: List[str] = _csv_env(
    "CYBERGUARD_ALLOWED_HOSTS",
    ["127.0.0.1", "localhost", "::1", "host.docker.internal"],
)

ALLOWED_PORTS: List[int] = [
    int(p)
    for p in _csv_env(
        "CYBERGUARD_ALLOWED_PORTS",
        ["80", "443", "3000", "3001", "3300", "5000", "8000", "8080", "8443", "8765", "8766", "8767", "8768", "8769", "8770", "8771", "8775"],
    )
    if p.isdigit()
]

HOST_SPECIFIC_PORT_RESTRICTIONS: Dict[str, List[int]] = {}
SAFE_MODE: bool = True
