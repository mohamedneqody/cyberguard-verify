"""SSRF prevention, cloud metadata blocking, and strict authorized scope enforcement."""

import ipaddress
import os
from typing import Optional, Set, Tuple
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, build_opener

from .config import ALLOWED_HOSTS, ALLOWED_PORTS


class SecurityBoundaryViolation(Exception):
    """Raised when an operation attempts to reach an unauthorized host, port, or scheme."""


_DYNAMIC_ALLOWED_HOSTS: Set[str] = set()
_DYNAMIC_ALLOWED_PORTS: Set[int] = set()


def authorize_target_scope(target_url: str, extra_hosts: Optional[list] = None) -> Tuple[str, int]:
    """Explicitly registers the target URL host/port and CLI-authorized hosts in the session scope."""
    for h in extra_hosts or []:
        if h and h.strip():
            _DYNAMIC_ALLOWED_HOSTS.add(h.strip().lower())
    raw = target_url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    u = urlparse(raw)
    if u.hostname:
        _DYNAMIC_ALLOWED_HOSTS.add(u.hostname.lower())
    port = u.port or (443 if u.scheme == "https" else 80)
    _DYNAMIC_ALLOWED_PORTS.add(port)
    return validate_target(raw)


def _is_cloud_metadata(hostname: str) -> bool:
    if hostname in ("169.254.169.254", "metadata.google.internal", "100.100.100.200"):
        return True
    if hostname.startswith("169.254."):
        return True
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if ip_obj.is_link_local:
            return True
    except ValueError:
        pass
    return False


def validate_target(target: str) -> Tuple[str, int]:
    """Validates scheme, hostname safety, cloud-metadata exclusion, and port policy."""
    if not target or not isinstance(target, str):
        raise SecurityBoundaryViolation(f"Invalid target specification: {target}")

    raw = target.strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    parsed = urlparse(raw)

    if parsed.scheme not in ("http", "https"):
        raise SecurityBoundaryViolation(f"Unauthorized URL scheme '{parsed.scheme}'.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise SecurityBoundaryViolation(f"Missing hostname in target '{target}'.")

    for forbidden in (";", "&", "|", "`", "$", " ", "\n", "\r", "\t"):
        if forbidden in hostname:
            raise SecurityBoundaryViolation(f"Disallowed character in hostname: '{hostname}'.")

    if _is_cloud_metadata(hostname):
        raise SecurityBoundaryViolation(f"Scope violation: Cloud metadata host '{hostname}' is blocked.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    sensitive_ports = {21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 6379, 9200, 27017}
    if port in sensitive_ports:
        raise SecurityBoundaryViolation(f"Scope violation: non-web infrastructure port {port} is blocked.")

    allowed_hosts = {h.lower() for h in ALLOWED_HOSTS} | _DYNAMIC_ALLOWED_HOSTS
    env_extra = os.getenv("CYBERGUARD_ALLOW_TARGET_HOSTS", "")
    if env_extra:
        allowed_hosts |= {h.strip().lower() for h in env_extra.split(",") if h.strip()}

    if hostname not in allowed_hosts and not hostname.endswith((".local", ".internal")):
        raise SecurityBoundaryViolation(
            f"Scope violation: host '{hostname}' is not authorized. Pass --allow-host or scan a permitted local/staging target."
        )

    allowed_ports = set(ALLOWED_PORTS) | _DYNAMIC_ALLOWED_PORTS
    if port not in allowed_ports:
        raise SecurityBoundaryViolation(f"Scope violation: port {port} is outside permitted scope.")

    return hostname, port


class SafeRedirectHandler(HTTPRedirectHandler):
    """Validates HTTP redirects against scope rules to prevent SSRF redirect bypass."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_target(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def get_safe_opener():
    """Returns a urllib opener wrapped with scope-enforcing redirect validation."""
    return build_opener(SafeRedirectHandler())
