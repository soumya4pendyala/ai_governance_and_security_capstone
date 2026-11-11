"""Fail-closed OPA policy decision client for CRA gateway actions."""

import json
import os
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from typing import Any


def _is_loopback(hostname: str | None) -> bool:
    return hostname in ("127.0.0.1", "localhost", "::1")


class OPAPolicyClient:
    def __init__(self, decision_url: str, ca_file: str | None = None):
        parsed_url = urlsplit(decision_url)
        if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
            raise RuntimeError("OPA_DECISION_URL must be an absolute HTTP(S) URL.")
        if parsed_url.scheme != "https" and not _is_loopback(parsed_url.hostname):
            raise RuntimeError("HTTPS is required for OPA outside loopback.")
        self.decision_url = decision_url
        self.tls_context = ssl.create_default_context(cafile=ca_file) if ca_file else None

    @classmethod
    def from_environment(cls) -> "OPAPolicyClient":
        decision_url = os.getenv("OPA_DECISION_URL")
        if not decision_url:
            raise RuntimeError("OPA_DECISION_URL is required; CRA actions are denied without OPA.")
        return cls(decision_url, os.getenv("OPA_CA_FILE"))

    @classmethod
    def mortgage_action_from_environment(cls) -> "OPAPolicyClient | None":
        decision_url = os.getenv("MORTGAGE_ACTION_OPA_DECISION_URL")
        if not decision_url:
            return None
        return cls(decision_url, os.getenv("OPA_CA_FILE"))

    def authorize(self, *, principal: dict[str, Any], action: str, resource: dict[str, Any]) -> bool:
        body = json.dumps({
            "input": {
                "principal": principal,
                "action": action,
                "resource": resource,
            },
        }).encode("utf-8")
        request = urllib.request.Request(
            self.decision_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=2, context=self.tls_context) as response:
                if response.status != 200:
                    raise RuntimeError(f"OPA returned HTTP {response.status}.")
                body = response.read(4097)
                if len(body) > 4096:
                    raise RuntimeError("OPA response exceeded the size limit.")
                response_data = json.loads(body)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError("OPA policy decision is unavailable; CRA action denied.") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError("OPA policy decision is unavailable; CRA action denied.") from exc
        if not isinstance(response_data, dict) or type(response_data.get("result")) is not bool:
            raise RuntimeError("OPA returned an invalid decision; CRA action denied.")
        return response_data["result"]
