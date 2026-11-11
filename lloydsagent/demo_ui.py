"""Loopback-only UI for demonstrating synthetic mortgage-agent governance controls."""

import json
import math
import os
from threading import Lock
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

from lloydsagent.governance import (
    build_mortgage_risk_register,
    build_regulatory_obligations_register,
    classify_eu_ai_act,
)
from lloydsagent.lloyds_tools import evaluate_decision_authority
from lloydsagent.privacy import ContentFilterMiddleware

MAX_BODY_BYTES = 8192
MAX_DEMO_TEXT_LENGTH = 4000
DEMO_PAGE = Path(__file__).with_name("demo_ui.html")
_MOCK_POLICY_LOCK = Lock()


def build_overview() -> dict[str, Any]:
    """Build a UI-safe governance snapshot from the project's demo registers."""
    classification = classify_eu_ai_act(
        evaluates_creditworthiness=True,
        concerns_natural_person=True,
        fraud_detection_only=False,
        materially_affects_decision=True,
        profiling=True,
    )
    return {
        "classification": asdict(classification),
        "risks": build_mortgage_risk_register(),
        "obligations": build_regulatory_obligations_register(),
        "controls": [
            {"name": "Direct prompt screening", "state": "Prototype control"},
            {"name": "Document-result screening", "state": "Mock tool-output boundary"},
            {"name": "Decision output schema", "state": "Pending/referral only"},
            {"name": "£500k action policy", "state": "Mock policy in local UI"},
            {"name": "At-rest protection", "state": "AES-GCM vault helpers; UI does not write records"},
            {"name": "Human decision workflow", "state": "Not implemented"},
        ],
    }


def _validate_demo_request(payload: Any) -> dict[str, Any]:
    required = {
        "requested_loan_amount_gbp",
        "affordability_passed",
        "is_standard_profile",
        "adverse_credit_flags",
        "credit_score",
        "direct_prompt",
        "document_text",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("Request must contain exactly the supported demo fields.")

    amount = payload["requested_loan_amount_gbp"]
    if (
        isinstance(amount, bool)
        or not isinstance(amount, (int, float))
        or not math.isfinite(amount)
        or amount <= 0
        or amount > 100_000_000
    ):
        raise ValueError("Requested amount must be a finite positive demo value.")
    if type(payload["affordability_passed"]) is not bool:
        raise ValueError("Affordability must be a boolean.")
    if type(payload["is_standard_profile"]) is not bool:
        raise ValueError("Profile type must be a boolean.")
    adverse_flags = payload["adverse_credit_flags"]
    if (
        isinstance(adverse_flags, bool)
        or not isinstance(adverse_flags, int)
        or not 0 <= adverse_flags <= 100
    ):
        raise ValueError("Adverse-credit flags must be an integer from 0 to 100.")
    credit_score = payload["credit_score"]
    if (
        isinstance(credit_score, bool)
        or not isinstance(credit_score, int)
        or not 0 <= credit_score <= 999
    ):
        raise ValueError("Credit score must be an integer from 0 to 999.")
    for field in ("direct_prompt", "document_text"):
        value = payload[field]
        if not isinstance(value, str) or len(value) > MAX_DEMO_TEXT_LENGTH:
            raise ValueError(f"{field} must be text no longer than {MAX_DEMO_TEXT_LENGTH} characters.")
    return payload


def evaluate_demo_request(payload: Any) -> dict[str, Any]:
    """Exercise local screening and decision-policy helpers without storing data."""
    values = _validate_demo_request(payload)
    prompt_allowed, prompt_reason, prompt_score = ContentFilterMiddleware.inspect_input(
        values["direct_prompt"]
    )
    document_allowed, document_reason, document_score = ContentFilterMiddleware.inspect_input(
        values["document_text"]
    )

    if not prompt_allowed:
        return {
            "status": "BLOCKED_PROMPT_INJECTION",
            "customer_message": "Request blocked by the local prompt-injection screen.",
            "direct_prompt": {
                "passed": False,
                "reason": prompt_reason,
                "risk_score": prompt_score,
            },
            "document": {
                "passed": document_allowed,
                "reason": document_reason,
                "risk_score": document_score,
            },
            "decision": None,
            "storage_written": False,
        }

    if not document_allowed:
        return {
            "status": "MANUAL_REVIEW_REQUIRED",
            "customer_message": "Document content was flagged; assessment stopped for manual review.",
            "direct_prompt": {
                "passed": True,
                "reason": prompt_reason,
                "risk_score": prompt_score,
            },
            "document": {
                "passed": False,
                "reason": document_reason,
                "risk_score": document_score,
            },
            "decision": None,
            "storage_written": False,
        }

    with _MOCK_POLICY_LOCK:
        with patch.dict(
            os.environ,
            {"MORTGAGE_ACTION_POLICY_MODE": "mock"},
        ):
            decision = json.loads(evaluate_decision_authority.invoke({
                "applicant_name": "Synthetic Demo Applicant",
                "requested_loan_amount": values["requested_loan_amount_gbp"],
                "affordability_passed": values["affordability_passed"],
                "credit_score": values["credit_score"],
                "is_standard_profile": values["is_standard_profile"],
                "adverse_credit_flags": values["adverse_credit_flags"],
                "lti_ratio": 4.0,
            }))

    status = (
        "PENDING_HUMAN_REVIEW"
        if decision["outcome"] == "PENDING_HUMAN_REVIEW"
        else "REFERRED_TO_HUMAN_REVIEW"
    )
    return {
        "status": status,
        "customer_message": "No approval or Decision in Principle was issued.",
        "direct_prompt": {
            "passed": True,
            "reason": prompt_reason,
            "risk_score": prompt_score,
        },
        "document": {
            "passed": True,
            "reason": document_reason,
            "risk_score": document_score,
        },
        "decision": decision,
        "storage_written": False,
    }


def _is_loopback_address(address: str) -> bool:
    return address in {"127.0.0.1", "::1"}


class DemoHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def create_handler() -> type[BaseHTTPRequestHandler]:
    class DemoHandler(BaseHTTPRequestHandler):
        server_version = "KeystoneGovernanceDemo"
        sys_version = ""

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _request_is_local(self) -> bool:
            peer = self.client_address[0]
            host = urlsplit("//" + self.headers.get("Host", "")).hostname
            return _is_loopback_address(peer) and host in {"127.0.0.1", "localhost", "::1"}

        def do_GET(self) -> None:
            if not self._request_is_local():
                self._send_json(403, {"error": "loopback_only"})
                return
            if urlsplit(self.path).path == "/api/overview":
                self._send_json(200, build_overview())
                return
            if urlsplit(self.path).path != "/":
                self._send_json(404, {"error": "not_found"})
                return

            try:
                body = DEMO_PAGE.read_bytes()
            except OSError:
                self._send_json(500, {"error": "demo_page_unavailable"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            if not self._request_is_local():
                self._send_json(403, {"error": "loopback_only"})
                return
            if urlsplit(self.path).path != "/api/evaluate":
                self._send_json(404, {"error": "not_found"})
                return
            if self.headers.get_content_type() != "application/json":
                self._send_json(415, {"error": "unsupported_media_type"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"error": "invalid_content_length"})
                return
            if length <= 0 or length > MAX_BODY_BYTES:
                self._send_json(413, {"error": "invalid_request_size"})
                return
            try:
                payload = json.loads(self.rfile.read(length))
                result = evaluate_demo_request(payload)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(200, result)

    return DemoHandler


def main() -> None:
    host = os.getenv("KEYSTONE_DEMO_HOST", "127.0.0.1")
    if not _is_loopback_address(host):
        raise RuntimeError("The governance demo UI may only bind to a loopback address.")
    try:
        port = int(os.getenv("KEYSTONE_DEMO_PORT", "8765"))
    except ValueError as exc:
        raise RuntimeError("KEYSTONE_DEMO_PORT must be an integer.") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("KEYSTONE_DEMO_PORT must be between 1 and 65535.")

    server = DemoHTTPServer((host, port), create_handler())
    print(f"Keystone governance demo running at http://{host}:{port}")
    print("Synthetic data only; no application records are stored.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Keystone governance demo.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
