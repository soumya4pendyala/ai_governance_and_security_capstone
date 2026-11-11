"""MCP tool-call gateway with agent JWT validation and scoped delegation."""

import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import jwt

from lloydsagent.cra_gateway_audit import TamperEvidentAuditLog
from lloydsagent.cra_gateway_auth import (
    AGENT_AUDIENCE,
    CREDIT_REPORT_SCOPE,
    GATEWAY_ISSUER,
    MORTGAGE_ASSESS_SCOPE,
    decode_agent_token,
    read_key_file,
    validate_credit_report_arguments,
    validate_mortgage_action_arguments,
)
from lloydsagent.cra_gateway_policy import OPAPolicyClient

MAX_REQUEST_BYTES = 16 * 1024
DOWNSTREAM_TOKEN_LIFETIME_SECONDS = 30
logger = logging.getLogger(__name__)


def _is_loopback(hostname: str | None) -> bool:
    return hostname in ("127.0.0.1", "localhost", "::1")


def _require_secure_url(url: str, purpose: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" and not _is_loopback(parsed.hostname):
        raise RuntimeError(f"HTTPS is required for the {purpose} URL outside loopback.")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise RuntimeError(f"Invalid {purpose} URL.")


def _ssl_context(ca_file_variable: str) -> ssl.SSLContext | None:
    ca_file = os.getenv(ca_file_variable)
    return ssl.create_default_context(cafile=ca_file) if ca_file else None


def create_server(host: str, port: int) -> ThreadingHTTPServer:
    agent_public_key = read_key_file("CRA_AGENT_JWT_PUBLIC_KEY_FILE")
    downstream_private_key = read_key_file("CRA_DOWNSTREAM_PRIVATE_KEY_FILE")
    service_url = os.getenv("CRA_TOOL_SERVICE_URL")
    audit_path = os.getenv("CRA_GATEWAY_AUDIT_FILE")
    if not service_url:
        raise RuntimeError("CRA_TOOL_SERVICE_URL is required.")
    if not audit_path:
        raise RuntimeError("CRA_GATEWAY_AUDIT_FILE is required.")
    _require_secure_url(service_url, "CRA tool service")
    opa_client = OPAPolicyClient.from_environment()
    mortgage_action_opa_client = OPAPolicyClient.mortgage_action_from_environment()
    audit_log = TamperEvidentAuditLog(audit_path)
    handler = _handler_for(
        agent_public_key,
        downstream_private_key,
        service_url,
        audit_log,
        opa_client,
        mortgage_action_opa_client,
    )
    server = ThreadingHTTPServer((host, port), handler)
    cert_file = os.getenv("CRA_GATEWAY_TLS_CERT_FILE")
    key_file = os.getenv("CRA_GATEWAY_TLS_KEY_FILE")
    if cert_file or key_file:
        if not cert_file or not key_file:
            server.server_close()
            raise RuntimeError("Both CRA_GATEWAY_TLS_CERT_FILE and CRA_GATEWAY_TLS_KEY_FILE are required.")
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        except Exception:
            server.server_close()
            raise
    else:
        if not _is_loopback(host):
            server.server_close()
            raise RuntimeError("TLS certificate and key are required when the gateway is not bound to loopback.")
    return server


def _handler_for(
    agent_public_key: str,
    downstream_private_key: str,
    service_url: str,
    audit_log: TamperEvidentAuditLog,
    opa_client: OPAPolicyClient,
    mortgage_action_opa_client: OPAPolicyClient | None = None,
) -> type[BaseHTTPRequestHandler]:
    downstream_context = _ssl_context("CRA_TOOL_SERVICE_CA_FILE")

    class GatewayHandler(BaseHTTPRequestHandler):
        server_version = "CRA-MCP-Gateway"

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def _respond(self, status_code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._respond(200, {"status": "ok"})
            else:
                self._respond(404, {"error": "not_found"})

        def do_POST(self) -> None:
            request_id = str(uuid.uuid4())
            tool_name = "unknown"
            status_code = 500
            outcome = "error"
            payload: dict[str, Any] = {"error": "gateway_error"}
            try:
                if self.path == "/v1/policies/mortgage-action":
                    tool_name = "mortgage_action_policy"
                    length = int(self.headers.get("Content-Length", "0"))
                    if length <= 0 or length > MAX_REQUEST_BYTES:
                        status_code, outcome, payload = 413, "rejected", {"error": "invalid_request_size"}
                    elif self.headers.get_content_type() != "application/json":
                        status_code, outcome, payload = 415, "rejected", {"error": "unsupported_media_type"}
                    elif mortgage_action_opa_client is None:
                        status_code, outcome, payload = 503, "error", {"error": "policy_unavailable"}
                    else:
                        authorization = self.headers.get("Authorization", "")
                        scheme, _, agent_token = authorization.partition(" ")
                        if scheme.lower() != "bearer" or not agent_token:
                            status_code, outcome, payload = 401, "rejected", {"error": "unauthorized"}
                        else:
                            claims = decode_agent_token(
                                agent_token,
                                agent_public_key,
                                required_scope=MORTGAGE_ASSESS_SCOPE,
                            )
                            request = json.loads(self.rfile.read(length))
                            arguments = validate_mortgage_action_arguments(request)
                            allowed = mortgage_action_opa_client.authorize(
                                principal={
                                    "issuer": "keystone-agent",
                                    "subject": claims["sub"],
                                    "audience": AGENT_AUDIENCE,
                                    "scopes": [MORTGAGE_ASSESS_SCOPE],
                                },
                                action="mortgage:assess",
                                resource=arguments,
                            )
                            status_code = 200
                            outcome = "allowed" if allowed else "denied"
                            payload = {"allowed": allowed}
                elif self.path != "/v1/tools/call":
                    status_code, outcome, payload = 404, "rejected", {"error": "not_found"}
                else:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length <= 0 or length > MAX_REQUEST_BYTES:
                        status_code, outcome, payload = 413, "rejected", {"error": "invalid_request_size"}
                    elif self.headers.get_content_type() != "application/json":
                        status_code, outcome, payload = 415, "rejected", {"error": "unsupported_media_type"}
                    else:
                        authorization = self.headers.get("Authorization", "")
                        scheme, _, agent_token = authorization.partition(" ")
                        if scheme.lower() != "bearer" or not agent_token:
                            status_code, outcome, payload = 401, "rejected", {"error": "unauthorized"}
                        else:
                            claims = decode_agent_token(agent_token, agent_public_key)
                            request = json.loads(self.rfile.read(length))
                            if not isinstance(request, dict) or set(request) != {"tool_name", "arguments"}:
                                raise ValueError("Invalid request shape.")
                            tool_name = request["tool_name"]
                            if tool_name != "get_credit_report":
                                status_code, outcome, payload = 403, "rejected", {"error": "tool_not_permitted"}
                            else:
                                arguments = validate_credit_report_arguments(request["arguments"])
                                authorized = opa_client.authorize(
                                    principal={
                                        "issuer": "keystone-agent",
                                        "subject": claims["sub"],
                                        "audience": AGENT_AUDIENCE,
                                        "scopes": [CREDIT_REPORT_SCOPE],
                                    },
                                    action="cra:get_credit_report",
                                    resource={
                                        "tool": tool_name,
                                        "arguments_valid": True,
                                    },
                                )
                                if not authorized:
                                    status_code, outcome, payload = 403, "denied", {"error": "policy_denied"}
                                    raise PermissionError("OPA policy denied the CRA action.")
                                now = int(time.time())
                                delegated_token = jwt.encode(
                                    {
                                        "iss": GATEWAY_ISSUER,
                                        "aud": "keystone-cra-service",
                                        "sub": "cra-mcp-gateway",
                                        "scope": [CREDIT_REPORT_SCOPE],
                                        "tool": "get_credit_report",
                                        "iat": now,
                                        "exp": now + DOWNSTREAM_TOKEN_LIFETIME_SECONDS,
                                        "jti": str(uuid.uuid4()),
                                    },
                                    downstream_private_key,
                                    algorithm="RS256",
                                )
                                body = json.dumps({
                                    "tool_name": "get_credit_report",
                                    "arguments": arguments,
                                }).encode("utf-8")
                                downstream_request = urllib.request.Request(
                                    service_url.rstrip("/") + "/v1/tools/call",
                                    data=body,
                                    headers={
                                        "Authorization": f"Bearer {delegated_token}",
                                        "Content-Type": "application/json",
                                    },
                                    method="POST",
                                )
                                try:
                                    with urllib.request.urlopen(
                                        downstream_request,
                                        timeout=10,
                                        context=downstream_context,
                                    ) as response:
                                        downstream_body = response.read(MAX_REQUEST_BYTES * 8 + 1)
                                        if len(downstream_body) > MAX_REQUEST_BYTES * 8:
                                            raise RuntimeError("CRA tool service response exceeded the size limit.")
                                        downstream_data = json.loads(downstream_body)
                                        if (
                                            response.status != 200
                                            or not isinstance(downstream_data, dict)
                                            or not isinstance(downstream_data.get("result"), dict)
                                        ):
                                            raise RuntimeError("CRA tool service returned an invalid response.")
                                        payload = downstream_data
                                        status_code, outcome = 200, "success"
                                except (urllib.error.URLError, TimeoutError, ValueError, RuntimeError):
                                    status_code, outcome, payload = 502, "error", {"error": "cra_service_unavailable"}
            except jwt.InvalidTokenError:
                status_code, outcome, payload = 401, "rejected", {"error": "unauthorized"}
            except PermissionError:
                pass
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                status_code, outcome, payload = 400, "rejected", {"error": "invalid_request"}
            except RuntimeError as exc:
                logger.error("CRA gateway authorization failed (%s).", type(exc).__name__)
                status_code, outcome, payload = 503, "error", {"error": "policy_unavailable"}
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception:
                status_code, outcome, payload = 500, "error", {"error": "gateway_error"}

            try:
                audit_log.append(
                    request_id=request_id,
                    tool=tool_name
                    if tool_name in {"get_credit_report", "mortgage_action_policy"}
                    else "unknown",
                    outcome=outcome,
                    status_code=status_code,
                )
            except RuntimeError as exc:
                logger.error("CRA gateway audit write failed (%s).", type(exc).__name__)
                status_code, payload = 503, {"error": "audit_unavailable"}
            try:
                self._respond(status_code, payload)
            except (BrokenPipeError, ConnectionResetError):
                return

    return GatewayHandler


def main() -> None:
    host = os.getenv("CRA_GATEWAY_HOST", "127.0.0.1")
    port = int(os.getenv("CRA_GATEWAY_PORT", "8443"))
    server = create_server(host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
