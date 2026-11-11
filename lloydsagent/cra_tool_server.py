"""Authenticated HTTP boundary for the internal CRA tool service."""

import json
import logging
import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt

from lloydsagent.cra_gateway_auth import (
    CREDIT_REPORT_SCOPE,
    decode_downstream_token,
    read_key_file,
    validate_credit_report_arguments,
)
from lloydsagent.cra_mcp_server import _get_credit_report

MAX_REQUEST_BYTES = 16 * 1024
logger = logging.getLogger(__name__)


def _validate_server_url_scheme(host: str) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise RuntimeError("TLS is required when the CRA tool server is not bound to loopback.")


def create_server(host: str, port: int) -> ThreadingHTTPServer:
    public_key = read_key_file("CRA_DOWNSTREAM_PUBLIC_KEY_FILE")
    cert_file = os.getenv("CRA_TOOL_TLS_CERT_FILE")
    key_file = os.getenv("CRA_TOOL_TLS_KEY_FILE")
    if not cert_file and not key_file:
        _validate_server_url_scheme(host)
    handler = _handler_for(public_key)
    server = ThreadingHTTPServer((host, port), handler)
    if cert_file or key_file:
        if not cert_file or not key_file:
            server.server_close()
            raise RuntimeError("Both CRA_TOOL_TLS_CERT_FILE and CRA_TOOL_TLS_KEY_FILE are required.")
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        except Exception:
            server.server_close()
            raise
    return server


def _handler_for(public_key: str) -> type[BaseHTTPRequestHandler]:
    consumed_tokens: dict[str, int] = {}
    token_lock = threading.Lock()

    class CRAHandler(BaseHTTPRequestHandler):
        server_version = "CRA-Tool-Service"

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
            if self.path != "/v1/tools/call":
                self._respond(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_REQUEST_BYTES:
                    self._respond(413, {"error": "invalid_request_size"})
                    return
                if self.headers.get_content_type() != "application/json":
                    self._respond(415, {"error": "unsupported_media_type"})
                    return
                authorization = self.headers.get("Authorization", "")
                scheme, _, token = authorization.partition(" ")
                if scheme.lower() != "bearer" or not token:
                    self._respond(401, {"error": "unauthorized"})
                    return
                claims = decode_downstream_token(token, public_key)
                now = int(time.time())
                token_id = claims["jti"]
                with token_lock:
                    expired = [key for key, expiry in consumed_tokens.items() if expiry <= now]
                    for key in expired:
                        consumed_tokens.pop(key, None)
                    if token_id in consumed_tokens:
                        self._respond(401, {"error": "unauthorized"})
                        return
                    consumed_tokens[token_id] = int(claims["exp"])
                request = json.loads(self.rfile.read(length))
                if not isinstance(request, dict) or set(request) != {"tool_name", "arguments"}:
                    self._respond(400, {"error": "invalid_request"})
                    return
                if request["tool_name"] != "get_credit_report":
                    self._respond(403, {"error": "tool_not_permitted"})
                    return
                if claims.get("scope") != [CREDIT_REPORT_SCOPE]:
                    self._respond(403, {"error": "scope_not_permitted"})
                    return
                arguments = validate_credit_report_arguments(request["arguments"])
                result = _get_credit_report(**arguments)
                self._respond(200, {"result": result})
            except jwt.InvalidTokenError:
                self._respond(401, {"error": "unauthorized"})
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                self._respond(400, {"error": "invalid_request"})
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as exc:
                logger.error("CRA tool request failed (%s).", type(exc).__name__)
                self._respond(500, {"error": "tool_service_error"})

    return CRAHandler


def main() -> None:
    host = os.getenv("CRA_TOOL_HOST", "127.0.0.1")
    port = int(os.getenv("CRA_TOOL_PORT", "8444"))
    server = create_server(host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
