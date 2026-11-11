import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lloydsagent import lloyds_tools
from lloydsagent.cra_gateway_audit import TamperEvidentAuditLog
from lloydsagent.cra_gateway_auth import (
    AGENT_AUDIENCE,
    AGENT_ISSUER,
    CREDIT_REPORT_SCOPE,
    CRA_AUDIENCE,
    GATEWAY_ISSUER,
    MORTGAGE_ASSESS_SCOPE,
)
from lloydsagent.cra_mcp_gateway import create_server as create_gateway_server
from lloydsagent.cra_tool_server import create_server as create_tool_server


def create_opa_stub(state: dict) -> ThreadingHTTPServer:
    class OPAHandler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args):
            return

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["input"] = request["input"]
            status_code = state.get("status_code", 200)
            body = json.dumps({"result": state.get("decision", True)}).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer(("127.0.0.1", 0), OPAHandler)


def create_key_pair(directory: Path, name: str) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = directory / f"{name}_private.pem"
    public_path = directory / f"{name}_public.pem"
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return private_path.read_text(encoding="utf-8"), public_path.read_text(encoding="utf-8")


def make_agent_token(private_key: str, *, expires_in: int = 300, scope: list[str] | None = None) -> str:
    now = int(time.time())
    return jwt.encode({
        "iss": AGENT_ISSUER,
        "aud": AGENT_AUDIENCE,
        "sub": "keystone-mortgage-agent",
        "scope": scope if scope is not None else [
            CREDIT_REPORT_SCOPE,
            MORTGAGE_ASSESS_SCOPE,
        ],
        "iat": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4()),
    }, private_key, algorithm="RS256")


def make_downstream_token(
    private_key: str,
    *,
    expires_in: int = 30,
    scope: list[str] | None = None,
) -> str:
    now = int(time.time())
    return jwt.encode({
        "iss": GATEWAY_ISSUER,
        "aud": CRA_AUDIENCE,
        "sub": "cra-mcp-gateway",
        "scope": scope if scope is not None else [CREDIT_REPORT_SCOPE],
        "tool": "get_credit_report",
        "iat": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4()),
    }, private_key, algorithm="RS256")


class GatewayIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.agent_private, self.agent_public = create_key_pair(self.path, "agent")
        self.gateway_private, self.gateway_public = create_key_pair(self.path, "gateway")
        self.agent_token_path = self.path / "agent.jwt"
        self.agent_token_path.write_text(make_agent_token(self.agent_private), encoding="utf-8")
        self.audit_path = self.path / "audit.jsonl"
        self.opa_state = {"decision": True}
        self.opa_server = create_opa_stub(self.opa_state)
        self.opa_thread = threading.Thread(target=self.opa_server.serve_forever, daemon=True)
        self.opa_thread.start()

        self.environment = patch.dict(os.environ, {
            "CRA_DOWNSTREAM_PUBLIC_KEY_FILE": str(self.path / "gateway_public.pem"),
            "CRA_AGENT_JWT_PUBLIC_KEY_FILE": str(self.path / "agent_public.pem"),
            "CRA_DOWNSTREAM_PRIVATE_KEY_FILE": str(self.path / "gateway_private.pem"),
            "CRA_GATEWAY_AUDIT_FILE": str(self.audit_path),
            "CRA_AGENT_JWT_FILE": str(self.agent_token_path),
            "OPA_DECISION_URL": f"http://127.0.0.1:{self.opa_server.server_address[1]}/v1/data/keystone/authz/allow",
            "MORTGAGE_ACTION_OPA_DECISION_URL": f"http://127.0.0.1:{self.opa_server.server_address[1]}/v1/data/keystone/authz/allow_mortgage_action",
        })
        self.environment.start()

        self.tool_server = create_tool_server("127.0.0.1", 0)
        self.tool_thread = threading.Thread(target=self.tool_server.serve_forever, daemon=True)
        self.tool_thread.start()
        tool_port = self.tool_server.server_address[1]
        os.environ["CRA_TOOL_SERVICE_URL"] = f"http://127.0.0.1:{tool_port}"

        self.gateway_server = create_gateway_server("127.0.0.1", 0)
        self.gateway_thread = threading.Thread(target=self.gateway_server.serve_forever, daemon=True)
        self.gateway_thread.start()
        gateway_port = self.gateway_server.server_address[1]
        os.environ["CRA_MCP_GATEWAY_URL"] = f"http://127.0.0.1:{gateway_port}"

    def tearDown(self):
        self.gateway_server.shutdown()
        self.gateway_server.server_close()
        self.tool_server.shutdown()
        self.tool_server.server_close()
        self.opa_server.shutdown()
        self.opa_server.server_close()
        self.environment.stop()
        self.directory.cleanup()

    def test_gateway_forwards_with_minimal_scope_and_audits_without_pii(self):
        result = json.loads(lloyds_tools.pull_credit_report_mcp.invoke({
            "applicant_name": "John Smith",
            "national_insurance_number": "QQ123456C",
        }))

        self.assertEqual(result["credit_score"], 825)
        self.assertNotIn("national_insurance_number", result)
        self.assertNotIn("applicant_name", result)
        self.assertEqual(self.opa_state["input"], {
            "principal": {
                "issuer": "keystone-agent",
                "subject": "keystone-mortgage-agent",
                "audience": AGENT_AUDIENCE,
                "scopes": [CREDIT_REPORT_SCOPE],
            },
            "action": "cra:get_credit_report",
            "resource": {
                "tool": "get_credit_report",
                "arguments_valid": True,
            },
        })
        self.assertNotIn("John Smith", json.dumps(self.opa_state["input"]))
        self.assertNotIn("QQ123456C", json.dumps(self.opa_state["input"]))
        audit_text = self.audit_path.read_text(encoding="utf-8")
        self.assertIn("get_credit_report", audit_text)
        self.assertNotIn("John Smith", audit_text)
        self.assertNotIn("QQ123456C", audit_text)
        self.assertTrue(TamperEvidentAuditLog(str(self.audit_path)).verify())

    def test_external_opa_mortgage_action_policy_is_authenticated_and_audited(self):
        os.environ["MORTGAGE_ACTION_POLICY_MODE"] = "external"
        allowed = lloyds_tools.mortgage_action_policy_allows(
            requested_loan_amount_gbp=400000,
            affordability_passed=True,
            is_standard_profile=True,
            adverse_credit_flags=0,
        )

        self.assertTrue(allowed)
        self.assertEqual(self.opa_state["input"]["action"], "mortgage:assess")
        self.assertEqual(
            self.opa_state["input"]["principal"]["scopes"],
            [MORTGAGE_ASSESS_SCOPE],
        )
        self.assertEqual(
            self.opa_state["input"]["resource"]["requested_loan_amount_gbp"],
            400000.0,
        )
        self.assertNotIn("applicant_name", json.dumps(self.opa_state["input"]))
        self.assertNotIn("national_insurance_number", json.dumps(self.opa_state["input"]))

        missing_scope_token = make_agent_token(
            self.agent_private,
            scope=[CREDIT_REPORT_SCOPE],
        )
        request = urllib.request.Request(
            os.environ["CRA_MCP_GATEWAY_URL"] + "/v1/policies/mortgage-action",
            data=json.dumps({
                "requested_loan_amount_gbp": 200000,
                "affordability_passed": True,
                "is_standard_profile": True,
                "adverse_credit_flags": 0,
            }).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {missing_scope_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as unauthorized:
            urllib.request.urlopen(request)
        self.assertEqual(unauthorized.exception.code, 401)
        unauthorized.exception.close()

        self.opa_state["decision"] = False
        denied = lloyds_tools.mortgage_action_policy_allows(
            requested_loan_amount_gbp=2000000,
            affordability_passed=True,
            is_standard_profile=True,
            adverse_credit_flags=0,
        )
        self.assertFalse(denied)
        audit_text = self.audit_path.read_text(encoding="utf-8")
        self.assertIn("mortgage_action_policy", audit_text)
        self.assertTrue(TamperEvidentAuditLog(str(self.audit_path)).verify())

    def test_invalid_and_expired_agent_tokens_are_rejected(self):
        for token in (
            "not-a-token",
            make_agent_token(self.agent_private, expires_in=-1),
            make_agent_token(self.agent_private, scope=["cra:identity:verify"]),
            make_agent_token(
                self.agent_private,
                scope=[CREDIT_REPORT_SCOPE, "cra:identity:verify"],
            ),
        ):
            self.agent_token_path.write_text(token, encoding="utf-8")
            with self.subTest(token=token[:12]):
                with self.assertRaisesRegex(RuntimeError, "HTTP 401"):
                    lloyds_tools.call_mcp_sync("get_credit_report", {
                        "applicant_name": "John Smith",
                        "national_insurance_number": "QQ123456C",
                    })

    def test_agent_without_gateway_configuration_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "direct CRA calls are disabled"):
                lloyds_tools.call_mcp_sync("get_credit_report", {
                    "applicant_name": "John Smith",
                    "national_insurance_number": "QQ123456C",
                })

    def test_opa_deny_and_unavailable_decisions_fail_closed(self):
        arguments = {
            "applicant_name": "John Smith",
            "national_insurance_number": "QQ123456C",
        }
        self.opa_state["decision"] = False
        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            lloyds_tools.call_mcp_sync("get_credit_report", arguments)

        self.opa_state["status_code"] = 503
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            lloyds_tools.call_mcp_sync("get_credit_report", arguments)

    def test_opa_invalid_decision_fails_closed(self):
        self.opa_state["decision"] = "allow"
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            lloyds_tools.call_mcp_sync("get_credit_report", {
                "applicant_name": "John Smith",
                "national_insurance_number": "QQ123456C",
            })
    def test_direct_service_request_without_gateway_token_is_rejected(self):
        body = json.dumps({
            "tool_name": "get_credit_report",
            "arguments": {
                "applicant_name": "John Smith",
                "national_insurance_number": "QQ123456C",
            },
        }).encode("utf-8")
        request = urllib.request.Request(
            os.environ["CRA_TOOL_SERVICE_URL"] + "/v1/tools/call",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=3)
        try:
            self.assertEqual(error.exception.code, 401)
        finally:
            error.exception.close()

    def test_backend_rejects_expired_or_wrong_scope_delegated_tokens_and_prevents_replay(self):
        body = json.dumps({
            "tool_name": "get_credit_report",
            "arguments": {
                "applicant_name": "John Smith",
                "national_insurance_number": "QQ123456C",
            },
        }).encode("utf-8")
        endpoint = os.environ["CRA_TOOL_SERVICE_URL"] + "/v1/tools/call"

        def call_backend(token: str) -> int:
            request = urllib.request.Request(
                endpoint,
                data=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=3) as response:
                    return response.status
            except urllib.error.HTTPError as error:
                try:
                    return error.code
                finally:
                    error.close()

        self.assertEqual(call_backend(make_downstream_token(self.gateway_private, expires_in=-1)), 401)
        self.assertEqual(call_backend(make_downstream_token(
            self.gateway_private,
            scope=["cra:identity:verify"],
        )), 401)
        token = make_downstream_token(self.gateway_private)
        self.assertEqual(call_backend(token), 200)
        self.assertEqual(call_backend(token), 401)

    def test_unknown_tools_and_invalid_arguments_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported CRA tool"):
            lloyds_tools.call_mcp_sync("verify_identity", {})
        with self.assertRaisesRegex(RuntimeError, "HTTP 400"):
            lloyds_tools.call_mcp_sync("get_credit_report", {
                "applicant_name": "John Smith",
                "national_insurance_number": "not-a-nino",
            })


class AuditChainTests(unittest.TestCase):
    def test_audit_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = TamperEvidentAuditLog(str(path))
            audit.append(request_id="request-1", tool="get_credit_report", outcome="success", status_code=200)
            entry = json.loads(path.read_text(encoding="utf-8"))
            entry["event"]["outcome"] = "replaced"
            path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "audit chain is corrupt"):
                TamperEvidentAuditLog(str(path))

    def test_audit_refuses_append_after_external_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = TamperEvidentAuditLog(str(path))
            audit.append(request_id="request-1", tool="get_credit_report", outcome="success", status_code=200)
            path.write_text(path.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "changed after startup"):
                audit.append(request_id="request-2", tool="get_credit_report", outcome="success", status_code=200)


if __name__ == "__main__":
    unittest.main()
