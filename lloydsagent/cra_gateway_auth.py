"""JWT helpers and claim validation shared by the CRA gateway and service."""

import os
import math
import re
from pathlib import Path
from typing import Any

import jwt

AGENT_ISSUER = "keystone-agent"
AGENT_AUDIENCE = "keystone-cra-gateway"
GATEWAY_ISSUER = "keystone-cra-gateway"
CRA_AUDIENCE = "keystone-cra-service"
CREDIT_REPORT_SCOPE = "cra:credit-report:read"
MORTGAGE_ASSESS_SCOPE = "mortgage:assessment:request"
AGENT_SCOPES = {CREDIT_REPORT_SCOPE, MORTGAGE_ASSESS_SCOPE}
_NINO_PATTERN = re.compile(r"^[A-Z]{2}\d{6}[A-Z]$")


def read_key_file(environment_variable: str) -> str:
    key_path = os.getenv(environment_variable)
    if not key_path:
        raise RuntimeError(f"{environment_variable} must point to a provisioned key file.")
    try:
        return Path(key_path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"Unable to read configured key file for {environment_variable}.") from exc


def decode_agent_token(
    token: str,
    public_key: str,
    *,
    required_scope: str = CREDIT_REPORT_SCOPE,
) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=AGENT_AUDIENCE,
        issuer=AGENT_ISSUER,
        options={"require": ["exp", "iat", "jti", "iss", "aud", "sub"]},
    )
    scopes = claims.get("scope")
    if claims.get("sub") != "keystone-mortgage-agent":
        raise jwt.InvalidTokenError("Unexpected agent identity.")
    if (
        not isinstance(scopes, list)
        or not scopes
        or any(not isinstance(scope, str) for scope in scopes)
        or len(scopes) != len(set(scopes))
        or not set(scopes).issubset(AGENT_SCOPES)
        or required_scope not in scopes
    ):
        raise jwt.InvalidTokenError("Agent token is missing an allowed action scope.")
    return claims


def decode_downstream_token(token: str, public_key: str) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=CRA_AUDIENCE,
        issuer=GATEWAY_ISSUER,
        options={"require": ["exp", "iat", "jti", "iss", "aud", "sub"]},
    )
    scopes = claims.get("scope")
    if claims.get("sub") != "cra-mcp-gateway":
        raise jwt.InvalidTokenError("Unexpected gateway identity.")
    if claims.get("tool") != "get_credit_report":
        raise jwt.InvalidTokenError("Token is not scoped to the requested tool.")
    if not isinstance(scopes, list) or CREDIT_REPORT_SCOPE not in scopes:
        raise jwt.InvalidTokenError("Required downstream scope is missing.")
    return claims


def validate_credit_report_arguments(arguments: Any) -> dict[str, str]:
    if not isinstance(arguments, dict) or set(arguments) != {
        "applicant_name",
        "national_insurance_number",
    }:
        raise ValueError("Invalid arguments for get_credit_report.")
    applicant_name = arguments["applicant_name"]
    national_insurance_number = arguments["national_insurance_number"]
    if not isinstance(applicant_name, str) or not applicant_name.strip() or len(applicant_name) > 200:
        raise ValueError("Invalid applicant_name.")
    if not isinstance(national_insurance_number, str):
        raise ValueError("Invalid national_insurance_number.")
    normalized_nino = national_insurance_number.replace(" ", "").upper()
    if not _NINO_PATTERN.fullmatch(normalized_nino):
        raise ValueError("Invalid national_insurance_number.")
    return {
        "applicant_name": applicant_name.strip(),
        "national_insurance_number": normalized_nino,
    }


def validate_mortgage_action_arguments(arguments: Any) -> dict[str, Any]:
    required = {
        "requested_loan_amount_gbp",
        "affordability_passed",
        "is_standard_profile",
        "adverse_credit_flags",
    }
    if not isinstance(arguments, dict) or set(arguments) != required:
        raise ValueError("Invalid arguments for mortgage action policy.")
    amount = arguments["requested_loan_amount_gbp"]
    adverse_flags = arguments["adverse_credit_flags"]
    if (
        isinstance(amount, bool)
        or not isinstance(amount, (int, float))
        or not math.isfinite(amount)
        or amount <= 0
    ):
        raise ValueError("Invalid requested loan amount.")
    if type(arguments["affordability_passed"]) is not bool:
        raise ValueError("Invalid affordability status.")
    if type(arguments["is_standard_profile"]) is not bool:
        raise ValueError("Invalid applicant profile status.")
    if (
        isinstance(adverse_flags, bool)
        or not isinstance(adverse_flags, int)
        or adverse_flags < 0
    ):
        raise ValueError("Invalid adverse-credit count.")
    return {
        "requested_loan_amount_gbp": float(amount),
        "affordability_passed": arguments["affordability_passed"],
        "is_standard_profile": arguments["is_standard_profile"],
        "adverse_credit_flags": adverse_flags,
    }
