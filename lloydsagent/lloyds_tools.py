"""
Lloyds Keystone Agent Tools & Data Layer
-----------------------------------------
This module implements the internal banking tools, mock databases, affordability calculations,
decision authority enforcement, storage persistence, and the MCP client integration
for Lloyds Bank's Keystone Mortgage Agent.
"""

import base64
import binascii
import math
import os
import json
import ssl
import tempfile
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from urllib.parse import urlsplit
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from langchain_core.tools import tool
from pydantic import BaseModel, ConfigDict, Field
from lloydsagent.privacy import PIISanitizationMiddleware
from typing import Literal

# Path for persistent application storage
VAULT_STORAGE_DIR = os.getenv("KEYSTONE_VAULT_DIR", os.path.dirname(__file__))
VAULT_STORAGE_FILE = os.path.join(VAULT_STORAGE_DIR, "mortgage_applications_vault.json")
VAULT_ENVELOPE_FORMAT = "keystone-encrypted-vault"
VAULT_ASSOCIATED_DATA = b"keystone-mortgage-vault:v1"
FIELD_ENVELOPE_MARKER = "__keystone_field_ciphertext_v1__"
SENSITIVE_FIELD_NAMES = {
    "national_insurance_number",
    "account_number",
    "sort_code",
    "credit_score",
    "score",
    "score_band",
    "ccj_count",
    "defaults_count",
    "bankruptcies",
    "risk_category",
    "bureau_ref",
    "bureau_reference",
}
MOCK_VAULT_ROLE_PERMISSIONS = {
    "mortgage_underwriter": "read_application",
    "privacy_officer": "read_application",
    "audit_reader": "read_metadata",
}
HUMAN_MANDATE_ESCALATION_THRESHOLD_GBP = 500000.0
MIN_STANDARD_CREDIT_SCORE = 700


class MortgageDecisionOutput(BaseModel):
    """Strict allow-list for decision-tool output; auto-approval is not a valid state."""

    model_config = ConfigDict(extra="forbid", strict=True)

    requested_loan_amount_gbp: float = Field(gt=0, strict=False)
    evaluated_at: str = Field(min_length=1)
    human_mandate_escalation_threshold_gbp: float = Field(
        default=HUMAN_MANDATE_ESCALATION_THRESHOLD_GBP,
        le=HUMAN_MANDATE_ESCALATION_THRESHOLD_GBP,
        strict=False,
    )
    outcome: Literal["ESCALATE_TO_HUMAN_UNDERWRITER", "PENDING_HUMAN_REVIEW"]
    dip_status: Literal["REFERRED", "PENDING_REVIEW"]
    escalation_tier: str = Field(min_length=1)
    escalation_reasons: list[str] = Field(min_length=1)
    action_required: str = Field(min_length=1)


def _validated_decision_json(decision: Dict[str, Any]) -> str:
    validated = MortgageDecisionOutput.model_validate(decision)
    return json.dumps(validated.model_dump(), indent=2)


def _vault_cipher() -> AESGCM:
    encoded_key = os.getenv("MORTGAGE_VAULT_KEY", "")
    key_file = os.getenv("MORTGAGE_VAULT_KEY_FILE")
    if encoded_key and key_file:
        raise RuntimeError("Configure only one of MORTGAGE_VAULT_KEY or MORTGAGE_VAULT_KEY_FILE.")
    if key_file:
        try:
            with open(key_file, "r", encoding="ascii") as key_handle:
                encoded_key = key_handle.read().strip()
        except (OSError, UnicodeError) as exc:
            raise RuntimeError("Unable to read MORTGAGE_VAULT_KEY_FILE.") from exc
    if not encoded_key:
        raise RuntimeError(
            "MORTGAGE_VAULT_KEY is required, or MORTGAGE_VAULT_KEY_FILE must point to its protected file."
        )
    try:
        key = base64.b64decode(encoded_key.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise RuntimeError("MORTGAGE_VAULT_KEY must be URL-safe base64.") from exc
    if len(key) != 32:
        raise RuntimeError("MORTGAGE_VAULT_KEY must decode to exactly 32 bytes.")
    return AESGCM(key)


def _load_vault_records(cipher: AESGCM) -> List[Dict[str, Any]]:
    if not os.path.exists(VAULT_STORAGE_FILE):
        return []

    with open(VAULT_STORAGE_FILE, "r", encoding="utf-8") as vault_file:
        stored_data = json.load(vault_file)

    if isinstance(stored_data, dict) and stored_data.get("format") == VAULT_ENVELOPE_FORMAT:
        if stored_data.get("version") != 1 or stored_data.get("algorithm") != "AES-256-GCM":
            raise ValueError("Unsupported encrypted mortgage vault format.")
        nonce = base64.b64decode(stored_data["nonce"], validate=True)
        ciphertext = base64.b64decode(stored_data["ciphertext"], validate=True)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, VAULT_ASSOCIATED_DATA)
        except InvalidTag as exc:
            raise RuntimeError(
                "Mortgage vault authentication failed; data was not read or overwritten."
            ) from exc
        records = _reveal_sensitive_fields(
            json.loads(plaintext.decode("utf-8")),
            cipher,
        )
    else:
        # Existing JSON vaults are migrated to an encrypted envelope on the next write.
        records = stored_data

    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError("Mortgage vault must contain a list of application records.")
    return records


def _write_vault_records(records: List[Dict[str, Any]], cipher: AESGCM) -> None:
    nonce = os.urandom(12)
    protected_records = _protect_sensitive_fields(records, cipher)
    plaintext = json.dumps(protected_records, indent=2).encode("utf-8")
    envelope = {
        "format": VAULT_ENVELOPE_FORMAT,
        "version": 1,
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(
            cipher.encrypt(nonce, plaintext, VAULT_ASSOCIATED_DATA)
        ).decode("ascii"),
    }

    vault_directory = os.path.dirname(VAULT_STORAGE_FILE)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".mortgage-vault-", suffix=".tmp", dir=vault_directory
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as vault_file:
            json.dump(envelope, vault_file, indent=2)
            vault_file.flush()
            os.fsync(vault_file.fileno())
        os.replace(temporary_path, VAULT_STORAGE_FILE)
        if os.name != "nt":
            os.chmod(VAULT_STORAGE_FILE, 0o600)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def _project_fields(data: Dict[str, Any], allowed_fields: tuple[str, ...]) -> Dict[str, Any]:
    return {field: data[field] for field in allowed_fields if field in data}


def _is_finite_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _protect_sensitive_fields(value: Any, cipher: AESGCM, path: str = "$") -> Any:
    if isinstance(value, dict):
        protected = {}
        for key, item in value.items():
            field_path = f"{path}.{key}"
            is_sensitive_context = (
                ".lloyds_account_summary." in field_path
                or ".cra_credit_bureau." in field_path
            )
            if (
                key.lower() in SENSITIVE_FIELD_NAMES or is_sensitive_context
            ) and item is not None:
                nonce = os.urandom(12)
                plaintext = json.dumps(item, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
                ciphertext = cipher.encrypt(nonce, plaintext, field_path.encode("utf-8"))
                protected[key] = {
                    FIELD_ENVELOPE_MARKER: True,
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                }
            else:
                protected[key] = _protect_sensitive_fields(item, cipher, field_path)
        return protected
    if isinstance(value, list):
        return [
            _protect_sensitive_fields(item, cipher, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    return value


def _reveal_sensitive_fields(value: Any, cipher: AESGCM, path: str = "$") -> Any:
    if isinstance(value, dict):
        revealed = {}
        for key, item in value.items():
            field_path = f"{path}.{key}"
            if isinstance(item, dict) and item.get(FIELD_ENVELOPE_MARKER) is True:
                nonce = base64.b64decode(item["nonce"], validate=True)
                ciphertext = base64.b64decode(item["ciphertext"], validate=True)
                plaintext = cipher.decrypt(nonce, ciphertext, field_path.encode("utf-8"))
                revealed[key] = json.loads(plaintext.decode("utf-8"))
            else:
                revealed[key] = _reveal_sensitive_fields(item, cipher, field_path)
        return revealed
    if isinstance(value, list):
        return [
            _reveal_sensitive_fields(item, cipher, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    return value


@dataclass(frozen=True)
class MockVaultPrincipal:
    """Demo-only identity context; production must construct this from verified claims."""

    subject: str
    tenant_id: str
    role: str


def read_mortgage_application_for_principal(
    application_id: str,
    principal: MockVaultPrincipal,
) -> Dict[str, Any]:
    """Demonstrate tenant row filtering and role-based reads over the mock vault."""
    if not isinstance(principal, MockVaultPrincipal) or not principal.subject.strip():
        raise PermissionError("An authenticated vault principal is required.")
    permission = MOCK_VAULT_ROLE_PERMISSIONS.get(principal.role)
    if permission is None:
        raise PermissionError("The vault role is not authorized.")
    records = _load_vault_records(_vault_cipher())
    record = next(
        (item for item in records if item.get("application_id") == application_id),
        None,
    )
    if record is None or record.get("tenant_id") != principal.tenant_id:
        raise PermissionError("The application is outside the principal's tenant scope.")
    if permission == "read_metadata":
        return {
            key: record[key]
            for key in ("application_id", "tenant_id", "stored_at", "governance_status")
            if key in record
        }
    return record


# ============================================================================
# 1. MOCK INTERNAL DATABASES (Lloyds Bank Customer & Financial Records)
# ============================================================================

MOCK_LLOYDS_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    "12345678": {
        "customer_name": "John Smith",
        "sort_code": "30-90-89",
        "account_number": "12345678",
        "tenure_years": 7,
        "relationship_tier": "Club Lloyds",
        "current_account_balance_gbp": 14500.0,
        "savings_balance_gbp": 42000.0,
        "average_monthly_salary_credit_gbp": 4200.0,
        "monthly_living_costs_gbp": 1330.0,
        "existing_debt_commitments_monthly_gbp": 220.0,  # car finance
        "overdraft_usage_12m": 0,
        "bounced_payments_12m": 0,
        "kyc_verified": True
    },
    "87654321": {
        "customer_name": "Sarah Jenkins",
        "sort_code": "30-90-89",
        "account_number": "87654321",
        "tenure_years": 10,
        "relationship_tier": "Lloyds Premier",
        "current_account_balance_gbp": 32000.0,
        "savings_balance_gbp": 150000.0,
        "average_monthly_salary_credit_gbp": 9500.0,
        "monthly_living_costs_gbp": 2400.0,
        "existing_debt_commitments_monthly_gbp": 450.0,
        "overdraft_usage_12m": 0,
        "bounced_payments_12m": 0,
        "kyc_verified": True
    },
    "11223344": {
        "customer_name": "Robert Taylor",
        "sort_code": "30-90-89",
        "account_number": "11223344",
        "tenure_years": 2,
        "relationship_tier": "Classic Account",
        "current_account_balance_gbp": 450.0,
        "savings_balance_gbp": 5000.0,
        "average_monthly_salary_credit_gbp": 2200.0,
        "monthly_living_costs_gbp": 1800.0,
        "existing_debt_commitments_monthly_gbp": 600.0,
        "overdraft_usage_12m": 8,
        "bounced_payments_12m": 3,
        "kyc_verified": True
    }
}

MOCK_VERIFIED_DOCUMENTS: Dict[str, Dict[str, Any]] = {
    "John Smith": {
        "employer_name": "FinTech Systems UK Ltd",
        "employment_type": "Permanent Full-Time",
        "job_title": "Lead Software Architect",
        "employment_length_years": 4.5,
        "gross_annual_income_gbp": 70000.0,
        "net_monthly_pay_gbp": 4200.0,
        "tax_code": "1257L",
        "payslips_verified": True,
        "bank_statements_cross_verified": True,
        "notes": "Verified 3 consecutive months payslips match Lloyds current account salary credits exactly."
    },
    "Sarah Jenkins": {
        "employer_name": "BioHealth Global PLC",
        "employment_type": "Permanent Full-Time",
        "job_title": "VP Medical Director",
        "employment_length_years": 6.0,
        "gross_annual_income_gbp": 160000.0,
        "net_monthly_pay_gbp": 9500.0,
        "tax_code": "1257L",
        "payslips_verified": True,
        "bank_statements_cross_verified": True,
        "notes": "Verified executive remuneration statements match account credits."
    },
    "Robert Taylor": {
        "employer_name": "Apex Gig Logistics",
        "employment_type": "Zero Hours Contractor",
        "job_title": "Courier",
        "employment_length_years": 0.8,
        "gross_annual_income_gbp": 32000.0,
        "net_monthly_pay_gbp": 2200.0,
        "tax_code": "BR",
        "payslips_verified": False,
        "bank_statements_cross_verified": False,
        "notes": "Inconsistent payslips and contractor gaps."
    }
}


# ============================================================================
# 2. MCP INTEGRATION LAYER (Third-Party Credit Reference Agency)
# ============================================================================

def call_mcp_sync(tool_name: str, arguments: Dict[str, Any]) -> Any:
    """Call an allow-listed CRA tool through the authenticated network gateway."""
    if tool_name != "get_credit_report":
        raise ValueError(f"Unsupported CRA tool: {tool_name}")
    gateway_url = os.getenv("CRA_MCP_GATEWAY_URL")
    token_file = os.getenv("CRA_AGENT_JWT_FILE")
    if not gateway_url:
        raise RuntimeError("CRA_MCP_GATEWAY_URL is required; direct CRA calls are disabled.")
    if not token_file:
        raise RuntimeError("CRA_AGENT_JWT_FILE is required; direct CRA calls are disabled.")
    parsed_url = urlsplit(gateway_url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
        raise RuntimeError("CRA_MCP_GATEWAY_URL must be an absolute HTTP(S) URL.")
    if parsed_url.scheme != "https" and parsed_url.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise RuntimeError("HTTPS is required for the CRA gateway outside loopback.")
    try:
        with open(token_file, "r", encoding="utf-8") as token_handle:
            token = token_handle.read().strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("Unable to read the configured CRA agent token file.") from exc
    if not token:
        raise RuntimeError("CRA agent token file is empty.")
    request_body = json.dumps({
        "tool_name": tool_name,
        "arguments": arguments,
    }).encode("utf-8")
    request = urllib.request.Request(
        gateway_url.rstrip("/") + "/v1/tools/call",
        data=request_body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    ca_file = os.getenv("CRA_GATEWAY_CA_FILE")
    tls_context = ssl.create_default_context(cafile=ca_file) if ca_file else None
    try:
        with urllib.request.urlopen(request, timeout=10, context=tls_context) as response:
            response_body = response.read(128 * 1024 + 1)
            if len(response_body) > 128 * 1024:
                raise RuntimeError("CRA MCP gateway response exceeded the size limit.")
            if response.status != 200:
                raise RuntimeError(f"CRA MCP gateway returned HTTP {response.status}.")
            result = json.loads(response_body)
            if not isinstance(result, dict) or "result" not in result:
                raise RuntimeError("CRA MCP gateway returned an invalid response.")
            return result["result"]
    except urllib.error.HTTPError as exc:
        exc.close()
        raise RuntimeError(f"CRA MCP gateway rejected the request (HTTP {exc.code}).") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("CRA MCP gateway is unavailable.") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("CRA MCP gateway returned invalid JSON.") from exc


def mortgage_action_policy_allows(
    *,
    requested_loan_amount_gbp: float,
    affordability_passed: bool,
    is_standard_profile: bool,
    adverse_credit_flags: int,
) -> bool:
    """Use the authenticated gateway/OPA policy or an explicit local mock policy."""
    mode = os.getenv("MORTGAGE_ACTION_POLICY_MODE", "mock").lower()
    arguments = {
        "requested_loan_amount_gbp": requested_loan_amount_gbp,
        "affordability_passed": affordability_passed,
        "is_standard_profile": is_standard_profile,
        "adverse_credit_flags": adverse_credit_flags,
    }
    if mode == "mock":
        return (
            _is_finite_number(requested_loan_amount_gbp)
            and requested_loan_amount_gbp > 0
            and requested_loan_amount_gbp <= HUMAN_MANDATE_ESCALATION_THRESHOLD_GBP
            and affordability_passed is True
            and is_standard_profile is True
            and type(adverse_credit_flags) is int
            and adverse_credit_flags == 0
        )
    if mode != "external":
        raise RuntimeError("MORTGAGE_ACTION_POLICY_MODE must be 'mock' or 'external'.")

    gateway_url = os.getenv("CRA_MCP_GATEWAY_URL")
    token_file = os.getenv("CRA_AGENT_JWT_FILE")
    if not gateway_url or not token_file:
        raise RuntimeError("External mortgage policy requires the authenticated CRA gateway and agent JWT.")
    parsed_url = urlsplit(gateway_url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
        raise RuntimeError("CRA_MCP_GATEWAY_URL must be an absolute HTTP(S) URL.")
    if parsed_url.scheme != "https" and parsed_url.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise RuntimeError("HTTPS is required for the mortgage policy gateway outside loopback.")
    try:
        with open(token_file, "r", encoding="utf-8") as token_handle:
            token = token_handle.read().strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("Unable to read the configured CRA agent token file.") from exc
    if not token:
        raise RuntimeError("CRA agent token file is empty.")

    request = urllib.request.Request(
        gateway_url.rstrip("/") + "/v1/policies/mortgage-action",
        data=json.dumps(arguments).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    ca_file = os.getenv("CRA_GATEWAY_CA_FILE")
    tls_context = ssl.create_default_context(cafile=ca_file) if ca_file else None
    try:
        with urllib.request.urlopen(request, timeout=5, context=tls_context) as response:
            body = response.read(4097)
            if response.status != 200 or len(body) > 4096:
                raise RuntimeError("Mortgage action policy gateway returned an invalid response.")
            response_data = json.loads(body)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise RuntimeError(f"Mortgage action policy gateway rejected the request (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError("Mortgage action policy gateway is unavailable.") from exc
    if not isinstance(response_data, dict) or type(response_data.get("allowed")) is not bool:
        raise RuntimeError("Mortgage action policy gateway returned an invalid decision.")
    return response_data["allowed"]


@tool
def pull_credit_report_mcp(applicant_name: str, national_insurance_number: str) -> str:
    """Fetch a minimized credit summary from the CRA through the MCP boundary.
    
    Args:
        applicant_name: Full name of applicant.
        national_insurance_number: UK National Insurance Number.
    """
    report = call_mcp_sync(
        "get_credit_report",
        {
            "applicant_name": applicant_name,
            "national_insurance_number": national_insurance_number
        }
    )
    safe_report = {
        "status": (
            "SUCCESS"
            if isinstance(report, dict) and report.get("status") == "SUCCESS"
            else "MANUAL_REVIEW_REQUIRED"
        )
    }
    if isinstance(report, dict):
        for field in ("credit_score", "ccj_count", "defaults_count", "bankruptcies"):
            value = report.get(field)
            if isinstance(value, int) and not isinstance(value, bool):
                safe_report[field] = value
    return json.dumps(safe_report, indent=2)


# ============================================================================
# 3. INTERNAL LLOYDS BANKING TOOLS
# ============================================================================

@tool
def lookup_lloyds_account(account_number: str, sort_code: str = "30-90-89") -> str:
    """
    [INTERNAL TOOL] Returns only salary-credit, debt-commitment, and KYC status fields
    needed for assessment.
    
    Args:
        account_number: 8-digit UK account number.
        sort_code: 6-digit sort code (default: 30-90-89).
    """
    acc = account_number.strip()
    if acc in MOCK_LLOYDS_ACCOUNTS:
        data = MOCK_LLOYDS_ACCOUNTS[acc].copy()
        data["lookup_timestamp"] = datetime.now(timezone.utc).isoformat()
        data["status"] = "FOUND"
        return json.dumps(
            _project_fields(
                data,
                (
                    "status",
                    "average_monthly_salary_credit_gbp",
                    "existing_debt_commitments_monthly_gbp",
                    "kyc_verified",
                ),
            ),
            indent=2,
        )
    
    # Generic mock fallback
    return json.dumps({
        "status": "NOT_FOUND",
        "message": "Account not found in internal Lloyds customer database.",
    }, indent=2)

@tool
def ingest_applicant_documents(applicant_name: str, document_types: str = "payslips,bank_statements") -> str:
    """Extract the minimum verified income and employment fields needed for assessment.
    
    Args:
        applicant_name: Name of applicant.
        document_types: Comma-separated list of documents uploaded.
    """
    if applicant_name in MOCK_VERIFIED_DOCUMENTS:
        doc = MOCK_VERIFIED_DOCUMENTS[applicant_name].copy()
        doc["documents_analyzed"] = document_types.split(",")
        doc["ocr_confidence"] = 0.985
        doc["verification_status"] = "VERIFIED" if doc["payslips_verified"] else "FAILED_VERIFICATION"
        return json.dumps(
            _project_fields(
                doc,
                (
                    "employer_name",
                    "employment_type",
                    "employment_length_years",
                    "gross_annual_income_gbp",
                    "net_monthly_pay_gbp",
                    "payslips_verified",
                    "bank_statements_cross_verified",
                    "verification_status",
                ),
            ),
            indent=2,
        )

    return json.dumps({
        "verification_status": "MANUAL_REVIEW_REQUIRED",
        "payslips_verified": False,
        "bank_statements_cross_verified": False,
    }, indent=2)

@tool
def compute_affordability(
    gross_annual_income: float,
    requested_loan_amount: float,
    property_valuation: float,
    monthly_debt_commitments: float = 0.0,
    term_years: int = 25,
    stress_interest_rate_pct: float = 7.5
) -> str:
    """
    [AFFORDABILITY ENGINE TOOL] Calculates Loan-to-Income (LTI), Loan-to-Value (LTV),
    and regulatory affordability stress testing under Bank of England / FCA guidelines.
    
    Args:
        gross_annual_income: Verified annual gross income in GBP.
        requested_loan_amount: Requested mortgage borrowing in GBP.
        property_valuation: Agreed purchase price / property valuation in GBP.
        monthly_debt_commitments: Existing monthly debts (loans, credit cards, car finance).
        term_years: Loan term in years (standard 25).
        stress_interest_rate_pct: Stress interest rate percentage (e.g. 7.5%).
    """
    if gross_annual_income <= 0 or property_valuation <= 0:
        return json.dumps({"error": "Gross annual income and property valuation must be greater than 0."})

    # 1. Key Ratios
    lti_ratio = round(requested_loan_amount / gross_annual_income, 2)
    ltv_ratio_pct = round((requested_loan_amount / property_valuation) * 100, 2)
    deposit_amount_gbp = round(property_valuation - requested_loan_amount, 2)
    deposit_pct = round((deposit_amount_gbp / property_valuation) * 100, 2)

    # 2. Standard Payment vs Stressed Payment Calculation (monthly annuity formula)
    standard_rate = 0.045 / 12  # 4.5% standard variable/fixed estimate
    stress_rate = (stress_interest_rate_pct / 100.0) / 12
    n_months = term_years * 12

    # Monthly payment standard
    pmt_standard = requested_loan_amount * (standard_rate * (1 + standard_rate)**n_months) / ((1 + standard_rate)**n_months - 1)
    
    # Monthly payment stressed (at 7.5%)
    pmt_stressed = requested_loan_amount * (stress_rate * (1 + stress_rate)**n_months) / ((1 + stress_rate)**n_months - 1)

    # Net monthly estimated income (after ~28% effective tax)
    est_net_monthly = (gross_annual_income * 0.72) / 12
    
    # Benchmark basic living costs (ONS / Lloyds standard benchmark)
    living_cost_allowance = 1100.0 + (0.05 * est_net_monthly)
    
    # Affordability buffer under stress test
    disposable_surplus_stressed = est_net_monthly - monthly_debt_commitments - pmt_stressed - living_cost_allowance

    # Lloyds Policy Caps
    max_lti_allowed = 4.5
    max_ltv_allowed = 85.0
    
    lti_pass = lti_ratio <= max_lti_allowed
    ltv_pass = ltv_ratio_pct <= max_ltv_allowed
    stress_pass = disposable_surplus_stressed > 150.0  # Buffer of at least £150/mo under stress

    overall_affordability_pass = lti_pass and ltv_pass and stress_pass

    max_affordable_by_lti = gross_annual_income * max_lti_allowed
    max_affordable_by_ltv = property_valuation * (max_ltv_allowed / 100.0)
    max_recommendation = round(min(max_affordable_by_lti, max_affordable_by_ltv), 2)

    result = {
        "requested_loan_amount_gbp": requested_loan_amount,
        "property_valuation_gbp": property_valuation,
        "deposit_amount_gbp": deposit_amount_gbp,
        "deposit_pct": deposit_pct,
        "loan_to_income_ratio": lti_ratio,
        "lti_cap": max_lti_allowed,
        "lti_passed": lti_pass,
        "loan_to_value_pct": ltv_ratio_pct,
        "ltv_cap_pct": max_ltv_allowed,
        "ltv_passed": ltv_pass,
        "estimated_monthly_payment_standard_gbp": round(pmt_standard, 2),
        "stressed_monthly_payment_7_5pct_gbp": round(pmt_stressed, 2),
        "monthly_debt_commitments_gbp": monthly_debt_commitments,
        "surplus_under_stress_gbp": round(disposable_surplus_stressed, 2),
        "stress_test_passed": stress_pass,
        "overall_affordability_passed": overall_affordability_pass,
        "max_recommended_loan_gbp": max_recommendation
    }
    return json.dumps(result, indent=2)

@tool
def evaluate_decision_authority(
    applicant_name: str,
    requested_loan_amount: float,
    affordability_passed: bool,
    credit_score: int,
    is_standard_profile: bool,
    adverse_credit_flags: int = 0,
    lti_ratio: float = 4.0
) -> str:
    """
    [DECISION AUTHORITY TOOL] Applies prototype lending referral rules.
    It never approves or issues a Decision in Principle. Cases that meet the
    configured automated checks are held for authorized human review.
    
    Args:
        applicant_name: Full name.
        requested_loan_amount: Borrowing requested in GBP.
        affordability_passed: Boolean from compute_affordability.
        credit_score: Credit score (0-999).
        is_standard_profile: True if standard applicant, False if self-employed non-standard or contractor.
        adverse_credit_flags: Number of CCJs, defaults, or bankruptcies.
        lti_ratio: Loan-to-income ratio.
    """
    if (
        not _is_finite_number(requested_loan_amount)
        or requested_loan_amount <= 0
        or type(affordability_passed) is not bool
        or type(is_standard_profile) is not bool
        or isinstance(credit_score, bool)
        or not isinstance(credit_score, int)
        or not 0 <= credit_score <= 999
        or isinstance(adverse_credit_flags, bool)
        or not isinstance(adverse_credit_flags, int)
        or adverse_credit_flags < 0
        or not _is_finite_number(lti_ratio)
        or lti_ratio < 0
    ):
        raise ValueError("Decision-policy inputs are invalid.")

    decision = {
        "requested_loan_amount_gbp": requested_loan_amount,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "human_mandate_escalation_threshold_gbp": HUMAN_MANDATE_ESCALATION_THRESHOLD_GBP
    }
    try:
        policy_allowed = mortgage_action_policy_allows(
            requested_loan_amount_gbp=requested_loan_amount,
            affordability_passed=affordability_passed,
            is_standard_profile=is_standard_profile,
            adverse_credit_flags=adverse_credit_flags,
        )
        policy_unavailable = False
    except RuntimeError:
        policy_allowed = False
        policy_unavailable = True

    # 1. Hard disqualification / adverse credit
    if adverse_credit_flags > 0 or credit_score < MIN_STANDARD_CREDIT_SCORE:
        decision["outcome"] = "ESCALATE_TO_HUMAN_UNDERWRITER"
        decision["dip_status"] = "REFERRED"
        decision["escalation_tier"] = "Senior Credit Risk Underwriter"
        decision["escalation_reasons"] = [
            f"Adverse credit or sub-prime score: Score={credit_score} (min standard {MIN_STANDARD_CREDIT_SCORE}), Adverse flags={adverse_credit_flags}."
        ]
        decision["action_required"] = "Full manual underwrite and risk mitigation assessment required."
        return _validated_decision_json(decision)

    # 2. Affordability failure
    if not affordability_passed:
        decision["outcome"] = "ESCALATE_TO_HUMAN_UNDERWRITER"
        decision["dip_status"] = "REFERRED"
        decision["escalation_tier"] = "Mortgage Underwriter"
        decision["escalation_reasons"] = [
            f"Affordability stress test failed at requested loan of £{requested_loan_amount:,.2f}."
        ]
        decision["action_required"] = "Underwriter review of alternative term lengths or reduced borrowing amount."
        return _validated_decision_json(decision)

    # 3. Non-standard applicant category (e.g. contractor/complex income)
    if not is_standard_profile:
        decision["outcome"] = "ESCALATE_TO_HUMAN_UNDERWRITER"
        decision["dip_status"] = "REFERRED"
        decision["escalation_tier"] = "Specialist Underwriter"
        decision["escalation_reasons"] = [
            "Applicant profile classified as non-standard (e.g. self-employed/contractor/complex income)."
        ]
        decision["action_required"] = "Verify 2 years SA302 / tax calculations."
        return _validated_decision_json(decision)

    # 4. Limit check (£500,000 threshold)
    if requested_loan_amount > HUMAN_MANDATE_ESCALATION_THRESHOLD_GBP:
        decision["outcome"] = "ESCALATE_TO_HUMAN_UNDERWRITER"
        decision["dip_status"] = "REFERRED"
        decision["escalation_tier"] = "Senior Mortgage Mandate Underwriter"
        decision["escalation_reasons"] = [
            f"Requested loan amount £{requested_loan_amount:,.2f} exceeds the configured human-mandate escalation threshold of £{HUMAN_MANDATE_ESCALATION_THRESHOLD_GBP:,.2f}."
        ]
        decision["action_required"] = "Mandate sign-off required for loans exceeding £500,000."
        return _validated_decision_json(decision)

    if not policy_allowed:
        decision["outcome"] = "ESCALATE_TO_HUMAN_UNDERWRITER"
        decision["dip_status"] = "REFERRED"
        decision["escalation_tier"] = "Mortgage Underwriter"
        decision["escalation_reasons"] = [
            "The external mortgage action policy could not authorize this case."
            if policy_unavailable
            else "The mortgage action policy denied standard assessment; human review is required."
        ]
        decision["action_required"] = (
            "Policy service unavailable; do not assess or issue a DIP until an authorized "
            "underwriter reviews the case."
            if policy_unavailable
            else "Do not issue a DIP; refer the case to an authorized mortgage underwriter."
        )
        return _validated_decision_json(decision)

    # Passing automated checks is not an approval; require an authorized person.
    decision["outcome"] = "PENDING_HUMAN_REVIEW"
    decision["dip_status"] = "PENDING_REVIEW"
    decision["escalation_tier"] = "Authorized Mortgage Underwriter"
    decision["escalation_reasons"] = [
        "Automated checks passed; an authorized human must review and decide."
    ]
    decision["action_required"] = (
        "Do not issue or communicate a DIP until an authorized underwriter "
        "has completed and recorded the review."
    )
    return _validated_decision_json(decision)

@tool
def store_mortgage_application(application_payload_json: str) -> str:
    """
    [SECURE STORAGE TOOL] Persists the application in an authenticated, encrypted vault.
    
    Args:
        application_payload_json: Full JSON string containing all verified application data.
    """
    data = (
        json.loads(application_payload_json)
        if isinstance(application_payload_json, str)
        else application_payload_json
    )
    if not isinstance(data, dict):
        raise ValueError("Application payload must be a JSON object.")
    tenant_id = data.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("A tenant_id is required for mock row-level vault isolation.")

    # Ensure application metadata
    app_id = data.get("application_id") or f"APP-{uuid.uuid4().hex.upper()}"
    data["application_id"] = app_id
    data["stored_at"] = datetime.now(timezone.utc).isoformat()
    data["governance_status"] = "PROTOTYPE_NOT_CERTIFIED"

    cipher = _vault_cipher()
    records = _load_vault_records(cipher)
    records = [r for r in records if r.get("application_id") != app_id]
    records.append(data)
    _write_vault_records(records, cipher)

    return json.dumps({
        "status": "STORED_SUCCESSFULLY",
        "application_id": app_id,
        "vault_records_count": len(records),
        "encrypted": True,
        "governance_status": "PROTOTYPE_NOT_CERTIFIED",
        "message": "Application stored in the authenticated encrypted vault."
    }, indent=2)


# List of all available Keystone Tools
KEYSTONE_TOOLS = [
    pull_credit_report_mcp,
    lookup_lloyds_account,
    ingest_applicant_documents,
    compute_affordability,
    evaluate_decision_authority,
    store_mortgage_application
]
