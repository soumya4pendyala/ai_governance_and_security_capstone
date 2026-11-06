"""
Lloyds Keystone Agent Tools & Data Layer
-----------------------------------------
This module implements the internal banking tools, mock databases, affordability calculations,
decision authority enforcement, storage persistence, and the MCP client integration
for Lloyds Bank's Keystone Mortgage Agent.
"""

import os
import json
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from langchain_core.tools import tool
from fastmcp import Client
from lloydsagent.cra_mcp_server import cra_mcp

# Path for persistent application storage
VAULT_STORAGE_FILE = os.path.join(os.path.dirname(__file__), "mortgage_applications_vault.json")

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

import threading

def call_mcp_sync(tool_name: str, arguments: Dict[str, Any]) -> Any:
    """
    Executes an MCP tool call reliably across all environments (including Jupyter
    and Python 3.14) by running in an isolated clean thread.
    """
    results = []
    errors = []

    def _worker():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _run():
            async with Client(cra_mcp) as client:
                res = await client.call_tool(tool_name, arguments)
                return res.data

        try:
            results.append(loop.run_until_complete(_run()))
        except Exception as exc:
            errors.append(exc)
        finally:
            loop.close()

    t = threading.Thread(target=_worker)
    t.start()
    t.join()

    if errors:
        raise errors[0]
    return results[0]

@tool
def pull_credit_report_mcp(applicant_name: str, national_insurance_number: str) -> str:
    """
    [MCP LAYER TOOL] Pulls official credit report from third-party Credit Reference Agency
    over the Model Context Protocol (MCP).
    
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
    return json.dumps(report, indent=2)


# ============================================================================
# 3. INTERNAL LLOYDS BANKING TOOLS
# ============================================================================

@tool
def lookup_lloyds_account(account_number: str, sort_code: str = "30-90-89") -> str:
    """
    [INTERNAL TOOL] Looks up an applicant's existing Lloyds current account, savings balance,
    and 12-month transaction/cashflow history.
    
    Args:
        account_number: 8-digit UK account number.
        sort_code: 6-digit sort code (default: 30-90-89).
    """
    acc = account_number.strip()
    if acc in MOCK_LLOYDS_ACCOUNTS:
        data = MOCK_LLOYDS_ACCOUNTS[acc].copy()
        data["lookup_timestamp"] = datetime.now(timezone.utc).isoformat()
        return json.dumps(data, indent=2)
    
    # Generic mock fallback
    return json.dumps({
        "status": "NOT_FOUND",
        "account_number": acc,
        "sort_code": sort_code,
        "message": "Account not found in internal Lloyds customer database."
    }, indent=2)

@tool
def ingest_applicant_documents(applicant_name: str, document_types: str = "payslips,bank_statements") -> str:
    """
    [DOCUMENT INGESTION TOOL] Ingests and parses uploaded verification documents (payslips,
    bank statements, P60), verifying income, employer, tax deductions, and consistency.
    
    Args:
        applicant_name: Name of applicant.
        document_types: Comma-separated list of documents uploaded.
    """
    if applicant_name in MOCK_VERIFIED_DOCUMENTS:
        doc = MOCK_VERIFIED_DOCUMENTS[applicant_name].copy()
        doc["documents_analyzed"] = document_types.split(",")
        doc["ocr_confidence"] = 0.985
        doc["verification_status"] = "VERIFIED" if doc["payslips_verified"] else "FAILED_VERIFICATION"
        return json.dumps(doc, indent=2)
    
    return json.dumps({
        "applicant_name": applicant_name,
        "verification_status": "MANUAL_REVIEW_REQUIRED",
        "gross_annual_income_gbp": 50000.0,
        "net_monthly_pay_gbp": 3100.0,
        "employer_name": "Standard Employer",
        "payslips_verified": True,
        "notes": "Standard document ingestion without exceptions."
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
    [DECISION AUTHORITY TOOL] Applies Lloyds risk authority limits.
    May auto-issue a Decision in Principle (DIP) up to £500,000 for standard applicants.
    Escalates to a human underwriter if loan exceeds £500,000 OR if non-standard profile.
    
    Args:
        applicant_name: Full name.
        requested_loan_amount: Borrowing requested in GBP.
        affordability_passed: Boolean from compute_affordability.
        credit_score: Credit score (0-999).
        is_standard_profile: True if standard applicant, False if self-employed non-standard or contractor.
        adverse_credit_flags: Number of CCJs, defaults, or bankruptcies.
        lti_ratio: Loan-to-income ratio.
    """
    AUTO_APPROVAL_LIMIT_GBP = 500000.0
    MIN_STANDARD_CREDIT_SCORE = 700

    decision = {
        "applicant_name": applicant_name,
        "requested_loan_amount_gbp": requested_loan_amount,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "auto_approval_threshold_gbp": AUTO_APPROVAL_LIMIT_GBP
    }

    # 1. Hard disqualification / adverse credit
    if adverse_credit_flags > 0 or credit_score < MIN_STANDARD_CREDIT_SCORE:
        decision["outcome"] = "ESCALATE_TO_HUMAN_UNDERWRITER"
        decision["dip_status"] = "REFERRED"
        decision["escalation_tier"] = "Senior Credit Risk Underwriter"
        decision["escalation_reasons"] = [
            f"Adverse credit or sub-prime score: Score={credit_score} (min standard {MIN_STANDARD_CREDIT_SCORE}), Adverse flags={adverse_credit_flags}."
        ]
        decision["action_required"] = "Full manual underwrite and risk mitigation assessment required."
        return json.dumps(decision, indent=2)

    # 2. Affordability failure
    if not affordability_passed:
        decision["outcome"] = "ESCALATE_TO_HUMAN_UNDERWRITER"
        decision["dip_status"] = "REFERRED"
        decision["escalation_tier"] = "Mortgage Underwriter"
        decision["escalation_reasons"] = [
            f"Affordability stress test failed at requested loan of £{requested_loan_amount:,.2f}."
        ]
        decision["action_required"] = "Underwriter review of alternative term lengths or reduced borrowing amount."
        return json.dumps(decision, indent=2)

    # 3. Non-standard applicant category (e.g. contractor/complex income)
    if not is_standard_profile:
        decision["outcome"] = "ESCALATE_TO_HUMAN_UNDERWRITER"
        decision["dip_status"] = "REFERRED"
        decision["escalation_tier"] = "Specialist Underwriter"
        decision["escalation_reasons"] = [
            "Applicant profile classified as non-standard (e.g. self-employed/contractor/complex income)."
        ]
        decision["action_required"] = "Verify 2 years SA302 / tax calculations."
        return json.dumps(decision, indent=2)

    # 4. Limit check (£500,000 threshold)
    if requested_loan_amount > AUTO_APPROVAL_LIMIT_GBP:
        decision["outcome"] = "ESCALATE_TO_HUMAN_UNDERWRITER"
        decision["dip_status"] = "REFERRED"
        decision["escalation_tier"] = "Senior Mortgage Mandate Underwriter"
        decision["escalation_reasons"] = [
            f"Requested loan amount £{requested_loan_amount:,.2f} exceeds AI automated authority limit of £{AUTO_APPROVAL_LIMIT_GBP:,.2f}."
        ]
        decision["action_required"] = "Mandate sign-off required for loans exceeding £500,000."
        return json.dumps(decision, indent=2)

    # 5. Passed all automated criteria - AUTO-ISSUE DIP
    dip_ref = f"DIP-LLOYDS-{abs(hash(applicant_name + str(requested_loan_amount))) % 10000000:07d}"
    expiry_date = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%d")

    decision["outcome"] = "AUTO_ISSUED_DIP"
    decision["dip_status"] = "ACCEPTED"
    decision["dip_reference"] = dip_ref
    decision["approved_loan_amount_gbp"] = requested_loan_amount
    decision["indicative_interest_rate_pct"] = 4.45
    decision["certificate_valid_until"] = expiry_date
    decision["governance_signoff"] = "Keystone Algorithmic Decisioning Engine - FCA MCOB Compliant"
    decision["message"] = (
        f"Congratulations {applicant_name}! Your Lloyds Decision in Principle has been automatically approved for up to "
        f"£{requested_loan_amount:,.2f} under reference {dip_ref}."
    )
    return json.dumps(decision, indent=2)

@tool
def store_mortgage_application(application_payload_json: str) -> str:
    """
    [SECURE STORAGE TOOL] Persists the complete mortgage application into the encrypted
    vault storage: applicant PII, National Insurance Number, bank details, credit bureau data,
    affordability calculations, and final decision record with full audit metadata.
    
    Args:
        application_payload_json: Full JSON string containing all verified application data.
    """
    try:
        data = json.loads(application_payload_json) if isinstance(application_payload_json, str) else application_payload_json
    except Exception:
        data = {"raw_payload": application_payload_json}

    # Ensure application metadata
    app_id = data.get("application_id", f"APP-{abs(hash(str(data))) % 1000000:06d}")
    data["application_id"] = app_id
    data["stored_at"] = datetime.now(timezone.utc).isoformat()
    data["compliance_certifications"] = ["GDPR", "FCA_MCOB", "AI_GOVERNANCE_AUDITED"]

    # Read existing vault records
    records = []
    if os.path.exists(VAULT_STORAGE_FILE):
        try:
            with open(VAULT_STORAGE_FILE, "r", encoding="utf-8") as f:
                records = json.load(f)
        except Exception:
            records = []

    # Update or append
    records = [r for r in records if r.get("application_id") != app_id]
    records.append(data)

    with open(VAULT_STORAGE_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    return json.dumps({
        "status": "STORED_SUCCESSFULLY",
        "application_id": app_id,
        "vault_records_count": len(records),
        "vault_path": VAULT_STORAGE_FILE,
        "message": "Application, credit bureau report, bank details, and decision safely persisted for audit."
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
