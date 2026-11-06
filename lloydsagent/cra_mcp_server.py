"""
Credit Reference Agency (CRA) MCP Server
-----------------------------------------
This module provides a Model Context Protocol (MCP) server representing an
external third-party Credit Reference Agency (e.g. Experian / Equifax / TransUnion).
Keystone interacts with this external boundary strictly over the MCP protocol.
"""

from fastmcp import FastMCP
from typing import Dict, Any

# Initialize FastMCP Server for Credit Reference Agency
cra_mcp = FastMCP(
    name="CreditReferenceAgency-MCP",
)

# Mock CRA Bureau Database
MOCK_CRA_DATABASE: Dict[str, Dict[str, Any]] = {
    "QQ123456C": {
        "applicant_name": "John Smith",
        "national_insurance_number": "QQ123456C",
        "credit_score": 825,
        "score_band": "Excellent",
        "score_range": "0-999",
        "active_credit_accounts": 2,
        "credit_utilization_pct": 12.5,
        "ccj_count": 0,
        "defaults_count": 0,
        "bankruptcies": 0,
        "electoral_roll_registered": True,
        "electoral_roll_years": 4,
        "delinquencies_24m": 0,
        "risk_category": "Standard - Low Risk",
        "bureau_reference": "EXP-2026-889104"
    },
    "AB987654D": {
        "applicant_name": "Sarah Jenkins",
        "national_insurance_number": "AB987654D",
        "credit_score": 860,
        "score_band": "Excellent",
        "score_range": "0-999",
        "active_credit_accounts": 3,
        "credit_utilization_pct": 14.0,
        "ccj_count": 0,
        "defaults_count": 0,
        "bankruptcies": 0,
        "electoral_roll_registered": True,
        "electoral_roll_years": 6,
        "delinquencies_24m": 0,
        "risk_category": "Standard - Low Risk",
        "bureau_reference": "EXP-2026-992134"
    },
    "CD112233E": {
        "applicant_name": "Robert Taylor",
        "national_insurance_number": "CD112233E",
        "credit_score": 540,
        "score_band": "Poor",
        "score_range": "0-999",
        "active_credit_accounts": 5,
        "credit_utilization_pct": 82.0,
        "ccj_count": 1,
        "ccj_details": [{"amount_gbp": 1250, "registered_months_ago": 18, "satisfied": False}],
        "defaults_count": 2,
        "bankruptcies": 0,
        "electoral_roll_registered": False,
        "delinquencies_24m": 4,
        "risk_category": "Non-Standard - High Risk",
        "bureau_reference": "EXP-2026-331092"
    }
}

@cra_mcp.tool()
def get_credit_report(applicant_name: str, national_insurance_number: str) -> Dict[str, Any]:
    """
    Pulls the applicant's official credit file and risk score from the Credit Reference Agency.
    
    Args:
        applicant_name: Full legal name of the mortgage applicant.
        national_insurance_number: UK National Insurance Number (e.g. QQ123456C).
        
    Returns:
        Structured credit report containing credit score, active accounts, CCJs, defaults,
        and electoral roll status.
    """
    ni_cleaned = national_insurance_number.strip().upper()
    
    if ni_cleaned in MOCK_CRA_DATABASE:
        report = MOCK_CRA_DATABASE[ni_cleaned].copy()
        report["queried_name"] = applicant_name
        report["status"] = "SUCCESS"
        return report
    
    # Generic synthetic fallback for arbitrary applicant
    return {
        "status": "SUCCESS",
        "applicant_name": applicant_name,
        "national_insurance_number": ni_cleaned,
        "credit_score": 750,
        "score_band": "Good",
        "score_range": "0-999",
        "active_credit_accounts": 2,
        "credit_utilization_pct": 20.0,
        "ccj_count": 0,
        "defaults_count": 0,
        "bankruptcies": 0,
        "electoral_roll_registered": True,
        "electoral_roll_years": 2,
        "delinquencies_24m": 0,
        "risk_category": "Standard - Moderate Risk",
        "bureau_reference": f"EXP-2026-{abs(hash(ni_cleaned)) % 1000000:06d}"
    }

@cra_mcp.tool()
def verify_identity(national_insurance_number: str, date_of_birth: str, current_postcode: str) -> Dict[str, Any]:
    """
    Verifies the applicant's identity against electoral roll and credit agency identity records.
    
    Args:
        national_insurance_number: UK National Insurance Number.
        date_of_birth: Date of birth (YYYY-MM-DD).
        current_postcode: UK residential postcode.
    """
    return {
        "status": "VERIFIED",
        "national_insurance_number": national_insurance_number.strip().upper(),
        "identity_confidence_score": 0.99,
        "aml_pep_sanctions_clear": True,
        "electoral_roll_match": True,
        "address_history_verified_years": 5
    }

if __name__ == "__main__":
    # When run directly, start stdio MCP server
    cra_mcp.run()

