"""Synthetic CRA dataset and private lookup used by the authenticated tool service."""

from typing import Dict, Any

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

def _get_credit_report(applicant_name: str, national_insurance_number: str) -> Dict[str, Any]:
    ni_cleaned = national_insurance_number.strip().upper()
    
    if ni_cleaned in MOCK_CRA_DATABASE:
        report = MOCK_CRA_DATABASE[ni_cleaned].copy()
        report["queried_name"] = applicant_name
        report["status"] = "SUCCESS"
        return report
    
    return {
        "status": "MANUAL_REVIEW_REQUIRED",
        "message": "No verified synthetic CRA record is available for this applicant.",
    }
