"""
Lloyds Keystone AI Agent Implementation
----------------------------------------
Implements the Keystone Mortgage Agent with:
- Conversational system prompt and persona
- LangChain tool calling bindings
- Autonomous assessment pipeline orchestrator
- Robust dual-mode execution (Live LLM via LangChain if API key available, 
  with seamless governance/fallback orchestration for local sandbox testing)
"""

import os
import json
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
from langchain.agents import create_agent
from lloydsagent.lloyds_tools import (
    KEYSTONE_TOOLS,
    pull_credit_report_mcp,
    lookup_lloyds_account,
    ingest_applicant_documents,
    compute_affordability,
    evaluate_decision_authority,
    store_mortgage_application
)

load_dotenv(override=True)

KEYSTONE_SYSTEM_PROMPT = """
You are Keystone, Lloyds Banking Group's flagship AI Mortgage Agent.
Your role is to guide customers through the mortgage application journey from first inquiry 
to a Decision in Principle (DIP).

CRITICAL GOVERNANCE & DECISION AUTHORITY RULES:
1. DATA BOUNDARIES:
   - Use 'lookup_lloyds_account' ONLY for existing Lloyds internal customer records.
   - Use 'pull_credit_report_mcp' to retrieve third-party Credit Reference Agency reports via the MCP layer.
   - Use 'ingest_applicant_documents' to cross-verify payslips and bank statement income.
2. AFFORDABILITY & STRESS TESTING:
   - Always call 'compute_affordability' to evaluate Loan-to-Income (LTI max 4.5x), Loan-to-Value (LTV max 85%), 
     and FCA regulatory stress tests (at 7.5% interest rate).
3. DECISION AUTHORITY & HUMAN ESCALATION:
   - Standard applicants requesting borrowing <= £500,000 may be AUTO-ISSUED a Decision in Principle.
   - ANY application requesting > £500,000 MUST be ESCALATED to a Human Mortgage Underwriter.
   - ANY applicant with adverse credit (CCJs, defaults, score < 700) or non-standard employment MUST be ESCALATED.
4. AUDIT & STORAGE:
   - Always persist the finalized application payload, verified income, NI number, account details, 
     and credit bureau findings into the vault using 'store_mortgage_application'.
5. TONE:
   - Professional, empathetic, transparent, and compliant with FCA Consumer Duty and MCOB regulations.
"""

class KeystoneMortgageAgent:
    """
    Keystone Agent Controller supporting both LangChain LLM execution and
    structured AI governance pipeline orchestration.
    """
    def __init__(self, model_name: Optional[str] = None):
        self.system_prompt = KEYSTONE_SYSTEM_PROMPT.strip()
        self.tools = KEYSTONE_TOOLS
        self.model_name = model_name or os.getenv("LLM_MODEL", "openai:gpt-4o-mini")
        self.agent_graph = None
        self._init_llm_agent()

    def _init_llm_agent(self):
        """Attempts to initialize standard LangChain agent if valid LLM configuration exists."""
        try:
            # Check if an API key is available
            openai_key = os.getenv("OPENAI_API_KEY", "")
            groq_key = os.getenv("GROQ_API_KEY", "")
            anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")

            if openai_key.startswith("sk-") and len(openai_key) > 30 and not "WAPkXc" in openai_key:
                self.agent_graph = create_agent(
                    model=self.model_name,
                    tools=self.tools,
                    system_prompt=self.system_prompt
                )
            elif groq_key:
                self.agent_graph = create_agent(
                    model="groq:llama-3.3-70b-versatile",
                    tools=self.tools,
                    system_prompt=self.system_prompt
                )
        except Exception as e:
            # Fall back to structured autonomous pipeline
            self.agent_graph = None

    def run_assessment_pipeline(
        self,
        applicant_name: str,
        national_insurance_number: str,
        account_number: str,
        requested_loan_amount: float,
        property_valuation: float,
        is_standard_profile: bool = True
    ) -> Dict[str, Any]:
        """
        Executes Keystone's full end-to-end mortgage assessment pipeline, executing
        all required tool calls, enforcing MCP layer boundary, applying decision authority limits,
        and persisting full audit records.
        """
        audit_trail: List[Dict[str, Any]] = []

        # -------------------------------------------------------------
        # Step 1: Document Ingestion (Payslips & Verification)
        # -------------------------------------------------------------
        doc_raw = ingest_applicant_documents.invoke({"applicant_name": applicant_name})
        doc_data = json.loads(doc_raw)
        audit_trail.append({"step": "Document Ingestion", "tool": "ingest_applicant_documents", "result": doc_data})

        # -------------------------------------------------------------
        # Step 2: Internal Account Lookup (Lloyds Customer History)
        # -------------------------------------------------------------
        acc_raw = lookup_lloyds_account.invoke({"account_number": account_number})
        acc_data = json.loads(acc_raw)
        audit_trail.append({"step": "Internal Account Lookup", "tool": "lookup_lloyds_account", "result": acc_data})

        # -------------------------------------------------------------
        # Step 3: Credit Check over MCP Layer (Third-Party CRA)
        # -------------------------------------------------------------
        cra_raw = pull_credit_report_mcp.invoke({
            "applicant_name": applicant_name,
            "national_insurance_number": national_insurance_number
        })
        cra_data = json.loads(cra_raw)
        audit_trail.append({"step": "Credit Check (over MCP)", "tool": "pull_credit_report_mcp", "result": cra_data})

        # -------------------------------------------------------------
        # Step 4: Affordability & Stress Test
        # -------------------------------------------------------------
        gross_income = doc_data.get("gross_annual_income_gbp", 50000.0)
        debt_commitments = acc_data.get("existing_debt_commitments_monthly_gbp", 0.0)

        affordability_raw = compute_affordability.invoke({
            "gross_annual_income": gross_income,
            "requested_loan_amount": requested_loan_amount,
            "property_valuation": property_valuation,
            "monthly_debt_commitments": debt_commitments,
            "term_years": 25,
            "stress_interest_rate_pct": 7.5
        })
        affordability_data = json.loads(affordability_raw)
        audit_trail.append({"step": "Affordability Calculation", "tool": "compute_affordability", "result": affordability_data})

        # -------------------------------------------------------------
        # Step 5: Decision Authority & Governance Evaluation
        # -------------------------------------------------------------
        credit_score = cra_data.get("credit_score", 700)
        adverse_flags = cra_data.get("ccj_count", 0) + cra_data.get("defaults_count", 0)
        aff_pass = affordability_data.get("overall_affordability_passed", False)
        lti_val = affordability_data.get("loan_to_income_ratio", 4.0)

        decision_raw = evaluate_decision_authority.invoke({
            "applicant_name": applicant_name,
            "requested_loan_amount": requested_loan_amount,
            "affordability_passed": aff_pass,
            "credit_score": credit_score,
            "is_standard_profile": is_standard_profile and (doc_data.get("verification_status") == "VERIFIED"),
            "adverse_credit_flags": adverse_flags,
            "lti_ratio": lti_val
        })
        decision_data = json.loads(decision_raw)
        audit_trail.append({"step": "Decision Authority Evaluation", "tool": "evaluate_decision_authority", "result": decision_data})

        # -------------------------------------------------------------
        # Step 6: Secure Application Storage & Audit Persistence
        # -------------------------------------------------------------
        application_payload = {
            "applicant_name": applicant_name,
            "national_insurance_number": national_insurance_number,
            "account_number": account_number,
            "requested_loan_amount_gbp": requested_loan_amount,
            "property_valuation_gbp": property_valuation,
            "verified_employment": doc_data,
            "lloyds_account_summary": {
                "tier": acc_data.get("relationship_tier"),
                "savings_balance": acc_data.get("savings_balance_gbp"),
                "tenure_years": acc_data.get("tenure_years")
            },
            "cra_credit_bureau": {
                "bureau_ref": cra_data.get("bureau_reference"),
                "score": credit_score,
                "score_band": cra_data.get("score_band"),
                "risk_category": cra_data.get("risk_category")
            },
            "affordability_assessment": affordability_data,
            "decision": decision_data
        }

        storage_raw = store_mortgage_application.invoke({
            "application_payload_json": json.dumps(application_payload)
        })
        storage_data = json.loads(storage_raw)
        audit_trail.append({"step": "Secure Storage", "tool": "store_mortgage_application", "result": storage_data})

        # Formulate customer-facing message
        if decision_data.get("outcome") == "AUTO_ISSUED_DIP":
            customer_message = (
                f"### Decision in Principle: APPROVED (Auto-Issued)\n\n"
                f"Dear **{applicant_name}**,\n\n"
                f"Good news! We have successfully assessed your application using verified payslips, "
                f"your Lloyds banking history, and your credit bureau report received via our secure CRA MCP service.\n\n"
                f"- **Decision in Principle Reference:** `{decision_data.get('dip_reference')}`\n"
                f"- **Approved Borrowing Amount:** £{requested_loan_amount:,.2f}\n"
                f"- **Loan-to-Value (LTV):** {affordability_data.get('loan_to_value_pct')}%\n"
                f"- **Loan-to-Income (LTI):** {affordability_data.get('loan_to_income_ratio')}x\n"
                f"- **Indicative Interest Rate:** {decision_data.get('indicative_interest_rate_pct')}%\n"
                f"- **Certificate Validity:** Valid for 90 days (until {decision_data.get('certificate_valid_until')})\n\n"
                f"Your full application and credit bureau verification have been securely archived in Lloyds Audit Storage."
            )
        else:
            reasons_bullet = "\n".join([f"- {r}" for r in decision_data.get("escalation_reasons", [])])
            customer_message = (
                f"### Application Referral: Escalated to Human Underwriter\n\n"
                f"Dear **{applicant_name}**,\n\n"
                f"Thank you for submitting your mortgage details. In line with Lloyds AI Governance and Lending Mandates, "
                f"your application has been referred for review by our **{decision_data.get('escalation_tier')}**.\n\n"
                f"**Reason(s) for Underwriter Escalation:**\n{reasons_bullet}\n\n"
                f"- **Next Steps:** {decision_data.get('action_required')}\n"
                f"- **Estimated Review Time:** Within 1-2 business days. A human mortgage specialist will contact you directly."
            )

        return {
            "customer_message": customer_message,
            "decision_data": decision_data,
            "affordability_data": affordability_data,
            "cra_data": cra_data,
            "storage_data": storage_data,
            "audit_trail": audit_trail
        }

