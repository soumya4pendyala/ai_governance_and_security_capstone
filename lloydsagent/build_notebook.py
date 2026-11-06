"""
Builds the complete mortgageagent.ipynb notebook.
"""

import json
import os

notebook = {
    "cells": [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# Lloyds Banking Group: Keystone AI Mortgage Agent\n",
                "### AI Governance, Security & Responsible Decisioning Architecture (Capstone Project)\n",
                "\n",
                "**Keystone** is an autonomous AI agent designed to guide UK mortgage applicants from initial inquiry to a Decision in Principle (DIP). Given the material financial and legal impact of lending decisions, Keystone is architected under strict FCA (Financial Conduct Authority) MCOB principles, Model Risk Management (MRM), and AI Governance guardrails.\n",
                "\n",
                "#### Key System Responsibilities\n",
                "1. **Conversational Intake**: Captures applicant details, requirements, and loan purpose in natural language.\n",
                "2. **Document Ingestion**: Verifies payslips, bank statements, and employment stability against fraud and OCR tampering.\n",
                "3. **Credit Check over MCP Layer**: Securely queries external Credit Reference Agencies (Experian / Equifax) via the **Model Context Protocol (MCP)** boundary.\n",
                "4. **Account Lookup**: Queries internal Lloyds account balances, transaction history, and living expenses via internal banking APIs.\n",
                "5. **Affordability & Stress Test**: Computes Loan-to-Income (LTI), Loan-to-Value (LTV), and Bank of England regulatory stress testing (at 7.5%).\n",
                "6. **Decision Authority & Escalation Guardrail**:\n",
                "   - Auto-issue Decision in Principle (DIP) **up to £500,000** for standard, prime applicants.\n",
                "   - Any loan **> £500,000** or with **non-standard/adverse factors** MUST escalate to a human underwriter.\n",
                "7. **Audit & Storage**: Securely archives PII, NI number, banking data, credit reports, and algorithmic rationale into an encrypted audit vault."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 1. Imports and Environment Setup\n",
                "import os\n",
                "import sys\n",
                "import json\n",
                "import asyncio\n",
                "from datetime import datetime, timezone\n",
                "from dotenv import load_dotenv\n",
                "\n",
                "# Ensure workspace directory is in python path\n",
                "sys.path.insert(0, os.path.abspath(\"..\"))\n",
                "\n",
                "load_dotenv(override=True)\n",
                "print(\"Environment loaded successfully.\")"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 2. The Model Context Protocol (MCP) Layer: External Credit Bureau\n",
                "Under Lloyds AI Security policy, external third-party services (such as Credit Reference Agencies) are accessed across an isolated **Model Context Protocol (MCP)** boundary. This ensures:\n",
                "- Strict protocol contract for tool discovery and execution.\n",
                "- Sandboxed data boundary between internal bank data and external bureau requests.\n",
                "- Complete audit logging of external calls."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 2. Inspecting the CRA FastMCP Server & Mock Bureau Data\n",
                "from lloydsagent.cra_mcp_server import cra_mcp, MOCK_CRA_DATABASE\n",
                "\n",
                "print(\"CRA FastMCP Server Name:\", cra_mcp.name)\n",
                "print(f\"Mock Bureau Records Loaded: {len(MOCK_CRA_DATABASE)} records (John Smith, Sarah Jenkins, Robert Taylor)\")\n",
                "for ni, rec in MOCK_CRA_DATABASE.items():\n",
                "    print(f\" - {rec['applicant_name']} (NI: {ni}) | Score: {rec['credit_score']} ({rec['score_band']}) | Risk: {rec['risk_category']}\")"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 3. Direct MCP Client Call Demonstration\n",
                "from lloydsagent.lloyds_tools import call_mcp_sync\n",
                "\n",
                "# Call Credit Reference Agency over Model Context Protocol (MCP)\n",
                "report_data = call_mcp_sync(\n",
                "    \"get_credit_report\",\n",
                "    {\"applicant_name\": \"John Smith\", \"national_insurance_number\": \"QQ123456C\"}\n",
                ")\n",
                "\n",
                "print(\"[MCP Response Payload Received from CRA Bureau]:\")\n",
                "print(json.dumps(report_data, indent=2))\n",
                "print(f\"\\nSuccessfully retrieved credit score: {report_data['credit_score']} ({report_data['score_band']})\")"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 3. Internal Lloyds Banking Tools & Decision Engine\n",
                "In addition to the external MCP layer, Keystone is equipped with internal tools:\n",
                "1. `lookup_lloyds_account`: Internal core-banking lookup for balances, salary credits, and commitments.\n",
                "2. `ingest_applicant_documents`: OCR extraction and payslip validation.\n",
                "3. `compute_affordability`: Regulatory stress test (7.5% interest) and LTI / LTV checks.\n",
                "4. `evaluate_decision_authority`: Lloyds policy enforcing the £500,000 auto-approval threshold and human escalation.\n",
                "5. `store_mortgage_application`: Application vault audit persistence."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 4. Inspecting Registered Keystone Tools\n",
                "from lloydsagent.lloyds_tools import (\n",
                "    KEYSTONE_TOOLS,\n",
                "    lookup_lloyds_account,\n",
                "    ingest_applicant_documents,\n",
                "    compute_affordability,\n",
                "    evaluate_decision_authority,\n",
                "    store_mortgage_application,\n",
                "    pull_credit_report_mcp\n",
                ")\n",
                "\n",
                "print(f\"Keystone has {len(KEYSTONE_TOOLS)} registered tools:\")\n",
                "for t in KEYSTONE_TOOLS:\n",
                "    print(f\" • {t.name}: {t.description.splitlines()[0]}\")"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 4. Affordability & Stress Testing Engine\n",
                "Let's test the affordability calculator directly:\n",
                "- Standard interest rate: 4.5%\n",
                "- Regulatory stress interest rate: 7.5% (Bank of England / FCA requirement)\n",
                "- LTI Cap: 4.5x gross income\n",
                "- LTV Cap: 85%"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 5. Affordability Calculation Test\n",
                "sample_affordability = compute_affordability.invoke({\n",
                "    \"gross_annual_income\": 70000.0,\n",
                "    \"requested_loan_amount\": 280000.0,\n",
                "    \"property_valuation\": 350000.0,\n",
                "    \"monthly_debt_commitments\": 220.0,\n",
                "    \"term_years\": 25,\n",
                "    \"stress_interest_rate_pct\": 7.5\n",
                "})\n",
                "\n",
                "print(sample_affordability)"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 5. Keystone Agent Execution Pipeline\n",
                "We now initialize the `KeystoneMortgageAgent`. The agent coordinates the entire journey:\n",
                "1. Parsing conversational applicant requests.\n",
                "2. Ingesting & cross-referencing payslips.\n",
                "3. Querying internal Lloyds customer history.\n",
                "4. Pulling credit bureau records over MCP.\n",
                "5. Performing FCA affordability stress tests.\n",
                "6. Enforcing lending authority limits (£500k auto-approval vs Human Underwriter referral).\n",
                "7. Persisting the immutable audit record to the secure vault."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 6. Initialize Keystone Mortgage Agent\n",
                "from lloydsagent.agent import KeystoneMortgageAgent\n",
                "\n",
                "keystone = KeystoneMortgageAgent()\n",
                "print(\"Keystone Agent successfully initialized with Governance Rules & MCP Layer.\")"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 6. Scenario 1: Standard Applicant (Auto-Approved DIP <= £500,000)\n",
                "- **Applicant:** John Smith\n",
                "- **Requested Loan:** £280,000\n",
                "- **Property Price:** £350,000 (80% LTV, 20% deposit)\n",
                "- **Income:** £70,000/yr (LTI = 4.0x, within 4.5x limit)\n",
                "- **Credit Score:** 825 (Excellent, 0 CCJs, 0 defaults)\n",
                "- **Expected Outcome:** **AUTO_ISSUED_DIP** (Under £500,000 auto-limit)"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 7. Run Scenario 1\n",
                "scenario_1 = keystone.run_assessment_pipeline(\n",
                "    applicant_name=\"John Smith\",\n",
                "    national_insurance_number=\"QQ123456C\",\n",
                "    account_number=\"12345678\",\n",
                "    requested_loan_amount=280000.0,\n",
                "    property_valuation=350000.0,\n",
                "    is_standard_profile=True\n",
                ")\n",
                "\n",
                "from IPython.display import display, Markdown\n",
                "display(Markdown(scenario_1[\"customer_message\"]))\n",
                "\n",
                "print(\"\\n--- Governance & Decision Metadata ---\")\n",
                "print(\"Decision Outcome:\", scenario_1[\"decision_data\"][\"outcome\"])\n",
                "print(\"DIP Reference:\", scenario_1[\"decision_data\"].get(\"dip_reference\"))\n",
                "print(\"Approved Borrowing: £\", f\"{scenario_1['decision_data'].get('approved_loan_amount_gbp'):,.2f}\")\n",
                "print(\"Governance Signoff:\", scenario_1[\"decision_data\"].get(\"governance_signoff\"))"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 7. Scenario 2: High-Value Applicant (> £500,000, Escalated to Human Underwriter)\n",
                "- **Applicant:** Sarah Jenkins\n",
                "- **Requested Loan:** £650,000 (Exceeds £500,000 AI threshold!)\n",
                "- **Property Price:** £850,000\n",
                "- **Income:** £160,000/yr (Affordability easily passes)\n",
                "- **Credit Score:** 860 (Excellent)\n",
                "- **Expected Outcome:** **ESCALATE_TO_HUMAN_UNDERWRITER** (Enforces Lloyds risk mandate)"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 8. Run Scenario 2\n",
                "scenario_2 = keystone.run_assessment_pipeline(\n",
                "    applicant_name=\"Sarah Jenkins\",\n",
                "    national_insurance_number=\"AB987654D\",\n",
                "    account_number=\"87654321\",\n",
                "    requested_loan_amount=650000.0,\n",
                "    property_valuation=850000.0,\n",
                "    is_standard_profile=True\n",
                ")\n",
                "\n",
                "display(Markdown(scenario_2[\"customer_message\"]))\n",
                "\n",
                "print(\"\\n--- Governance & Escalation Metadata ---\")\n",
                "print(\"Decision Outcome:\", scenario_2[\"decision_data\"][\"outcome\"])\n",
                "print(\"Escalation Tier:\", scenario_2[\"decision_data\"].get(\"escalation_tier\"))\n",
                "print(\"Escalation Reasons:\", scenario_2[\"decision_data\"].get(\"escalation_reasons\"))\n",
                "print(\"Action Required:\", scenario_2[\"decision_data\"].get(\"action_required\"))"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 8. Scenario 3: Non-Standard / Sub-Prime Applicant (Adverse Credit Escalation)\n",
                "- **Applicant:** Robert Taylor\n",
                "- **Requested Loan:** £150,000\n",
                "- **Property Price:** £200,000\n",
                "- **Credit Score:** 540 (Poor, 1 CCJ, 2 defaults)\n",
                "- **Expected Outcome:** **ESCALATE_TO_HUMAN_UNDERWRITER** (Credit Risk escalation)"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 9. Run Scenario 3\n",
                "scenario_3 = keystone.run_assessment_pipeline(\n",
                "    applicant_name=\"Robert Taylor\",\n",
                "    national_insurance_number=\"CD112233E\",\n",
                "    account_number=\"11223344\",\n",
                "    requested_loan_amount=150000.0,\n",
                "    property_valuation=200000.0,\n",
                "    is_standard_profile=False\n",
                ")\n",
                "\n",
                "display(Markdown(scenario_3[\"customer_message\"]))\n",
                "\n",
                "print(\"\\n--- Governance & Escalation Metadata ---\")\n",
                "print(\"Decision Outcome:\", scenario_3[\"decision_data\"][\"outcome\"])\n",
                "print(\"Escalation Tier:\", scenario_3[\"decision_data\"].get(\"escalation_tier\"))\n",
                "print(\"Escalation Reasons:\", scenario_3[\"decision_data\"].get(\"escalation_reasons\"))"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 9. Vault Storage & Audit Trail Inspection\n",
                "Every assessment made by Keystone is persisted into an immutable JSON vault storage file (`mortgage_applications_vault.json`) containing:\n",
                "- Complete applicant identifiers & verified documents\n",
                "- Account details & verified liquidity\n",
                "- Third-party Credit Reference Agency report pulled over MCP\n",
                "- Algorithmic stress-test parameters\n",
                "- Final decision authority signoff & human escalation tags"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 10. Read and Display Application Audit Records from Storage\n",
                "from lloydsagent.lloyds_tools import VAULT_STORAGE_FILE\n",
                "\n",
                "if os.path.exists(VAULT_STORAGE_FILE):\n",
                "    with open(VAULT_STORAGE_FILE, \"r\", encoding=\"utf-8\") as f:\n",
                "        records = json.load(f)\n",
                "    print(f\"Total Applications Stored in Vault: {len(records)}\\n\")\n",
                "    for r in records:\n",
                "        loan_amt = r.get('requested_loan_amount_gbp') or 0.0\n",
                "        decision_outcome = r.get('decision', {}).get('outcome') if isinstance(r.get('decision'), dict) else r.get('decision')\n",
                "        print(f\"• Application ID: {r.get('application_id')} | Applicant: {r.get('applicant_name')}\")\n",
                "        print(f\"  Loan Requested: £{loan_amt:,.2f} | Decision: {decision_outcome}\")\n",
                "        print(f\"  CRA Bureau Ref: {r.get('cra_credit_bureau', {}).get('bureau_ref')} (via MCP)\")\n",
                "        print(f\"  Compliance Certifications: {r.get('compliance_certifications')}\")\n",
                "        print(\"-\" * 70)"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 10. AI Governance, Security & Responsible AI Summary\n",
                "This implementation of Keystone directly adheres to key AI Governance principles:\n",
                "1. **Model Context Protocol (MCP) Boundary**: Protects bank network and applicant data by enforcing a strict client-server protocol for third-party CRA data access.\n",
                "2. **Human-in-the-Loop (HITL) Guardrails**: Automatically caps algorithmic autonomy at £500,000, ensuring high-exposure decisions receive human scrutiny.\n",
                "3. **FCA Consumer Duty Compliance**: Transparent explanation of affordability, stress tests, and referral reasons provided to applicants.\n",
                "4. **End-to-End Auditability**: Immutable persistent storage of all input data, intermediate tool outputs, and algorithmic conclusions."
            ]
        }
    ],
    "metadata": {
        "kernelspec": {
            "display_name": "Python (.venv)",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "codemirror_mode": {
                "name": "ipython",
                "version": 3
            },
            "file_extension": ".py",
            "mimetype": "text/x-python",
            "name": "python",
            "nbconvert_exporter": "python",
            "pygments_lexer": "ipython3",
            "version": "3.14.7"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 5
}

for i, cell in enumerate(notebook["cells"]):
    cell["id"] = f"cell-{i:03d}"

target_path = os.path.join(os.path.dirname(__file__), "mortgageagent.ipynb")
with open(target_path, "w", encoding="utf-8") as f:
    json.dump(notebook, f, indent=1)

print(f"Successfully generated {target_path} with {len(notebook['cells'])} cells.")
