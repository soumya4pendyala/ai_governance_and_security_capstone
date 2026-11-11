"""Illustrative AI risk classification and risk-register scoring for Keystone."""

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RegulatoryObligation:
    obligation_id: str
    framework: str
    provision: str
    purpose: str
    evidence_found: tuple[str, ...]
    status: str
    required_actions: tuple[str, ...]
    owner: str
    caveat: str

    def __post_init__(self) -> None:
        if self.status not in {"PARTIAL", "GAP", "DRAFT_ONLY", "NOT_ASSESSED"}:
            raise ValueError("Regulatory obligation status is not a supported evidence state.")
        if not self.obligation_id.strip() or not self.framework.strip() or not self.owner.strip():
            raise ValueError("Regulatory obligation ID, framework, and owner are required.")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_regulatory_obligations_register() -> list[dict[str, Any]]:
    """Return a repository-evidence map; it is not legal advice or a compliance finding."""
    obligations = [
        RegulatoryObligation(
            "UKGDPR-ART35",
            "UK GDPR",
            "Article 35 — Data Protection Impact Assessment",
            "Assess high-risk processing before it starts, including necessity, proportionality, risks to people, and mitigations.",
            (),
            "GAP",
            (
                "Complete a controller-led DPIA covering purposes, data flows, necessity/proportionality, affected people, risks, mitigations, residual risk, and consultation.",
                "Obtain DPO advice and record the controller's approval; consult the ICO before processing if high residual risk cannot be mitigated.",
            ),
            "Controller / Data Protection Officer",
            "A code register cannot make the controller's risk assessment or determine whether prior ICO consultation is required.",
        ),
        RegulatoryObligation(
            "UKGDPR-ART30",
            "UK GDPR",
            "Article 30 — Records of Processing Activities",
            "Maintain the controller's and, where applicable, processor's records of purposes, data subjects/data, recipients, transfers, retention, and security measures.",
            ("Prototype code identifies synthetic applicant/account/credit data flows and an encrypted vault.",),
            "GAP",
            (
                "Create and approve controller and processor RoPA entries with legal entity names, purposes, categories, recipients, transfers, retention/deletion periods, and security measures.",
                "Confirm controller/processor roles and keep the records current when providers, purposes, or data flows change.",
            ),
            "Controller / Data Protection Officer",
            "The repository does not establish the real legal entities, processing purposes, retention schedule, international transfers, or lawful basis.",
        ),
        RegulatoryObligation(
            "UKGDPR-LAWFUL-BASIS",
            "UK GDPR",
            "Articles 6 and, if special-category data is processed, 9; Data Protection Act 2018 as applicable",
            "Identify and document a valid lawful basis for each purpose and any additional condition for special-category data.",
            (),
            "GAP",
            (
                "Determine and document the lawful basis separately for each processing purpose, including credit checks, profiling, storage, and model evaluation.",
                "Assess whether any special-category data is collected or inferred; if so, identify the applicable Article 9 condition and DPA 2018 requirements.",
                "Document transparency, compatibility/purpose-limitation, data minimization, and rights handling with legal/DPO approval.",
            ),
            "Controller / Legal / Data Protection Officer",
            "Lawful basis is a fact-specific controller decision; it cannot be selected or proved by application code.",
        ),
        RegulatoryObligation(
            "UKGDPR-ART28",
            "UK GDPR",
            "Article 28 — Processor terms and safeguards",
            "Use processors providing sufficient guarantees and bind them with required written processing terms and instructions.",
            ("A custom CRA gateway and synthetic CRA service are implemented; no production CRA contract or DPA is present.",),
            "GAP",
            (
                "Identify the actual CRA, cloud/model, hosting, and support providers and determine controller/processor or joint-controller roles for each activity.",
                "Complete security/privacy due diligence and execute Article 28-compliant processor terms, including instructions, confidentiality, security, subprocessors, assistance, deletion/return, and audit rights.",
                "Review international transfer mechanisms and subprocessor chains where applicable.",
            ),
            "Controller Procurement / Legal / Data Protection Officer",
            "A technical gateway does not establish processor compliance, contractual safeguards, or a valid data-sharing arrangement.",
        ),
        RegulatoryObligation(
            "EUAI-HIGH-RISK",
            "EU AI Act",
            "High-risk obligations: Articles 9–15 and 17; deployer duties and other applicable provisions to be scoped",
            "Translate the preliminary creditworthiness screen into a controlled obligation-by-obligation evidence and conformity plan.",
            (
                "Preliminary creditworthiness classification and illustrative risk register in governance.py.",
                "Prototype evidence for selected risk, logging, transparency, human-oversight, and cybersecurity controls.",
            ),
            "PARTIAL",
            (
                "Legal counsel must confirm scope, roles, dates, classification, exceptions, and the applicable conformity route.",
                "Complete and approve evidence for risk management; data governance; technical documentation; logging; instructions/transparency; human oversight; accuracy, robustness and cybersecurity; and quality management.",
                "Assess registration, conformity assessment, declaration/marking, post-market monitoring, incident reporting, deployer duties, and fundamental-rights impact assessment where applicable.",
            ),
            "Provider / Deployer / AI Governance / Legal",
            "This repository screen is not a legal determination, conformity assessment, or demonstration that all duties apply or are met.",
        ),
        RegulatoryObligation(
            "FCA-CONSUMER-DUTY",
            "FCA",
            "PRIN 2A — Consumer Duty (including cross-cutting rules and four outcomes, where applicable)",
            "Design and evidence good outcomes for retail customers, avoid foreseeable harm, and support customer understanding and needs.",
            ("Draft go-live pack proposes monitoring, complaints, appeals, and incident responses.",),
            "DRAFT_ONLY",
            (
                "Map the actual product/service and customer journey to applicable Consumer Duty scope and responsibilities.",
                "Evidence outcomes for products/services, price and value, consumer understanding, and consumer support using representative customer testing and outcome monitoring.",
                "Assign accountable owners and evidence board/governing-body review, remediation, and support for customers in vulnerable circumstances.",
            ),
            "FCA-regulated firm / Consumer Duty Champion / Product Owner",
            "A stress-test formula or prototype escalation is not evidence of Consumer Duty compliance or good customer outcomes.",
        ),
        RegulatoryObligation(
            "FCA-MCOB",
            "FCA",
            "MCOB — applicable mortgage conduct, affordability, advice/sales, disclosure, and record-keeping requirements",
            "Determine which mortgage rules apply to the product, sales channel, lender/intermediary role, and customer journey; evidence the required controls.",
            ("Prototype affordability calculation and referral thresholds are present; no approved rule mapping or validated policy evidence was found.",),
            "PARTIAL",
            (
                "Compliance must map the actual permissions, regulated activities, mortgage type, advice/sales model, and customer journey to the applicable MCOB provisions.",
                "Validate affordability and creditworthiness controls against current applicable FCA rules and firm policy using representative data and independently reviewed tests.",
                "Evidence required disclosures, advice/suitability responsibilities where applicable, customer communications, record keeping, and exceptions/referrals.",
            ),
            "Mortgage Compliance / Product Owner",
            "Prototype LTI/LTV caps and a fixed stress rate are not a complete MCOB control set and must not be presented as FCA-approved rules.",
        ),
        RegulatoryObligation(
            "FCA-SYSC-SMCR",
            "FCA / UK Senior Managers and Certification Regime",
            "Applicable SYSC governance, systems-and-controls, records, outsourcing and risk-management requirements; SMCR responsibilities and Conduct Rules",
            "Establish accountable governance, competent roles, effective controls, escalation, records, and clear responsibility for the system and its risks.",
            ("Functional owner proposals and a demo assignee are documented; no named accountable SMF owner, responsibility map, or approved control framework is evidenced.",),
            "GAP",
            (
                "Confirm the firm's authorization and applicable SYSC/SMCR requirements with Compliance.",
                "Name the accountable Senior Management Function holder and document responsibilities, reasonable steps, delegation, escalation, and relevant Conduct Rules.",
                "Set competent operational, model-risk, data-protection, security, and compliance owners; approve policies, training, change control, monitoring, incident/complaint handling, and records.",
            ),
            "Firm Compliance / Named Senior Manager",
            "Soumya is the demo assignee only; this project record does not designate an SMF holder or establish reasonable steps.",
        ),
    ]
    return [obligation.to_dict() for obligation in obligations]


@dataclass(frozen=True)
class AIActClassification:
    category: str
    decision: str
    rationale: str
    follow_up: tuple[str, ...]
    human_oversight_required: bool
    caveat: str


def classify_eu_ai_act(
    *,
    evaluates_creditworthiness: bool,
    concerns_natural_person: bool = True,
    fraud_detection_only: bool = False,
    prohibited_practice: bool = False,
    safety_component: bool = False,
    materially_affects_decision: bool = True,
    profiling: bool = True,
) -> AIActClassification:
    """Apply a small, decision-tree-style screening; not a legal determination."""
    if prohibited_practice:
        return AIActClassification(
            category="prohibited-practice review",
            decision="STOP_AND_ESCALATE",
            rationale="The stated use may fall within a prohibited AI practice.",
            follow_up=("Obtain legal/compliance review before deployment.",),
            human_oversight_required=True,
            caveat="This screening cannot determine whether a legal prohibition applies.",
        )

    if safety_component:
        category = "potentially high-risk: regulated product safety component"
        rationale = "The system is described as a safety component of a regulated product."
        follow_up = (
            "Confirm the applicable product legislation and conformity-assessment route.",
            "Complete the required risk-management and human-oversight controls.",
        )
    elif evaluates_creditworthiness and concerns_natural_person and not fraud_detection_only:
        category = "high-risk: creditworthiness of natural persons"
        rationale = (
            "Assessing a natural person's creditworthiness is listed as a high-risk "
            "use under EU AI Act Annex III, subject to the Act's scope and applicable "
            "exceptions. The fraud-detection-only exception does not fit this purpose."
        )
        follow_up = (
            "Confirm the provider/deployer roles, territorial scope, and applicable dates.",
            "Complete the applicable high-risk-system obligations before deployment.",
            "Document the Article 6(3) exception analysis; profiling of natural persons "
            "is always treated as high-risk under that provision.",
            "Maintain risk management, data governance, logging, documentation, "
            "human oversight, accuracy, robustness, and cybersecurity evidence.",
            "Assess whether a fundamental-rights impact assessment is required.",
        )
    elif fraud_detection_only:
        category = "Annex III creditworthiness fraud-detection exception; review other routes"
        rationale = (
            "The supplied purpose is limited to financial-fraud detection, which is "
            "excluded from the Annex III creditworthiness category; other high-risk "
            "routes and legal obligations still need review."
        )
        follow_up = (
            "Document that the intended purpose is exclusively fraud detection.",
            "Screen the system against other high-risk categories and applicable laws.",
        )
    elif materially_affects_decision and profiling:
        category = "high-risk screening required"
        rationale = (
            "The system profiles people and materially affects a decision; assess "
            "whether Annex III or another high-risk route applies."
        )
        follow_up = (
            "Obtain documented legal/compliance classification before deployment.",
            "Assess human oversight, data governance, logging, and impact-assessment duties.",
        )
    else:
        category = "no high-risk route identified by this limited screen"
        rationale = (
            "The supplied answers do not identify the creditworthiness route or "
            "another route represented by this limited decision tree."
        )
        follow_up = ("Document the intended purpose and re-screen material changes.",)

    return AIActClassification(
        category=category,
        decision=(
            "HIGH_RISK"
            if category.startswith("high-risk:")
            else "HIGH_RISK_REVIEW"
            if category.startswith("potentially high-risk:")
            else "REVIEW"
        ),
        rationale=rationale,
        follow_up=follow_up,
        human_oversight_required=category.startswith(
            ("high-risk:", "potentially high-risk:")
        ),
        caveat=(
            "Illustrative governance screening only, not legal advice or a compliance "
            "certification. Confirm against the final intended purpose, deployment "
            "context, current law, and competent legal/compliance advice."
        ),
    )


@dataclass(frozen=True)
class Risk:
    risk_id: str
    title: str
    description: str
    likelihood: int
    impact: int
    current_controls: tuple[str, ...]
    residual_likelihood: int
    residual_impact: int
    recommended_actions: tuple[str, ...]
    owner: str

    def __post_init__(self) -> None:
        for field_name in ("likelihood", "impact", "residual_likelihood", "residual_impact"):
            score = getattr(self, field_name)
            if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 5:
                raise ValueError(f"{field_name} must be an integer from 1 to 5.")
        if not self.risk_id.strip() or not self.title.strip() or not self.owner.strip():
            raise ValueError("Risk ID, title, and owner are required.")

    @property
    def inherent_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def residual_score(self) -> int:
        return self.residual_likelihood * self.residual_impact

    @property
    def inherent_rating(self) -> str:
        return risk_rating(self.inherent_score)

    @property
    def residual_rating(self) -> str:
        return risk_rating(self.residual_score)

    def to_dict(self) -> dict[str, Any]:
        record = asdict(self)
        residual_rating = self.residual_rating
        record.update({
            "inherent_score": self.inherent_score,
            "inherent_rating": self.inherent_rating,
            "residual_score": self.residual_score,
            "residual_rating": residual_rating,
            "flagged": residual_rating in {"High", "Critical"},
            "action_status": (
                "ACTION_REQUIRED"
                if residual_rating in {"High", "Critical"}
                else "MONITOR"
            ),
        })
        return record


def risk_rating(score: int) -> str:
    """Map a 1–25 likelihood × impact score to a consistent rating band."""
    if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 25:
        raise ValueError("Risk score must be an integer from 1 to 25.")
    if score >= 17:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


def score_risk_register(risks: tuple[Risk, ...] | list[Risk]) -> list[dict[str, Any]]:
    """Return a highest-residual-risk-first register with explicit score fields."""
    if any(not isinstance(risk, Risk) for risk in risks):
        raise TypeError("Risk register entries must be Risk instances.")
    return [
        risk.to_dict()
        for risk in sorted(
            risks,
            key=lambda risk: (
                -risk.residual_score,
                -risk.inherent_score,
                risk.risk_id,
            ),
        )
    ]


def build_mortgage_risk_register() -> list[dict[str, Any]]:
    """Create the initial illustrative Keystone register; scores need owner validation."""
    risks = [
        Risk(
            "KMR-01",
            "Unfair or discriminatory lending outcomes",
            "Biased data, proxies, or decision logic could disadvantage protected groups.",
            4, 5,
            ("Human-underwriter escalation exists for defined adverse/high-value cases.",),
            4, 5,
            (
                "Validate outcomes across relevant groups using lawful, governed data.",
                "Document an independent fairness review and ongoing monitoring thresholds.",
            ),
            "Model Risk / Fair Lending",
        ),
        Risk(
            "KMR-02",
            "Incorrect or unsupported lending decision",
            "Model errors or weak evidence could cause financial harm or unsuitable outcomes.",
            4, 5,
            (
                "Affordability checks and referral rules are present.",
                "Automated DIP issuance is blocked; eligible cases remain pending for human review.",
            ),
            3, 5,
            (
                "Complete independent outcome validation and calibration.",
                "Implement authenticated, recorded human approval and keep the issuance block until decision performance is evidenced.",
            ),
            "Mortgage Product / Model Risk",
        ),
        Risk(
            "KMR-03",
            "Unauthorized disclosure or misuse of applicant data",
            "Personal and financial information could be exposed through prompts, tools, or storage.",
            4, 5,
            (
                "Local PII sanitization, minimized tool outputs, and encrypted vault storage.",
                "Scoped CRA gateway access and PII-minimized audit events.",
            ),
            2, 4,
            (
                "Test retention/deletion, access reviews, key rotation, and incident response.",
                "Verify production model/provider data handling and logging configuration.",
            ),
            "Data Protection / Security",
        ),
        Risk(
            "KMR-04",
            "Prompt injection or protected-record exfiltration",
            "Malicious instructions may attempt to bypass lending rules or expose records.",
            4, 5,
            (
                "Local injection pre-check, encoded-content scan, output canary, and attack patterns.",
                "Tool authorization and gateway allow-list constrain CRA actions.",
            ),
            2, 4,
            (
                "Expand adversarial testing and monitor false positives/negatives.",
                "Revalidate defenses after model, prompt, or tool changes.",
            ),
            "AI Security",
        ),
        Risk(
            "KMR-05",
            "Fraudulent or manipulated applicant evidence",
            "Forged documents or manipulated OCR could distort affordability assessments.",
            3, 5,
            (
                "Mock document-ingestion outputs are schema/status checked and screened for injected instructions before account or CRA calls.",
                "Income and affordability calculations use synthetic account and document fields; this is not issuer-authenticated evidence.",
            ),
            2, 4,
            (
                "Implement issuer-authenticated document provenance and independently validate income grounding against approved source records.",
                "Route missing, failed, or materially inconsistent verification to a human reviewer; do not treat mock verification flags as evidence.",
            ),
            "Financial Crime / Mortgage Operations",
        ),
        Risk(
            "KMR-06",
            "Unauthorized or excessive CRA access",
            "Credential compromise or overly broad access could expose bureau information.",
            3, 5,
            (
                "JWT verification, scoped short-lived delegation, OPA default-deny, and network isolation.",
            ),
            1, 5,
            (
                "Exercise credential rotation, policy change control, and production replay protection.",
            ),
            "Platform Security",
        ),
        Risk(
            "KMR-07",
            "Service outage or unsafe fallback",
            "Unavailable models, policy services, or data sources could interrupt or degrade processing.",
            3, 3,
            (
                "Gateway and sanitizer dependencies fail closed in covered paths.",
            ),
            2, 3,
            (
                "Test recovery objectives, alerting, and safe manual processing procedures.",
            ),
            "Mortgage Operations / SRE",
        ),
    ]
    return score_risk_register(risks)
