# Keystone Mortgage Agent — Governance Go-Live Pack

**Document type:** Assurance case, conformity evidence map, agent card, and
operations/oversight plan  
**Prepared:** 11 November 2026  
**Validation refresh:** 11 November 2026  
**Project demo assignee:** Soumya  
**Decision scope:** Proposed use of the Keystone mortgage-agent prototype for
customer mortgage affordability assessment and Decision in Principle (DIP)
recommendations  
**Status:** Internal governance draft — not an approval to deploy

> **Important:** This is a repository-based assessment, not legal advice,
> regulatory approval, or a formal conformity assessment. Risk ratings and
> proposed monitoring thresholds require validation by accountable business,
> risk, legal, privacy, and compliance owners.

---

## 1. Executive decision

### Recommendation: **DO NOT LAUNCH for live customer decisions**

Keystone has meaningful prototype security controls and some test evidence, but
the evidence currently available does not establish that the system is safe and
lawful for live mortgage decisioning. In particular:

- Automated DIP issuance has now been disabled in the shared decision tool and
  the mortgage assessment path; qualifying cases remain pending for an
  authorized human. However, the repository still has no authenticated
  underwriter workflow, recorded human approval/override, or evidence that
  review is meaningful and operational.
- No subgroup fairness/bias test results or approved lawful data-governance
  assessment were found.
- No complete, production-ready technical documentation or conformity record
  was found.
- Current audit events and application records do not yet demonstrate a
  complete, immutable, decision-reconstruction trail suitable for customer
  appeals and regulatory investigation.
- The CRA service is synthetic/mock data, not a production bureau connection.
- The assessment pipeline now fails closed to manual review when applicant
  documents, account/KYC, CRA fields, or affordability outputs are missing or
  invalid; unknown mock applicants are no longer assigned assumed income or a
  default credit score. This reduces unsafe fallback behavior but does not
  replace verified production connectors, source-quality controls, or human
  sign-off.
- Named accountable business and SMCR owners, residual-risk acceptance, and
  operational incident/appeal procedures are not evidenced.

**Permitted scope pending closure:** controlled internal demonstration and
non-production testing with synthetic data only. Do not use the prototype to
make or communicate real customer lending decisions, access real bureau data,
or store real applicant data.

**Reconsideration gate:** convene a formal review only after each pre-launch
condition in section 7 is evidenced, independently reviewed where appropriate,
and accepted by named accountable owners.

---

## 2. System and classification

### System description

Keystone is a mortgage-assessment prototype that combines customer input,
document and account information, a credit-report tool call, affordability
calculations, and decision-authority logic. Eligible cases are held pending
authorized human review; adverse, non-standard, affordability-failed, and
over-limit cases are referred to an underwriter. No authorized human-decision
workflow is implemented in this repository. Its tools include local PII
sanitization, a prompt-injection pre-check, a scoped CRA gateway, OPA
authorization, and an encrypted application vault.

Relevant implementation: [`agent.py`](lloydsagent/agent.py),
[`lloyds_tools.py`](lloydsagent/lloyds_tools.py),
[`privacy.py`](lloydsagent/privacy.py),
and [`governance.py`](lloydsagent/governance.py).

### Preliminary EU AI Act screen

**Screening outcome: HIGH-RISK — creditworthiness of natural persons.**
Keystone's stated purpose includes assessing mortgage applicants'
creditworthiness. This maps to the EU AI Act Annex III creditworthiness
category, subject to confirmation of territorial scope, provider/deployer
roles, applicable dates, final intended purpose, and legal interpretation.
The fraud-detection-only exception does not describe this system's purpose.
The system also profiles applicants; document the Article 6(3) analysis, noting
that profiling of natural persons is always treated as high-risk under that
provision.

This screen is a governance aid and does not determine legal status or prove
compliance. Legal/compliance must approve the classification and identify all
applicable duties before deployment.

**Human oversight flag:** high-risk status makes oversight design a required
workstream. The flag is not evidence that the present product has meaningful
oversight. Automated DIP issuance is now blocked and eligible cases remain
pending; the repository does not implement or authenticate an underwriter's
approval.

Code and unit tests: [`classify_eu_ai_act`](lloydsagent/governance.py) and
[`test_governance.py`](tests/test_governance.py). The wider preliminary
classification and scoring notes are in the [demo governance section](MORTGAGE_DATA_PROTECTION_DEMO.md#10-governance--ai-risk-classification-and-risk-register).

---

## 3. Assurance case — claim, argument, evidence

### Top-level claim

> **Claim C0:** Keystone is safe and lawful to operate for customer mortgage
> assessment only after the open conformity, fairness, human-oversight,
> traceability, operational-readiness, and ownership gaps below are closed and
> accepted by the accountable governance committee.

**Current argument:** The repository provides evidence of useful technical
controls, but that evidence is insufficient to support an unconditional live
deployment claim. Therefore, C0 is **not currently established**.

| Argument | Why it matters | Checkable evidence available | Assessment |
|---|---|---|---|
| **A1 — Intended use and risk are identified.** | The system materially affects access to mortgage credit, so obligations and controls must be scoped to that use. | Preliminary classification logic and tests in [`governance.py`](lloydsagent/governance.py) and [`test_governance.py`](tests/test_governance.py); risk register in section 4. | **Partial.** Preliminary screen exists; legal classification and formal risk-owner approval are open. |
| **A2 — Technical attacks and unauthorized CRA access are mitigated.** | Prompt injection, data exposure, and unauthorized tool use could cause customer harm or compromise data. | Input/output privacy tests [`test_mortgage_privacy.py`](tests/test_mortgage_privacy.py); gateway tests [`test_mcp_gateway.py`](tests/test_mcp_gateway.py); OPA policy and tests [`security/opa/`](security/opa/); security evidence report [`M6_M7_CAPSTONE_SECURITY_REPORT.md`](M6_M7_CAPSTONE_SECURITY_REPORT.md). | **Partial.** Tests cover selected cases; they do not prove complete threat coverage or production operation. |
| **A3 — Lending outcomes are accurate, fair, and appropriately governed.** | Incorrect or discriminatory decisions can cause material financial and equal-treatment harms. | Decision and affordability logic in [`lloyds_tools.py`](lloydsagent/lloyds_tools.py); risk actions in [`governance.py`](lloydsagent/governance.py). | **Gap.** No independent outcome validation, subgroup fairness results, calibration report, or approved data-governance evidence was found. |
| **A4 — Humans can meaningfully supervise consequential outputs.** | Human oversight must detect, challenge, and correct automation errors rather than rubber-stamp them. | Automated DIP issuance is disabled in [`evaluate_decision_authority`](lloydsagent/lloyds_tools.py), with a pipeline backstop in [`agent.py`](lloydsagent/agent.py); tests in [`test_mortgage_privacy.py`](tests/test_mortgage_privacy.py). | **Partial.** The system now holds eligible cases for human review, but has no authenticated reviewer workflow, recorded sign-off/override, or automation-bias evaluation. |
| **A5 — Decisions can be reconstructed and challenged.** | Customers, reviewers, and regulators need to understand how a decision was reached and what evidence was used. | Hash-chained gateway audit [`cra_gateway_audit.py`](lloydsagent/cra_gateway_audit.py), encrypted vault storage [`lloyds_tools.py`](lloydsagent/lloyds_tools.py), and documented limitations in [`MORTGAGE_DATA_PROTECTION_DEMO.md`](MORTGAGE_DATA_PROTECTION_DEMO.md). | **Partial.** Gateway audit is PII-minimized, but a full decision-level explanation, model/policy version, source snapshot, human actions, and appeal trail are not evidenced as one reconstructable record. |
| **A6 — The service can be operated safely after launch.** | Drift, incidents, privacy events, and complaints must trigger timely action. | Security tests and operating setup notes in [`M6_M7_CAPSTONE_SECURITY_REPORT.md`](M6_M7_CAPSTONE_SECURITY_REPORT.md) and [`MORTGAGE_DATA_PROTECTION_DEMO.md`](MORTGAGE_DATA_PROTECTION_DEMO.md). | **Gap.** No approved production monitoring, incident notification, customer appeal, or rollback plan was found. |

### Evidence not yet available

- Signed legal/compliance classification and applicability assessment.
- Approved training/validation data inventory, lawful-basis assessment, data
  quality review, representativeness analysis, and bias/fairness test results.
- Independent model validation, accuracy/calibration results, robustness
  evaluation, and acceptance thresholds for the intended mortgage population.
- Complete technical documentation and a controlled change/model release
  record.
- Meaningful human-oversight design, operating procedure, staffing/capacity
  evidence, override records, and automation-bias testing.
- Decision-level logging and a demonstrated reconstruction/appeal exercise.
- Production CRA and model-provider assurance, service resilience evidence,
  privacy/retention controls, and security operational acceptance.
- Signed residual-risk acceptance, accountable business owner, SMCR owner, and
  go-live committee decision.

---

## 4. Risk register and treatment

Scoring method: likelihood × impact, both 1–5. Bands: Low 1–4, Medium 5–9,
High 10–16, Critical 17–25. The ratings are initial estimates from
[`governance.py`](lloydsagent/governance.py), not measured frequencies or an
approved institutional risk appetite. Residual risk remains with the named
function until a real accountable individual accepts it.

| ID | Risk | Inherent → residual | Existing controls / evidence | Required treatment | Proposed owner | Status |
|---|---|---:|---|---|---|---|
| KMR-01 | Unfair or discriminatory lending outcomes | 20 Critical → 20 Critical | Human escalation exists for configured cases; no fairness evidence found. | Run lawful subgroup testing, assess proxies and disparate outcomes, define remediation and monitoring thresholds, obtain independent approval. | Model Risk / Fair Lending | **ACTION REQUIRED** |
| KMR-02 | Incorrect or unsupported lending decision | 20 Critical → 15 High | Affordability calculations and referral rules; DIP issuance is disabled and eligible cases are held for human review. | Independently validate outcomes and edge cases; implement authenticated, recorded human review and maintain no-DIP behavior until performance and oversight are approved. | Mortgage Product / Model Risk | **ACTION REQUIRED** |
| KMR-03 | Unauthorized disclosure or misuse of applicant data | 20 Critical → 8 Medium | Local PII sanitization, minimized tool outputs, encrypted vault, scoped gateway. | Verify production provider data handling, retention/deletion, key rotation, access controls, and breach response. | Data Protection / Security | **MONITOR + CLOSE GAPS** |
| KMR-04 | Prompt injection or protected-record exfiltration | 20 Critical → 8 Medium | Local injection and encoded-content checks, canary, tool allow-list; adversarial tests. | Extend attack testing, measure false negatives/positives, retest on material prompt/model/tool changes. | AI Security | **MONITOR + CLOSE GAPS** |
| KMR-05 | Fraudulent or manipulated applicant evidence | 15 High → 8 Medium | Document provenance and income grounding checks are described in the prototype. | Validate trusted issuers and thresholds; test realistic document fraud; route material mismatch to a reviewer. | Financial Crime / Mortgage Operations | **MONITOR + CLOSE GAPS** |
| KMR-06 | Unauthorized or excessive CRA access | 15 High → 5 Medium | JWT verification, short-lived scope, OPA default-deny, network isolation. | Verify production credential lifecycle, policy change control, alerting, and multi-instance replay protection. | Platform Security | **MONITOR + CLOSE GAPS** |
| KMR-07 | Service outage or unsafe fallback | 9 Medium → 6 Medium | Some dependencies fail closed; gateway tests exist. | Define recovery objectives, alerting, manual processing, and tested rollback. | Mortgage Operations / SRE | **MONITOR + CLOSE GAPS** |

Do not treat the displayed residual scores as accepted risk. KMR-01 remains
Critical and alone prevents a positive launch recommendation in the current
state. The full machine-readable register includes likelihood/impact values,
recommended actions, flags, and owners in [`governance.py`](lloydsagent/governance.py).

---

## 5. Conformity evidence map

Statuses below describe evidence found in this repository, not a formal
declaration of conformity. Article scope and final applicability require
legal/compliance review.

| Obligation | Evidence expected for Keystone | Evidence found | Status |
|---|---|---|---|
| **Article 9 — Risk management** | Lifecycle risk process, hazards, mitigations, residual-risk acceptance, periodic review. | Initial scored register and actions in [`governance.py`](lloydsagent/governance.py); no approved lifecycle process or signed acceptance located. | **Partial** |
| **Article 10 — Data and data governance** | Data provenance, quality, representativeness, bias checks, lawful collection/use, safeguards. | PII sanitization and data minimization in [`privacy.py`](lloydsagent/privacy.py); no dataset governance pack, lawful-basis assessment, or fairness results found. | **Gap** |
| **Article 11 / Annex IV — Technical documentation** | Controlled system description, design, data, validation, limitations, changes, and conformity evidence. | Source code and engineering/security report exist; no complete controlled Annex IV technical file or approved conformity record found. | **Gap** |
| **Article 12 — Record-keeping/logging** | Logs sufficient for traceability, risk detection, and decision reconstruction, with retention/access controls. | Metadata-only CRA gateway hash-chain audit in [`cra_gateway_audit.py`](lloydsagent/cra_gateway_audit.py); not a complete decision log. | **Partial** |
| **Article 13 — Transparency and information to deployers** | Instructions and limitations enabling deployers to interpret output and use it appropriately. | Demo documentation describes controls and limitations; no approved production instructions, meaningful confidence/explanation design, or user-facing transparency package found. | **Partial / Gap** |
| **Article 14 — Human oversight** | Trained, empowered people who understand limits, can interpret, challenge, override, or stop outputs. | [`evaluate_decision_authority`](lloydsagent/lloyds_tools.py) now returns pending review for eligible cases and cannot issue a DIP; regression test in [`test_mortgage_privacy.py`](tests/test_mortgage_privacy.py). | **Partial** |
| **Article 15 — Accuracy, robustness, cybersecurity** | Defined metrics and thresholds, representative validation, resilience and security evidence. | Gateway/privacy tests and adversarial evidence in [`M6_M7_CAPSTONE_SECURITY_REPORT.md`](M6_M7_CAPSTONE_SECURITY_REPORT.md); no independent lending accuracy/fairness validation. | **Partial** |
| **Article 17 — Quality management system** | Controlled responsibilities, development, testing, release, monitoring, corrective actions, and records. | No complete AI Act quality-management-system evidence found. | **Gap** |

---

## 5A. Security and governance toolkit implementation audit

The attached toolkit slide names tools and frameworks; a mention in a report or
documentation is not equivalent to an installed, integrated, repeatable
control. Status below is based on files and tests present in this workspace.

| Layer | Tool/framework named | Workspace evidence | Status |
|---|---|---|---|
| Threat modelling | OWASP LLM Top 10 | Threat categories are referenced in [`M3_SECURITY_AND_GOVERNANCE_GUIDE.md`](lloydsagent/M3_SECURITY_AND_GOVERNANCE_GUIDE.md) and [`M6_M7_CAPSTONE_SECURITY_REPORT.md`](M6_M7_CAPSTONE_SECURITY_REPORT.md); adversarial test cases exist. | **Partial:** useful references and cases, but no maintained threat-model workbook or threat-model tool project located. |
| Threat modelling | MITRE ATLAS | No ATLAS technique mapping or tracked assessment found. | **Missing** |
| Threat modelling | Microsoft Threat Modeling Tool | No model export/project or evidence of tool use found. | **Missing** |
| Input defense | Rebuff | [`LocalRebuffGuard`](lloydsagent/privacy.py) performs a local compatible pre-check, bounded encoded-content scan, and canary check with tests. | **Partial:** Rebuff-compatible behavior only; no official Rebuff SDK/service, LLM self-critique, vector-store logging, or Rebuff-backed detection is integrated. |
| Identity and action | OPA | Rego policies cover CRA reads and mortgage assessment requests; the gateway authenticates the corresponding action scope and sends minimized policy inputs. Policy and integration tests exist in [`security/opa/`](security/opa/), [`cra_gateway_policy.py`](lloydsagent/cra_gateway_policy.py), and [`test_mcp_gateway.py`](tests/test_mcp_gateway.py). | **Implemented in prototype; local mock mode remains the default outside hardened Compose** |
| Identity and action | OAuth 2.0 | Agent/gateway use signed JWT validation and scoped downstream JWTs. No OAuth 2.0 authorization server, authorization-code/client-credentials flow, or OAuth client integration was found. | **Missing as OAuth 2.0; JWT delegation is present** |
| Identity and action | HashiCorp Vault | Docker Compose mounts file-backed secrets. No Vault server/provider/client integration found. | **Missing** |
| Identity and action | MCP | The agent calls an allow-listed CRA gateway and the backend validates scoped tokens; tests cover gateway/backend behavior. | **Implemented as a custom secured MCP gateway path; no claim of a general MCP security product** |
| Data protection | Presidio | Local analyzer/anonymizer, UK-focused recognizers, fail-closed behavior, and tests are present in [`privacy.py`](lloydsagent/privacy.py) and [`test_mortgage_privacy.py`](tests/test_mortgage_privacy.py). | **Implemented in prototype** |
| Data at rest | PostgreSQL Row-Level Security | The repository uses encrypted JSON vault storage, not PostgreSQL. A mock helper applies tenant filtering and role-specific projection at the application layer. | **No database RLS; mock role/tenant filtering only** |
| Data at rest | Field-level encryption | AES-256-GCM encrypts selected NI, bank-account, bank-summary, and CRA-summary fields with path-bound associated data, then encrypts the full vault envelope. Both layers share the external vault key. | **Implemented in prototype; no separate KMS-managed keys or rotation** |
| Data at rest | KMS | Vault key is externally supplied by environment/file; no cloud KMS, key wrapping, rotation service, or key lifecycle integration found. | **Missing** |
| Audit | Tamper-evident audit log | [`cra_gateway_audit.py`](lloydsagent/cra_gateway_audit.py) hash-chains minimal CRA gateway events. It does not provide complete decision-level audit/reconstruction or external immutable anchoring. | **Partial** |
| Supply chain | Syft | SPDX and CycloneDX SBOM files exist at [`sbom.spdx.json`](sbom.spdx.json) and [`sbom.cdx.json`](sbom.cdx.json). | **Artifacts present; automatic regeneration in CI not found** |
| Supply chain | Grype | The narrative security report states a clean scan, but no Grype invocation, build-gate script, or workflow is present in this workspace. | **Not reproducible here / missing CI gate** |
| Runtime | Docker hardening | [`Dockerfile.hardened`](Dockerfile.hardened) and [`docker-compose.hardened.yml`](docker-compose.hardened.yml) set non-root, read-only, cap-drop, resource and segmented-network controls. Compose syntax validated. | **Configuration present; runtime deployment not proven** |
| Runtime | gVisor | No gVisor runtime configuration or deployment evidence found. | **Missing** |
| Red teaming | garak and PyRIT | No package, configuration, result, or execution evidence found. | **Missing** |
| Red teaming | Promptfoo | The narrative [`M6_M7_CAPSTONE_SECURITY_REPORT.md`](M6_M7_CAPSTONE_SECURITY_REPORT.md) describes Promptfoo results, but the referenced `redteam/` configuration/provider/results are absent from this workspace. | **Claim not independently reproducible here** |
| Red teaming | Repository tests | Python privacy/gateway/governance tests cover selected security cases; see [`tests/`](tests/). | **Implemented, limited coverage; not a substitute for garak/PyRIT or independent red-team assessment** |
| Governance | NIST AI RMF | No control-by-control NIST AI RMF mapping or assessment record found. | **Missing** |
| Governance | ISO/IEC 42001 | No management-system implementation or certification evidence found. | **Missing** |
| Governance | EU AI Act | Preliminary creditworthiness classification, initial register, and draft conformity evidence map are present in [`governance.py`](lloydsagent/governance.py) and this pack. | **Partial; no legal determination or conformity assessment** |
| Governance | FCA / ICO | Requirements and proposed processes are discussed in this draft pack. | **Documented proposals only; no approved operational procedure or regulator sign-off evidenced** |

**Important reconciliation:** the security report is a narrative artifact and
contains paths/evidence not present in this checkout. Its statements (including
Promptfoo and Grype results) have not been independently reproduced as part of
this validation. Some report language also describes an automated DIP path and
asserts compliance status that the current code no longer supports and this
pack does not endorse. Treat those statements as unverified or stale until the
referenced artifacts and commands are made available, checked against the
current revision, and rerun.

## 5B. M8 privacy and regulatory obligation assessment

The repository previously had a preliminary AI Act screen and generic
regulatory references, but it did not contain completed DPIA, RoPA/lawful
basis, or CRA processor/DPA evidence. A fictional, populated example pack now
demonstrates the structure of these artifacts; it is not evidence about the
real controller, CRA, or firm. See the
[M8 Mock Governance Evidence Pack](M8_MOCK_GOVERNANCE_EVIDENCE.md). A
structured engineering evidence register is defined by
[`build_regulatory_obligations_register`](lloydsagent/governance.py),
exposed as prototype metadata in [`agent.py`](lloydsagent/agent.py), and
covered by [`test_governance.py`](tests/test_governance.py). The register is a
gap/action tracker only: it is not a legal assessment, signed record, or
certification.

| Area | Evidence found | Status | Required closure evidence |
|---|---|---|---|
| UK GDPR Article 35 — DPIA | No completed controller-led DPIA. A mock DPIA example is available; DPO advice, controller approval, and residual-risk assessment remain absent. | **GAP — mock only** | Complete and approve the real DPIA covering purposes, data flows, necessity/proportionality, risks to people, mitigations, residual risk, DPO input, and prior ICO consultation decision where required. |
| UK GDPR Article 30 — RoPA; separate lawful-basis assessment under Articles 6/9 | No real controller/processor RoPA or purpose-specific lawful-basis record. A fictional RoPA and candidate-basis worksheet are available. | **GAP — mock only** | Create approved Article 30 records using actual entities, purposes, categories, recipients, transfers, retention/deletion, and safeguards; separately document applicable basis per purpose and Article 9/DPA 2018 condition if needed. |
| UK GDPR Article 28 — CRA processor/DPA | CRA integration is synthetic; no production CRA contract, processor due diligence, role assessment, or DPA. A mock supplier checklist and term schedule are available. | **GAP — mock only** | Confirm roles and actual service; complete due diligence and execute required processor terms/data-sharing arrangements and transfer safeguards. |
| EU AI Act high-risk obligations | Preliminary creditworthiness classification and selected prototype controls exist; a mock obligation map is available; applicability and conformity route remain unconfirmed. | **PARTIAL — mock mapping** | Legal/provider/deployer sign-off on scope and dates; complete obligation-level evidence for applicable risk, data, technical documentation, logging, transparency, oversight, accuracy/robustness/cybersecurity, quality, conformity, monitoring, and deployer duties. |
| FCA Consumer Duty | Draft monitoring proposals and a mock outcome/control map exist; no approved customer-outcome evidence or operational ownership. | **DRAFT ONLY — mock mapping** | Map the real product/service and customer journey to applicable PRIN 2A duties and evidence outcomes for products/services, price/value, understanding, and support. |
| FCA MCOB | Prototype affordability/referral logic and a mock journey map exist; no approved mapping to actual permissions, activities, product, or relevant MCOB rules. | **PARTIAL — mock mapping** | Mortgage Compliance to map the actual journey and validate applicable affordability/creditworthiness, advice/sales, disclosure, and record-keeping controls against current rules and firm policy. |
| FCA SYSC / SMCR | Functional-owner proposals and mock role allocation exist, but no named accountable SMF owner, responsibility map, reasonable-steps evidence, or approved controls mapping. | **GAP — mock only** | Confirm firm-specific applicability; appoint accountable senior management; document responsibilities, delegation, escalation, training, conduct, systems/controls, monitoring, and records. Soumya is the demo assignee, not an evidenced SMF owner. |

**No legal conclusion is made by this register.** The controller and regulated
firm must supply actual processing facts, contracts, permissions, intended
purpose, operating model, named owners, and current legal/compliance advice.
The [demo page](MORTGAGE_DATA_PROTECTION_DEMO.md#regulatory-and-privacy-obligation-validation)
contains the presenter-friendly summary; the
[mock pack](M8_MOCK_GOVERNANCE_EVIDENCE.md) contains synthetic sample entries,
action tables, and proposed role placeholders only.

---

## 6. Agent card — Keystone Mortgage Assessment

| Field | Declaration |
|---|---|
| **System name** | Keystone Mortgage Agent (prototype) |
| **Purpose** | Assist a mortgage application assessment by processing applicant information, checking configured affordability and credit criteria, and producing a referral or pending-human-review status. |
| **Intended users** | Mortgage operations and underwriting staff; customer-facing use is not approved by this pack. |
| **Risk tier** | Preliminary **EU AI Act high-risk** screening for creditworthiness of natural persons; subject to legal confirmation. |
| **Status / approved operating scope** | Non-production demonstration and testing with synthetic data only. Not approved for live mortgage decisions, customer advice, real bureau queries, or real applicant data. |
| **Must NOT do** | Must not make a final mortgage offer or execute lending; must not be used as financial advice; must not bypass policy, affordability or CRA checks; must not decide outside the mortgage-assessment scope; must not access or disclose another applicant's record; must not be used to deny or approve a real applicant until the launch conditions are met. |
| **Key controls** | Local input injection screening and PII sanitization; allow-listed mortgage tools; scoped CRA gateway, OPA policy, TLS/network separation; encrypted application vault; configured affordability and escalation rules. |
| **Known limitations** | Synthetic CRA data; heuristic input filtering; no evidenced independent fairness/accuracy validation; partial decision audit; no authenticated human approval workflow; production operating controls and legal conformity not established. |
| **Human review** | Automated DIP issuance is disabled. Eligible cases are left pending; configured adverse, non-standard, affordability-failed, and over-limit cases are referred. The repository does not implement reviewer authentication, a review UI, or recorded approval/override. |
| **Accountable business owner** | **TBD — must be appointed and accept residual risks before a go-live review.** |
| **SMCR accountable owner** | **TBD — named senior manager and applicable responsibility to be confirmed by Compliance.** Soumya is the demo assignee, not an evidenced SMCR accountable owner. |
| **Supporting owners** | Model Risk/Fair Lending, Mortgage Product, Data Protection, AI/Platform Security, Financial Crime, Mortgage Operations, and SRE — individual names and acceptance remain to be assigned. |

---

## 7. Operations and meaningful oversight plan

### A. Human oversight design — pre-launch requirement

The automated-DIP route has been disabled as an immediate prototype
safeguard. Pending status is not itself a human decision. Before live use,
implement and approve one of these operating models:

1. **Human approval before every customer decision** (recommended for the
   initial controlled release); or
2. A separately validated, legally approved tiered model with documented
   human review thresholds and demonstrated effectiveness.

For each reviewed case, the officer must be shown:

- The proposed result and plain-language reasons, with the key source facts
  (affordability inputs, credit summary, document verification outcomes).
- Missing, conflicting, stale, or low-quality inputs and known system
  limitations.
- The system/model, policy, and data versions used, plus a traceable case ID.
- What the system did not assess and what additional checks are required.

The officer must be able to pause, reject, correct, or override the output and
refer the case to specialist review. Record the officer's identity, decision,
reason, timestamp, source corrections, and any override. Do not use a
high-throughput target (including the case exercise's 5,000/week scenario) to
justify superficial review. Validate staffing, time per case, training,
quality sampling, escalation capacity, and automation-bias controls before
setting throughput.

### B. Post-market monitoring proposal

Thresholds below are **initial operating proposals**, not validated
acceptance criteria. Establish a governed baseline with representative data,
privacy review, and risk-owner approval before launch. A breach pauses the
affected automated path until a documented review authorizes resumption.

| Signal | Proposed trigger / alert | Owner | Response |
|---|---|---|---|
| Approval/referral/decline and override rates by legally reviewable groups | Any material unexplained disparity or a pre-approved statistical threshold breach; immediate review if a protected-group outcome appears systematically adverse. | Head of AI Risk / Fair Lending | Pause affected automation; investigate data, policy, and model behavior; document remediation and revalidation. |
| Human override and disagreement rate | More than 10% change from the approved rolling baseline, or any repeated common rationale for overrides. | Mortgage Operations / Model Risk | Sample cases, assess automation bias and model drift, update guidance or suspend the affected route. |
| Affordability and credit input quality | Missing, stale, invalid, or conflicting critical input above the approved threshold; any systematic source defect. | Mortgage Product / Data Owner | Stop decisions relying on affected input; investigate source and reprocess impacted cases. |
| Decision outcomes and repayment/complaint indicators | Material deterioration against approved validation baseline or risk appetite. | Model Risk / Credit Risk | Trigger independent performance review and recalibration/change governance. |
| Security/privacy events | Any confirmed unauthorized access, suspected PII disclosure, canary leak, or gateway-policy bypass. | Security / Data Protection Officer | Contain, preserve evidence, assess affected records and notification duties, and suspend impacted functionality. |
| Availability and fail-closed behavior | Any unexpected fallback, bypass of required control, or service-level breach. | SRE / Platform Security | Fail safe to manual processing, restore service, investigate, and complete change approval before restart. |
| Appeals and upheld complaints | Any substantiated pattern, or an increase beyond the approved baseline. | Customer Outcomes / Compliance | Review similar cases, remediate affected customers, and consider policy/system suspension. |

### C. Incident, notification, and appeal plan

- **Incident definition:** a systemic incorrect or discriminatory outcome;
  bypassed control; material privacy/security event; corrupted decision
  evidence; or repeated unsafe fallback is treated as a serious AI/service
  incident for internal escalation.
- **Immediate response:** stop the affected automated function, route new cases
  to the approved manual process, preserve logs/model/policy versions, identify
  potentially affected decisions, and notify the incident lead and accountable
  risk owner.
- **External notifications:** Legal/Compliance and the Data Protection Officer
  determine applicable AI Act authority, ICO, FCA, and other notifications and
  deadlines under current law and policy. For a personal-data breach, assess
  the GDPR/UK GDPR requirement to notify the ICO within 72 hours where
  applicable. Do not treat this document as a substitute for that assessment.
- **Customer appeal:** provide a clear contact route and accessible process
  for requesting review of a decision. A trained person not solely relying on
  the automated result must reassess the case, explain the material reasons in
  understandable language, correct inaccurate inputs, and record the outcome.
- **Reconstruction:** retain a protected, access-controlled case record
  sufficient to reproduce what information, tool results, decision rules,
  model/prompt version, recommendation, officer actions, and customer
  communication were used. The existing gateway audit alone is not sufficient.
- **Restart:** resume automation only after root cause, customer impact,
  remediation, independent retest, and risk-owner approval are documented.

---

## 8. Go-live review submission

| Review question | Current answer |
|---|---|
| Assurance case — does the evidence support the safety claim? | **No.** Technical controls are evidenced, but fairness, decision validation, meaningful human oversight, and operational evidence are incomplete. |
| Conformity — any unaddressed gaps? | **Yes.** Articles 9–15 are partial or gap; see section 5. |
| Agent card complete? | **Draft complete for demonstration.** Business and SMCR owners and approved use restrictions require formal confirmation. |
| Human oversight real or rubber stamp? | **Not established.** Automated DIP issuance is blocked and cases remain pending, but there is no authenticated reviewer workflow or evidence of meaningful operational review. |
| Monitoring, incident, and appeal plan in place? | **Proposed here, not operationally approved or tested.** |
| Residual risks accepted by named owners? | **No.** Proposed owners are functions; named risk acceptance is absent. |
| Named SMCR accountable owner? | **No — TBD.** Soumya is the demo assignee only. |
| Production evidence? | **No.** CRA data in this repository is synthetic/mock. |

### Decision

**☒ Do NOT launch for live customer decisions**  
☐ Launch with conditions  
☐ Launch

This decision is limited to the evidence reviewed in this repository on
11 November 2026. A future committee may reconsider after all launch gates are
closed and independently evidenced. The prototype may continue to be shown in
a controlled internal demo using synthetic data, subject to existing security
and data-handling rules.

### Minimum conditions to resubmit

1. Appoint and record the accountable business owner, SMCR owner, and named
   risk owners; obtain explicit residual-risk acceptance.
2. Complete and obtain controller/DPO approval for the Article 35 DPIA; create
   Article 30 controller/processor RoPA entries and document purpose-specific
   lawful bases, retention, transfers, and rights handling.
3. Confirm controller/processor roles for the CRA and other providers; complete
   due diligence and execute required Article 28 terms/DPA and transfer
   safeguards where applicable.
4. Complete legal/compliance classification, provider/deployer analysis,
   applicable EU AI Act conformity route, and a controlled technical
   documentation pack; complete Consumer Duty, MCOB, SYSC, and SMCR mappings
   with named accountable owners.
5. Complete data governance and independent fairness/bias testing; resolve
   findings and approve measurable monitoring thresholds.
6. Validate accuracy, robustness, and decision performance on representative,
   lawfully governed data; establish release and change-control gates.
7. Implement and test an authenticated, recorded human decision workflow,
   meaningful oversight and customer-facing explanation/appeal; keep the
   automated-issuance block in force until separately approved.
8. Deliver decision-level logging/reconstruction, production service and CRA
   assurance, privacy retention/deletion controls, and tested incident,
   rollback, and manual-processing procedures.
9. Demonstrate monitoring/appeal/incident tabletop exercises and obtain
   independent security, Model Risk, Data Protection, Compliance, and
   Operations sign-offs.

---

## 9. Evidence index and validation record

- Classification and scored risk register: [`governance.py`](lloydsagent/governance.py)
- Privacy and regulatory obligation gap register: [`build_regulatory_obligations_register`](lloydsagent/governance.py)
- Mock DPIA/RoPA/DPA and regulatory mappings: [M8 Mock Governance Evidence Pack](M8_MOCK_GOVERNANCE_EVIDENCE.md)
- Governance unit tests: [`test_governance.py`](tests/test_governance.py)
- Decision and escalation behavior: [`agent.py`](lloydsagent/agent.py) and
  [`lloyds_tools.py`](lloydsagent/lloyds_tools.py)
- Privacy and encrypted-storage tests: [`test_mortgage_privacy.py`](tests/test_mortgage_privacy.py)
- Gateway and policy tests: [`test_mcp_gateway.py`](tests/test_mcp_gateway.py)
- Security assessment and adversarial evidence summary:
  [`M6_M7_CAPSTONE_SECURITY_REPORT.md`](M6_M7_CAPSTONE_SECURITY_REPORT.md)
- Demo overview and implementation limitations:
  [`MORTGAGE_DATA_PROTECTION_DEMO.md`](MORTGAGE_DATA_PROTECTION_DEMO.md)

**Validation record:** focused governance, privacy, and gateway tests are run
against the current checkout; see the latest validation result for the exact
count. Tests validate prototype behavior, not regulatory compliance.
passed during the 11 November 2026 implementation session. These are software
tests, not an independent model validation, fairness assessment, conformity
assessment, or production-readiness certificate.
