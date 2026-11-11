# M8 Mock Governance Evidence Pack

**Status:** DEMO FIXTURE — synthetic assumptions only; not approved for live use  
**Prepared:** 11 November 2026  
**System:** Keystone Mortgage Agent prototype  
**Demo assignee:** Soumya  
**Related implementation:** [regulatory evidence register](lloydsagent/governance.py), [agent metadata](lloydsagent/agent.py), [demo overview](MORTGAGE_DATA_PROTECTION_DEMO.md), [go-live pack](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md)

> **Do not treat this document as a completed DPIA, RoPA, lawful-basis decision,
> data-processing agreement, legal opinion, FCA rule interpretation, or
> regulatory approval.** All organization/provider names, roles, dates,
> processing assumptions, metrics, and proposed controls below are invented
> for demonstration. The CRA and applicant data in the code are synthetic.
> Replace and validate every assumption with the actual controller, providers,
> contracts, permissions, intended purpose, and operating model before any
> real personal-data processing. This pack does not change the **DO NOT
> LAUNCH** recommendation.

---

## 1. Mock scenario and evidence status

| Field | Illustrative value |
|---|---|
| Fictional controller | Keystone Demo Bank Ltd — invented; not a real legal entity |
| Fictional system | Keystone Mortgage Agent — prototype using synthetic records |
| Purpose in this exercise | Demonstrate a mortgage-application information flow and referral to a human reviewer; no live lending decision |
| Fictional processor | Example Processing Services Ltd — invented; used only to illustrate an Article 28 assessment |
| CRA role | **Unresolved in reality.** For this example, model the CRA as an independent controller for its bureau-source records and a processor only for a separately defined service performed solely on documented instructions. |
| Data subjects | Synthetic applicant and fictional joint applicant |
| Live data | Prohibited for this demo pack |
| Approvers | Controller, DPO, Legal, Mortgage Compliance, Security, Model Risk, and accountable senior manager are all **TBD**; no signature or approval is represented |

### Evidence-state key

- **MOCK DRAFT:** a populated example using made-up facts; useful to demonstrate what evidence might look like.
- **OPEN:** requires replacement with real facts, legal analysis, controls, or approval.
- **NOT APPROVED:** no accountable person has adopted the example as organizational policy or evidence.

The code-level register intentionally continues to report unresolved items as
`GAP`, `PARTIAL`, or `DRAFT_ONLY`; mock text does not upgrade the real-world
compliance status. See [`build_regulatory_obligations_register`](lloydsagent/governance.py)
and its [regression tests](tests/test_governance.py).

---

## 2. UK GDPR Article 35 — sample DPIA

### 2.1 Screening and proposed decision

| DPIA field | Illustrative entry |
|---|---|
| DPIA ID / version | `DEMO-DPIA-001` / `0.1` |
| Controller / accountable owner | Keystone Demo Bank Ltd / **TBD** |
| DPO advice / date | **Not obtained — open action** |
| Processing being assessed | Collecting applicant-provided identity, income, account and property data; obtaining CRA credit information; calculating affordability; generating a referral/pending-review output; storing a synthetic application record. |
| Purpose and intended use | Prototype demonstration of mortgage-assessment workflow using synthetic data. Production purpose, customer impact, and controller/deployer roles require formal confirmation. |
| Article 35 screening outcome | **DPIA required for the proposed real-world use pending controller/DPO assessment.** Creditworthiness assessment, financial data, profiling, and potentially significant effects warrant a careful high-risk screening. |
| Decision | **Do not commence real-person processing.** Internal demo only with synthetic records until the DPIA is completed and approved. |
| Residual-risk / ICO consultation | **Not assessed.** Controller and DPO must determine whether residual high risk remains and whether prior supervisory-authority consultation is required. |

### 2.2 Processing description and proportionality

| Topic | Mock assessment |
|---|---|
| Data subjects | Mortgage applicant; joint applicant/guarantor if later in scope; staff reviewer |
| Data categories | Name and contact/identity identifiers; account/KYC status; income/employment and debt commitments; property value/loan amount; CRA score and adverse-credit indicators; assessment/referral outputs; staff review record in a future workflow |
| Special-category/criminal-offence data | Not intentionally requested in this synthetic flow. The controller must assess whether free text, documents, or inferences could contain such data and define exclusion, handling, and lawful conditions before live use. |
| Data sources | Synthetic user inputs, mock bank account/document records, mock CRA service. Real source owners, provenance, accuracy, permissions, and notice are **TBD**. |
| Recipients | Prototype application, authorized underwriting staff in a future approved workflow, and service providers only as lawfully instructed/contracted. Actual recipients and access groups are **TBD**. |
| Automated decisions | The prototype is configured not to issue a DIP; eligible cases remain pending for human review. No authenticated human review service currently exists. A live workflow must assess UK GDPR Article 22 and related transparency/rights implications where relevant. |
| Necessity and proportionality | Collect only fields demonstrably needed for the defined mortgage purpose; avoid free-text or document collection where structured verified fields suffice; use field-level access, purpose limitation, short retention, and customer transparency. A real necessity assessment and alternatives analysis are **OPEN**. |
| Data subject information and rights | Provide accurate privacy information before collection; define access, rectification, objection/restriction, erasure, portability, and complaint handling as applicable to the selected lawful basis and other legal duties. Operational mechanisms are **not implemented**. |
| Security controls in prototype | Local PII detection/redaction; minimized tool outputs; scoped CRA gateway; OPA authorization; TLS/network segmentation in hardened Compose; encrypted JSON vault; minimized hash-chained gateway audit. These controls have limitations and are not independently certified. |

### 2.3 Mock risk and mitigation table

| Risk to people | Initial example rating | Example mitigation / evidence | Residual example | Real approval needed |
|---|---:|---|---:|---|
| Unfair or discriminatory credit outcomes | Critical | Representative data governance; independent subgroup outcome and proxy testing; explainable reasons; human challenge/override; appeals and outcome monitoring. Current prototype has no fairness results or operational review workflow. | Critical / unresolved | Model Risk, Fair Lending, DPO, Legal |
| Incorrect outcome from missing, inaccurate, or stale data | High | Fail closed on missing/invalid required inputs; source freshness and provenance checks; correction/appeal route; validate source quality. Current mock-only integrations cannot establish real source quality. | High / unresolved | Product, Data Owner, Model Risk |
| Identity or financial-data disclosure | High | Data minimization; access control; encryption; managed keys; retention/deletion; incident response; supplier assurance. Prototype does not have KMS, production access review, or tested deletion. | Medium/High / unvalidated | Security, DPO, Platform Owner |
| Prompt injection or manipulated documents | High | Input/content screening, canary, constrained tools, document-source verification, adversarial testing and human referral. Pattern-based protections may miss novel attacks. | Medium/High / unvalidated | AI Security, Mortgage Operations |
| CRA data used without proper authority, notice, or contract | High | Verify lawful access, customer notice/permissions where applicable, actual CRA role, contract and data-sharing terms; audit lookups. Only synthetic CRA data exists. | High / unresolved | Legal, DPO, CRA owner |
| Human reviewer over-reliance or no meaningful review | High | Authenticated reviewer workflow; show evidence and uncertainty; require independent rationale; allow correction/override; quality sampling and appeal. Not implemented. | High / unresolved | Mortgage Operations, Compliance |

### 2.4 DPIA actions and sign-off record

| Action | Owner (role placeholder) | Status |
|---|---|---|
| Confirm controller, purposes, provider/deployer roles, data sources and end-to-end flows | Controller / Legal | OPEN |
| Obtain DPO advice and document necessity, proportionality, alternatives and rights | DPO / Product | OPEN |
| Validate legal bases, CRA access/notice, retention, transfers, and processor roles | Legal / DPO / Procurement | OPEN |
| Complete representative fairness, accuracy, robustness and privacy testing | Model Risk / Fair Lending / Security | OPEN |
| Implement authenticated human review, correction, appeal, deletion and incident procedures | Mortgage Operations / Privacy / Security | OPEN |
| Assess residual risk and determine prior ICO consultation | Controller / DPO / Legal | OPEN |
| Controller approval / date | Authorized approver | **NOT APPROVED / blank** |
| DPO advice / date | DPO | **NOT OBTAINED / blank** |

---

## 3. UK GDPR Article 30 — mock RoPA and lawful-basis worksheet

Article 30 is represented here by a draft processing record. The lawful-basis
analysis is a separate linked decision record; the legal basis must be selected
and documented by the controller for each purpose, not inferred by code.

### 3.1 Controller processing activity record

| Article 30 field | Synthetic example |
|---|---|
| Record ID / activity | `DEMO-ROPA-C-001` — Mortgage application assessment support |
| Controller | Keystone Demo Bank Ltd (**fictional; replace with legal entity and contact details**) |
| DPO contact | **TBD** |
| Joint controllers | None assumed for this example; actual arrangements **TBD** |
| Purpose | Receive and verify an application; access account/CRA information; calculate affordability; refer a case for human review; manage the application and related customer requests. Each purpose and compatibility must be confirmed. |
| Data subject categories | Applicant; joint applicant if applicable; authorized staff user |
| Personal-data categories | Identity/contact; account/KYC indicators; income/employment; debt/commitments; loan/property values; CRA score/adverse-credit indicators; application and referral metadata; reviewer actions if a real workflow is introduced |
| Special-category data | None intended in this example. **Open:** prevent/document incidental collection or inference from uploaded free text/documents; determine applicable Article 9/DPA 2018 condition if such data is processed. |
| Categories of recipients | Authorized mortgage staff; actual CRA; hosting/model/service providers if used; competent authorities where legally required. Actual recipient entities, purposes, and disclosure rules **TBD**. |
| Transfers outside UK | No international transfer assumed in the mock. **OPEN:** map hosting, model, support, CRA and subprocessor locations; document adequacy/safeguards and transfer-risk assessment where applicable. |
| Proposed erasure time limits | Demo synthetic fixtures: delete when the demo ends or within a short test-retention window set by the workspace owner. **Production: TBD** based on mortgage, complaints, limitation, regulatory, and privacy requirements; do not copy this demo schedule. |
| General security measures | PII minimization; encryption in transit and at rest; scoped access; key custody/rotation; audit; network segmentation; backup/restore; retention/deletion; incident management; supplier assurance. Current prototype controls are described in the [demo page](MORTGAGE_DATA_PROTECTION_DEMO.md). |
| Record owner / last reviewed | Privacy owner **TBD** / mock date 11 November 2026; no approval |

### 3.2 Separate lawful-basis worksheet — candidates, not decisions

| Purpose | Candidate basis to assess (not selected) | Evidence/conditions needed before adoption |
|---|---|---|
| Respond to an applicant-requested mortgage application and take pre-contractual steps | Assess whether Article 6(1)(b) applies to each necessary processing operation in the real application context. | Confirm the applicant's request, necessity of each data field and operation, who is party to the contract, and whether any processing falls outside steps requested by the applicant. |
| Credit-reference lookup and creditworthiness assessment | Assess the applicable basis for the controller's actual role and the CRA's separate role; do not assume one basis covers both parties. | Confirm legal role, purpose, necessity, CRA terms, fair-processing notice, data accuracy/challenge process, and any relevant credit-reference rules. Obtain Legal/DPO decision. |
| Fraud/security monitoring | Article 6(1)(f) may be a candidate for a defined legitimate-interest purpose, subject to a documented legitimate interests assessment and rights balancing; another basis may apply to particular duties. | Define a separate narrow purpose, necessity, reasonable expectations, balancing test, retention, safeguards, and objection handling. |
| Retention for legal/regulatory obligations or claims | Identify a specific applicable legal obligation or assess the relevant basis for each distinct retention purpose; do not retain all data indefinitely. | Map the exact law/claim period, affected records, access limits, deletion schedule, and legal hold process with counsel. |
| Model monitoring, fairness analysis, and improvement | Assess purpose compatibility and a separate basis; use minimization/pseudonymization and representative lawful datasets. | Define whether data is identifiable, use restrictions, special-category/proxy handling, safeguards, retention, access, and any new DPIA/fairness assessment. |
| Special-category data, if encountered | No Article 9 condition is assumed. | Avoid collection where unnecessary. If processing is needed, identify an applicable Article 9 condition and DPA 2018 safeguards with Legal/DPO before use. |

**Mock conclusion:** no lawful basis is approved by this worksheet. The
controller must record a purpose-by-purpose decision, provide the appropriate
privacy information, and assess fairness, compatibility, minimization, and
individual rights before processing.

---

## 4. UK GDPR Article 28 — mock CRA processor assessment and DPA schedule

### 4.1 Role and supplier decision record

| Assessment question | Mock answer / decision required |
|---|---|
| Is a real CRA connected? | No. The repository CRA is a synthetic mock in [`cra_mcp_server.py`](lloydsagent/cra_mcp_server.py). |
| Is the CRA automatically a processor? | **No conclusion.** A CRA may determine purposes/means for its own bureau data and act as an independent controller for some processing. A processor role applies only to processing carried out on behalf of and under documented instructions of a controller. Map each service separately. |
| Illustrative processor | Example Processing Services Ltd (**fictional**) is assumed to perform a defined lookup operation solely on documented controller instructions for this example. This does not describe any real CRA. |
| Due-diligence result | **NOT PERFORMED.** Mock checklist below is a request list, not a supplier approval. |
| Data sharing if separate controllers | Review a controller-to-controller data-sharing agreement, lawful access, notices, accuracy/challenge duties, retention, security and rights allocation; an Article 28 DPA alone is not sufficient. |

### 4.2 Mock due diligence checklist

| Control question | Mock evidence | Status |
|---|---|---|
| Security controls / independent assurance | No supplier evidence supplied | OPEN |
| Subprocessors and locations | No inventory supplied | OPEN |
| International transfers and transfer safeguards | No locations or transfer assessment supplied | OPEN |
| Data source rights, accuracy, correction and dispute handling | Synthetic source only | OPEN |
| Access control, logging, breach notice and cooperation | Prototype gateway controls exist, but no supplier commitments or tested operational process | OPEN |
| Retention, deletion, return and backups | No provider schedule or deletion evidence supplied | OPEN |
| Audit rights, assurance reports, and change notification | No contract/evidence supplied | OPEN |
| Financial crime/credit-reference obligations and customer disclosures | Requires legal/Compliance analysis for actual product and provider | OPEN |

### 4.3 Illustrative Article 28 schedule — not a contract

If the actual relationship is controller-to-processor, the written terms should
be reviewed against Article 28 and include, as applicable:

1. Subject matter, duration, nature, purpose, personal-data types, data-subject
   categories, and controller rights/obligations.
2. Processing only on documented instructions, including any international
   transfers; notify the controller if an instruction appears unlawful.
3. Confidentiality commitments for authorized personnel.
4. Appropriate technical and organizational security measures.
5. Prior authorization and flow-down terms for subprocessors, with the
   processor remaining responsible as required.
6. Assistance with data-subject rights, security/breach duties, DPIAs, and
   consultations, taking the processing into account.
7. At the controller's choice, return or deletion of personal data at the end
   of service, including copies, subject to applicable legal retention duties.
8. Information and audits/inspections to demonstrate compliance.
9. Prompt breach notification, cooperation, records, and change/exit
   assistance agreed in the contract.

**Status:** no DPA has been signed. This schedule is a negotiation checklist,
not substitute wording or evidence that a provider meets the requirements.

---

## 5. EU AI Act — mock high-risk obligation mapping

The configured screen identifies a possible high-risk creditworthiness use;
the applicable classification, roles, territorial scope, dates, exceptions,
and conformity route still require Legal review. This table is an evidence
map, not a clause-by-clause legal opinion.

| Obligation area | Relevant provision(s) to scope | Mock evidence / current prototype | Remaining work / status |
|---|---|---|---|
| Risk management | Article 9 | Initial mortgage risk register and risk actions in [`governance.py`](lloydsagent/governance.py). | No approved lifecycle risk process, testing acceptance criteria, monitoring records, or named risk acceptance. **PARTIAL** |
| Data and data governance | Article 10 | Synthetic mock data; input checks and privacy minimization. | No representative production data governance, provenance/quality plan, bias assessment, or approved collection/use controls. **GAP** |
| Technical documentation | Article 11 / Annex IV | Code, demo, and draft go-live pack. | No controlled technical file covering final purpose, architecture, design choices, data, validation, limitations, changes, and conformity evidence. **GAP** |
| Record keeping | Article 12 | Metadata-only CRA gateway hash-chain audit. | No complete decision-level record of input versions, system/model/policy versions, output, reviewer action, and retention. **PARTIAL** |
| Transparency / instructions | Article 13 | Demo documentation and limitations. | No approved instructions for deployers/users, intended-purpose restrictions, output interpretation, or customer notice package. **PARTIAL** |
| Human oversight | Article 14 | Automated DIP is blocked; results remain pending/referred. | No authenticated reviewer workflow, authority, independent challenge, recorded decision/override, or automation-bias testing. **PARTIAL** |
| Accuracy, robustness, cybersecurity | Article 15 | Selected security tests, gateway controls, and fail-closed checks. | No representative accuracy/performance evidence, robustness acceptance criteria, independent security assessment, or approved change monitoring. **PARTIAL** |
| Quality management | Article 17 | Engineering tests and draft operating proposals. | No provider-owned approved QMS covering governance, design, risk, data, testing, conformity, monitoring, corrective actions, and records. **GAP** |
| Deployer duties | Article 26, if applicable | Intended-user and no-live-use restrictions in the go-live pack. | Confirm deployer role; implement competent human oversight, input-data relevance, monitoring, logs, workplace information/training, and suspension/escalation duties as applicable. **OPEN** |
| Fundamental-rights impact assessment | Article 27, where applicable | Not performed. | Determine whether the deployer and use fall within Article 27; complete and document any required assessment before deployment. **OPEN** |
| Conformity, registration, and post-market duties | Applicable provisions including Articles 43/49/72 as scoped | No conformity assessment, registration, declaration, or post-market evidence. | Legal/provider to confirm applicability and complete the appropriate route, registration, monitoring and incident reporting. **GAP** |

The detailed preliminary classification and code are in
[`governance.py`](lloydsagent/governance.py); the repository status remains
`PARTIAL` in the [governance evidence register](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md#5-conformity-evidence-map).

---

## 6. FCA Consumer Duty, MCOB, SYSC and SMCR — mock control mapping

This is a fictional control map. Compliance must confirm the firm's
authorization, product, customer journey, advice/sales model, permissions,
outsourcing arrangements, and the precise Handbook rules that apply.

### 6.1 Consumer Duty — PRIN 2A, where applicable

| Outcome / control area | Mock control and evidence | Example test / measure (synthetic only) | Gap |
|---|---|---|---|
| Products and services | Define the intended user and prohibit live customer decisions until validation/oversight gates close. | Demo users correctly understand the prototype is not an offer or advice. | No approved product approval, target-market assessment, or customer testing. |
| Price and value | Assess fees, customer benefits, service costs, and foreseeable harms across the real mortgage journey. | Compare costs and customer outcomes by product/channel. | No product pricing/value data or assessment. |
| Consumer understanding | Plain-language explanations of missing data, referral status, and next steps; no misleading "approved" language. | Mock usability test: all participants identify that pending review is not approval. | No real customer research, communications approval, or accessibility testing. |
| Consumer support | Provide contact, correction, complaint, appeal and human assistance routes. | Mock journey verifies a user can request correction and human support. | No operational support or appeal service exists. |
| Cross-cutting rules / foreseeable harm | Fail closed on missing/invalid evidence and keep DIP issuance blocked. | Test no successful decision on missing account/CRA/document fields. | This reduces one technical risk but does not evidence good customer outcomes. |
| Governance and outcome monitoring | Proposed owners, incident triggers, complaints/appeal review and remediation in go-live plan. | Mock dashboard fields: referral, correction, complaint, abandonment, and turnaround rates. | No baselines, real outcomes, assigned accountable owners, or board review. |

### 6.2 MCOB — applicability and mortgage journey mapping

| Journey stage / obligation area | Mock implementation mapping | Evidence and open work |
|---|---|---|
| Scope and permissions | Determine regulated activity, lender/intermediary role, mortgage type, advice/sales model, and customer channel before selecting MCOB provisions. | No real firm permissions or operating model in repository. Compliance decision required. |
| Application and affordability | Prototype computes LTI/LTV and a stress scenario and blocks on missing/invalid required inputs. | [`compute_affordability`](lloydsagent/lloyds_tools.py). The formula, assumptions, thresholds, evidence sources and exceptions are illustrative and not a complete MCOB assessment. Independently validate against applicable current rules and policy. |
| Advice/sales and suitability where relevant | Do not let the agent provide regulated advice or make a recommendation until role, permissions, advice journey, suitability duties and controls are assessed. | No adviser authorization, suitability engine, approved recommendation record, or sales workflow. |
| Disclosure and customer communications | Clearly distinguish information, referral, advice, offer and decision; explain limitations and next steps. | Demo messaging exists; no Compliance-approved disclosure set or full customer journey. |
| Record keeping and exceptions | Retain approved evidence, rationale, source versions, customer communications, and human decisions with appropriate retention/access. | Current CRA gateway log is not a complete lending decision record; no approved retention schedule. |

### 6.3 SYSC / SMCR — roles, systems and controls

| Governance element | Mock allocation (role placeholder, not a named appointment) | Evidence expected before use |
|---|---|---|
| Senior accountability | Accountable Senior Manager: **TBD**; relevant SMF and prescribed responsibility applicability: **Compliance to determine**. | Approved responsibility statement/map, clear allocation for AI/model, mortgage conduct, outsourcing, privacy/security, and customer outcomes. |
| Business ownership | Mortgage Product Owner: **TBD**. | Product approval, intended use, limits, monitoring, change approval, complaints/appeals, and suspension authority. |
| Model and AI risk | Model Risk / Fair Lending Owner: **TBD**. | Independent validation, fairness review, inventory, tiering, ongoing performance/drift monitoring, and challenge records. |
| Data protection | Controller and DPO: **TBD**. | DPIA, RoPA, lawful-basis decisions, privacy notice, rights handling, retention/deletion, supplier and transfer review. |
| Security and operations | CISO/Security and SRE/Operations owners: **TBD**. | Access reviews, incident response, resilience/recovery, change/configuration management, secure logging, supplier oversight, and tested manual fallback. |
| Competence and Conduct Rules | Staff roles and training: **TBD**. | Competence/training records, role-specific guidance, escalation channels, and evidence of applicable Conduct Rule compliance. |
| Reasonable steps and oversight | Named accountable manager to determine and evidence reasonable steps; this document assigns no individual. | Management information, challenge/approval minutes, decisions, delegations, review cadence, and remediation evidence. |

---

## 7. Mock acceptance and launch-gate snapshot

These are illustrative statuses for the demo only; the repository's real
evidence status remains as shown in the [go-live pack](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md).

| Work item | Mock artifact included here | Real-world state |
|---|---|---|
| DPIA | Populated synthetic screening, processing description, risk/mitigation table, and action log | **Not approved; real DPIA required** |
| Article 30 / lawful basis | Draft RoPA row and purpose-by-purpose basis worksheet | **Not approved; facts and lawful basis unconfirmed** |
| Article 28 / CRA | Fictional processor due-diligence checklist and clause schedule with controller-role caveat | **No production CRA or DPA** |
| EU AI Act | High-risk obligation-to-evidence map | **Legal scope and conformity incomplete** |
| Consumer Duty / MCOB | Customer-outcome and mortgage-journey control map | **Compliance review and operational evidence incomplete** |
| SYSC / SMCR | Role allocation with explicit TBD holders | **No named accountable SMF owner or approved responsibility map** |

**Demo acceptance:** This sample is suitable only to demonstrate what a
structured evidence pack could contain. It must not be used to tell customers,
auditors, regulators, or decision-makers that the firm has completed or passed
these assessments. Live use remains prohibited until real artifacts are
completed, independently reviewed as appropriate, approved by accountable
owners, and the go-live decision is formally reconsidered.
