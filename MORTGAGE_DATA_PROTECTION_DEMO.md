# Mortgage Agent: Data Protection, Privacy & CRA Gateway

**Demo owner / assignee:** Soumya  
**Project:** Keystone mortgage agent  
**Purpose:** Demonstrate privacy controls, encrypted storage, role-scoped mock reads, and policy-gated CRA/mortgage actions.

---

## 1. End-to-end story

```text
Customer message
  -> prompt-injection screening
  -> local Presidio detection and PII anonymization
  -> LangChain agent and minimized internal-tool responses
  -> encrypted mock application vault; pending/referral only, never auto-DIP
  -> agent JWT -> TLS-protected CRA gateway
       -> validate issuer, audience, expiry, identity, and scope
       -> OPA evaluates CRA access and mortgage-action policy (default deny)
       -> mint a one-use, 30-second CRA-only JWT
       -> TLS-protected CRA tool service validates the delegated JWT
       -> append metadata-only event to SHA-256 hash chain
  -> minimized CRA summary -> AES-256-GCM encrypted application vault
```

The CRA tool service is on a separate internal network from the agent. The agent can address only the gateway; the gateway is the only service connected to the CRA tool network. Both network hops use TLS in the hardened Compose stack.

---

## 2. Feature — local privacy and minimization

| Tool / control | How it helps | Code |
|---|---|---|
| Prompt-injection screening | Blocks suspicious requests before the model call. | [`ContentFilterMiddleware`](lloydsagent/privacy.py) |
| Microsoft Presidio Analyzer + Anonymizer | Runs locally with spaCy and mortgage-focused UK recognizers; replaces detected values without creating a re-identification map. | [`PIISanitizationMiddleware`](lloydsagent/privacy.py), [pinned packages/model](requirements.txt) |
| Fail-closed sanitizer | Presidio/model initialization errors stop processing rather than silently falling back to weaker detection. | [`privacy.py`](lloydsagent/privacy.py) |
| LangChain agent and internal tools | Sanitizes chat input/output and uses explicit output allow-lists for account/document data. | [`agent.py`](lloydsagent/agent.py), [`lloyds_tools.py`](lloydsagent/lloyds_tools.py) |
| Notebook demo path | The generated notebook uses the same shared CRA gateway client and encrypted-vault tool; it does not create an unauthenticated in-process CRA server. | [`create_mortgageagent_nb.py`](lloydsagent/create_mortgageagent_nb.py), [`mortgageagent.ipynb`](lloydsagent/mortgageagent.ipynb) |
| Minimized CRA result | Projects only a validated status, credit score, and adverse-credit counts; omits bureau references and free-text categories from the agent response. | [`pull_credit_report_mcp`](lloydsagent/lloyds_tools.py) |
| Fail-closed source checks | Missing or invalid document, account/KYC, CRA, or affordability data stops the assessment and returns a manual-review-required result without persisting or computing a lending outcome. | [`run_assessment_pipeline`](lloydsagent/agent.py), [`test_mortgage_privacy.py`](tests/test_mortgage_privacy.py) |

---

## 3. Feature — Rebuff-compatible prompt defense and canary

The mortgage agent performs a local Rebuff-compatible pre-check before invoking
the language model. The guard scans direct text and bounded Base64/URL-safe
Base64 decoded content against a mortgage-specific attack vault, including a
new signature for customer-record export requests. Oversized inputs and
excessively nested/encoded content are rejected rather than sent onward.

A random per-agent canary is embedded in the system prompt and registered with
the same guard. Assistant responses are checked before they are returned; a
leak is replaced with a safe generic response. Neither prompts nor canary
values are sent to an external Rebuff service or written to the audit log.

Code walkthrough: [`LocalRebuffGuard`, Base64 scanning, and attack vault](lloydsagent/privacy.py) →
[`KeystoneMortgageAgent` prompt construction and pre/post checks](lloydsagent/agent.py) →
[focused tests](tests/test_mortgage_privacy.py). The generated notebook also
demonstrates encoded-attack detection and canary checks:
[`create_mortgageagent_nb.py`](lloydsagent/create_mortgageagent_nb.py) and
[`mortgageagent.ipynb`](lloydsagent/mortgageagent.ipynb).

---

## 4. Feature — OPA identity and action boundary

The gateway submits only verified identity claims (`issuer`, `subject`,
`audience`, and scopes), the requested action (`cra:get_credit_report`), and
validated tool metadata to OPA. Applicant names, NI numbers, JWT contents, and
CRA results are excluded from the policy input. OPA's default-deny policy only
allows the mortgage-agent principal with `cra:credit-report:read` to perform a
valid credit-report lookup. The gateway rejects explicit policy denials and
fails closed when OPA is unavailable or returns an invalid decision.

The OPA API is reachable by the gateway only on a separate internal network;
the hardened Compose setup uses TLS for the OPA connection. Rego policy and
policy tests: [`keystone.rego`](security/opa/keystone.rego) and
[`keystone_test.rego`](security/opa/keystone_test.rego). The HTTP decision
client and gateway enforcement are in [`cra_gateway_policy.py`](lloydsagent/cra_gateway_policy.py)
and [`cra_mcp_gateway.py`](lloydsagent/cra_mcp_gateway.py).

The separate mortgage-action policy allows only a standard, affordable
assessment request at or below £500,000 with no adverse-credit flags. It is
not an approval: every case remains pending for an authorized human. Larger,
non-standard, adverse, denied, or policy-unavailable requests are referred.
Local runs use an explicitly labeled mock policy by default; hardened Compose
selects the authenticated gateway/OPA route. See [policy and tests](security/opa/keystone.rego),
[policy caller](lloydsagent/lloyds_tools.py), and
[gateway integration test](tests/test_mcp_gateway.py).

---

## 5. Feature — signed JWTs and scoped delegation

1. The mortgage agent sends its provisioned JWT only to the gateway. The gateway checks the RS256 signature, issuer, audience, subject, expiry, and action-specific scope: `cra:credit-report:read` for CRA calls or `mortgage:assessment:request` for the action policy.
2. The gateway accepts only `get_credit_report` with the expected two input fields. Unknown tools, extra fields, malformed identifiers, expired tokens, or missing scopes are rejected.
3. For each accepted CRA call, the gateway signs a distinct downstream JWT with only the CRA read scope, the exact tool name, and a 30-second lifetime. The mortgage-action policy route never forwards to the CRA tool service.
4. The CRA tool service independently verifies that gateway signature, issuer, audience, tool, and scope. It rejects missing/invalid tokens and replays of a downstream token.

The agent does not have the gateway's signing key. The CRA service receives only the gateway public key. The agent is not connected to the CRA service network.

Code walkthrough: [`call_mcp_sync`](lloydsagent/lloyds_tools.py) → [gateway validation and scoped-token issuance](lloydsagent/cra_mcp_gateway.py) → [backend token enforcement](lloydsagent/cra_tool_server.py) → [JWT claim rules](lloydsagent/cra_gateway_auth.py).

---

## 6. Feature — TLS, network isolation, and secret handling

- The gateway and CRA service require TLS when bound outside loopback. The agent and gateway verify the internal CA when connecting to their next hop.
- Compose uses separate internal networks: agent↔gateway and gateway↔CRA. There is no agent↔CRA network route.
- JWTs and private keys are mounted as Docker secrets, not baked into the image or passed as environment-variable values. Generated local secrets are excluded by `.gitignore`.
- The one-time setup helper creates separate 3072-bit RSA key pairs and a short-lived (maximum 24 hours) agent JWT. The agent private key is provisioning-only; do not mount it into runtime containers.
- TLS certificates must be issued by the deployment's trusted internal CA with SANs for `cra-mcp-gateway`, `cra-mcp-server`, and `cra-opa`. See the [Compose service/network/secret wiring](docker-compose.hardened.yml) and [hardened image](Dockerfile.hardened).

Code walkthrough: [credential provisioning](lloydsagent/cra_gateway_credentials.py) → [agent/gateway/backend networking and mounted files](docker-compose.hardened.yml).

---

## 7. Feature — tamper-evident, PII-safe gateway audit

Each gateway decision records only a random request ID, tool name, outcome, status code, previous hash, and SHA-256 entry hash. Applicant names, NI numbers, request bodies, tokens, and CRA response payloads are not written to this audit file. The gateway validates the existing chain at startup and refuses to append after detected corruption or external modification.

Code: [hash-chain implementation](lloydsagent/cra_gateway_audit.py), called by the [gateway](lloydsagent/cra_mcp_gateway.py).

**Integrity limitation:** A hash chain detects edits/deletions when checked against its retained chain, but a privileged attacker who can rewrite the entire file can recompute it. Production audit evidence should be exported/anchored to a separately controlled append-only or immutable logging system. The local Compose volume is not itself encrypted by this feature.

---

## 8. Feature — encryption at rest

- The application vault uses AES-256-GCM to encrypt and authenticate the full application record before writing a versioned ciphertext envelope.
- Sensitive identifiers are additionally encrypted as path-bound AES-GCM field envelopes before whole-record encryption; NI number, bank account details, and fields under bank-account and CRA summaries are covered. This uses the same externally provisioned key, not separate KMS-managed keys.
- The key must be supplied separately as URL-safe base64 for exactly 32 bytes, either through `MORTGAGE_VAULT_KEY` for local runs or the protected `MORTGAGE_VAULT_KEY_FILE` for containers. The application does not generate or store it; missing/invalid keys fail closed.
- A fresh random nonce is used for each write, and atomic replacement reduces the risk of partial vault writes.
- The gateway audit contains no applicant data. Protect the audit volume separately using the organization's host/storage encryption and retention controls.

Code walkthrough: [vault key, field and envelope AES-GCM helpers, and mock principal access](lloydsagent/lloyds_tools.py) → [`store_mortgage_application`](lloydsagent/lloyds_tools.py); [tests](tests/test_mortgage_privacy.py).

---

## 9. Demo setup and walkthrough

### Optional interactive governance UI

Start the local UI with `python -m lloydsagent.demo_ui` and open
`http://127.0.0.1:8765`. It provides a visual data-flow/trust-boundary view,
separates features by the four demo roles, loads the AI-risk and regulatory
registers, and lets the presenter test synthetic prompt/document text and loan
amounts against local screening and mock decision policy. The UI is loopback
only; it does not call an LLM or CRA, write to the vault, or issue approvals.
The [UI service](lloydsagent/demo_ui.py), [page](lloydsagent/demo_ui.html),
and [tests](tests/test_demo_ui.py) are available for walkthrough and review.

1. Install the pinned packages: `python -m pip install -r requirements.txt`.
2. Create local JWT credentials once: `python -m lloydsagent.cra_gateway_credentials --valid-hours 12`. This writes new files under `security/secrets`; it will not overwrite existing files. Protect that directory and never commit or display its contents.
3. In separate terminals, configure the local loopback services and start `python -m lloydsagent.cra_tool_server`, OPA with `opa run --server --addr=127.0.0.1:8181 security\opa`, and `python -m lloydsagent.cra_mcp_gateway`. The [README setup section](README.md#cra-tool-gateway) lists the required PowerShell environment variables. Loopback-only HTTP is permitted for this local demo; non-loopback deployments require trusted TLS certificates.
4. Configure `CRA_MCP_GATEWAY_URL`, `CRA_AGENT_JWT_FILE`, and the vault key for the agent. Show the Rebuff-compatible input/output controls in section 3, the policy flow in section 4, and token flow in section 5; then demonstrate that policy denial, invalid tokens, and direct backend requests are rejected.
5. Inspect the audit JSONL file to show the hash chain and confirm it contains no applicant name or NI number. Then inspect the vault envelope metadata; do not print the vault key or plaintext record.
6. Run the synthetic £2m attack walkthrough. The “before” case is explicitly labeled simulation-only; the secured path shows direct prompt blocking, indirect document-injection referral before account/CRA calls, strict rejection of auto-approval output, and a pending/referral result above £500k. No real approval or lending exposure is created.
7. If presenting the notebook, show that its generated CRA call uses the same configured gateway and shared encrypted-vault tool: [`create_mortgageagent_nb.py`](lloydsagent/create_mortgageagent_nb.py) and [`mortgageagent.ipynb`](lloydsagent/mortgageagent.ipynb).
8. Run focused tests: `python -B -m unittest tests.test_governance tests.test_mcp_gateway tests.test_mortgage_privacy -v` and `opa test security\opa -v`. These cover classification and scoring, policy allow/deny rules, gateway forwarding, fail-closed decisions, token rejection, direct-call rejection, input validation, PII-free audit entries, and chain tampering.

---

## 10. Governance — AI risk classification and risk register

### Preliminary AI Act classification

The configured screen classifies Keystone as **high-risk AI: creditworthiness
of natural persons** because its intended purpose includes assessing mortgage
applicants' creditworthiness. This is a preliminary Annex III screening,
not a legal determination, conformity assessment, or claim that all high-risk
obligations have been met. Legal/compliance must confirm the final intended
purpose, provider/deployer roles, territorial scope, applicable dates, and
whether any other routes or exceptions apply. The fraud-detection-only
exception is not the mortgage agent's purpose.

The classification helper records the rationale, required follow-up, and
human-oversight flag. Automated DIP issuance is disabled in the shared
decision tool; eligible assessments remain pending for an authorized human.
This is a safety gate, not a complete human-oversight workflow: the prototype
does not authenticate reviewers or record their approval/override. Legal
review and operational oversight design remain open before any real-world
deployment.

Code: [`classify_eu_ai_act`](lloydsagent/governance.py), initialized for the
agent in [`KeystoneMortgageAgent`](lloydsagent/agent.py), with decision-tree
tests in [`test_governance.py`](tests/test_governance.py).

### Regulatory and privacy obligation validation

The repository does **not** contain completed controller-approved privacy or
regulatory assessments for the items below. A structured evidence register now
records what is present, the gap status, required follow-up, and proposed
accountable function. It is an engineering tracker—not a DPIA, a Record of
Processing Activities, a DPA, legal advice, or proof of compliance.

For a filled-in, entirely fictional example of these deliverables—including a
mock DPIA, RoPA/lawful-basis worksheet, CRA processor review, and FCA/EU AI Act
mapping—see the [M8 Mock Governance Evidence Pack](M8_MOCK_GOVERNANCE_EVIDENCE.md).
Those examples do **not** change the statuses below or the no-live-use decision.

| Requirement | Assessment from this checkout | Status | What must happen |
|---|---|---|---|
| UK GDPR Article 35 — DPIA | No completed DPIA, DPO advice, controller approval, or residual-risk assessment found. | **Gap** | Controller/DPO to assess necessity, proportionality, processing risks, mitigations, residual risk, and whether prior ICO consultation is required. |
| UK GDPR Article 30 — RoPA; separate lawful-basis assessment under Articles 6/9 | No controller/processor RoPA entry, approved purpose-specific lawful-basis assessment, retention schedule, or transfer record found. | **Gap** | Record the Article 30 particulars (actual entities, purposes, data-subject/data categories, recipients, transfers, retention/deletion, and security measures); separately document Articles 6 and, if relevant, 9/DPA 2018 grounds per purpose. |
| UK GDPR Article 28 — CRA processor/DPA | The CRA implementation is a synthetic mock. No production CRA contract, processor due diligence, role analysis, or DPA was found. | **Gap** | Identify real parties and roles, perform due diligence, and execute appropriate written terms covering instructions, security, subprocessors, assistance, deletion/return, audit, and transfers as applicable. |
| EU AI Act high-risk mapping | Preliminary creditworthiness classification and selected prototype evidence exist; the full applicability, conformity, and obligation evidence is not complete. | **Partial** | Legal/provider/deployer owners to validate scope and map applicable risk, data, technical documentation, logging, transparency, oversight, accuracy/robustness/security, quality, conformity, and deployer duties. |
| FCA Consumer Duty | Draft monitoring and customer-outcome proposals exist; approved outcome evidence and operational ownership are absent. | **Draft only** | Compliance/product owners to scope applicable PRIN 2A duties and evidence outcomes for products/services, price/value, understanding, and support. |
| FCA MCOB | Prototype affordability formulas and referral rules exist; no approved mapping to applicable mortgage permissions, activities, product, or MCOB provisions was found. | **Partial** | Mortgage Compliance to map the actual journey and validate affordability, advice/sales, disclosure, and record-keeping controls against current applicable rules. |
| FCA SYSC / SMCR | No named SMF accountable owner, responsibility map, reasonable-steps evidence, or approved systems-and-controls mapping found. | **Gap** | Compliance to confirm applicability, appoint accountable senior management, document responsibilities/escalations, and approve controls, training, monitoring, and records. Soumya remains the demo assignee only. |

The structured register is available through
[`build_regulatory_obligations_register`](lloydsagent/governance.py) and the
agent's [`regulatory_obligations`](lloydsagent/agent.py) metadata; coverage and
open statuses are regression-tested in
[`test_governance.py`](tests/test_governance.py). These entries are not marked
complete because the repository cannot establish the real controller,
processors, purposes, lawful basis, retention, customers, permissions, or
accountable senior managers.

### Scored risk register

Each risk has **inherent likelihood × impact** and **residual likelihood ×
impact**, each scored 1–5. Likelihood is rated Rare, Unlikely, Possible, Likely,
or Almost Certain; impact is rated Negligible, Minor, Moderate, Major, or
Severe. Score bands are Low 1–4, Medium 5–9, High 10–16, and Critical 17–25.
Residual High/Critical items are flagged `ACTION_REQUIRED`; lower ratings are
flagged `MONITOR`. Entries are sorted by residual score, then inherent score.
Owners and next actions are included for accountability.

| ID | Risk | Inherent | Residual | Owner |
|---|---|---:|---:|---|
| KMR-01 | Unfair or discriminatory lending outcomes | 20 Critical | 20 Critical | Model Risk / Fair Lending |
| KMR-02 | Incorrect or unsupported lending decision | 20 Critical | 15 High | Mortgage Product / Model Risk |
| KMR-03 | Unauthorized disclosure or misuse of applicant data | 20 Critical | 8 Medium | Data Protection / Security |
| KMR-04 | Prompt injection or protected-record exfiltration | 20 Critical | 8 Medium | AI Security |
| KMR-05 | Fraudulent or manipulated applicant evidence | 15 High | 8 Medium | Financial Crime / Mortgage Operations |
| KMR-06 | Unauthorized or excessive CRA access | 15 High | 5 Medium | Platform Security |
| KMR-07 | Service outage or unsafe fallback | 9 Medium | 6 Medium | Mortgage Operations / SRE |

These are **initial illustrative estimates**, not measured frequencies or an
approved institutional risk appetite. Residual scores reflect the controls
listed in the code register, not proof of control effectiveness. In particular,
fairness validation and independent decision-performance evidence are not
implemented here; the register therefore keeps those risks Critical and lists
the required follow-up. Risk owners must validate scores, evidence controls,
set acceptance thresholds, and review the register on material model, data, or
policy changes.

Code: [`Risk`, score bands, and mortgage register](lloydsagent/governance.py);
the agent exposes the classification and register as governance metadata in
[`agent.py`](lloydsagent/agent.py). The notebook prints both for the demo:
[`create_mortgageagent_nb.py`](lloydsagent/create_mortgageagent_nb.py) and
[`mortgageagent.ipynb`](lloydsagent/mortgageagent.ipynb).

The separate [Governance Go-Live Pack](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md)
turns this classification and risk register into an assurance case, conformity
evidence map, agent card, human-oversight and operations proposal, and a
conservative go/no-go recommendation.

---

## 11. Features mapped to security and governance roles

The role labels below group the project features by their primary security or
governance responsibility. They are a presentation aid, not evidence that
these roles are staffed or formally assigned. “Implemented” refers to code or
configuration in this prototype; it does not imply independent assurance or
production deployment.

### 11.1 Security Architect & Threat Modelling

**Focus:** Identify misuse and attack paths, define trust boundaries, and
select controls that reduce exposure.

| Feature / method | Purpose | Issue it helps address | Code / evidence and status |
|---|---|---|---|
| Prompt-injection threat checks | Scan direct and bounded encoded input for known attempts to override instructions, bypass lending rules, or export protected records. | Malicious or manipulative prompts influencing model behavior. | [`ContentFilterMiddleware`](lloydsagent/privacy.py), agent pre-check in [`agent.py`](lloydsagent/agent.py), [tests](tests/test_mortgage_privacy.py). Local pattern-based protection; not a complete threat defense. |
| Prompt canary / output-integrity check | Detect if the hidden system marker appears in an assistant response and block that response. | System-prompt disclosure. | [`create_prompt_canary` and `LocalRebuffGuard`](lloydsagent/privacy.py), [agent response check](lloydsagent/agent.py). Does not prevent every leakage technique. |
| Trust-boundary and attack-surface separation | Route CRA access through a gateway; isolate agent, gateway, CRA service, and policy service on separate networks. | Direct backend access, lateral movement, and excessive trust between components. | [Hardened Compose networks](docker-compose.hardened.yml), [gateway](lloydsagent/cra_mcp_gateway.py), [CRA service](lloydsagent/cra_tool_server.py). Configuration exists; production network deployment is unverified. |
| Threat-model artifact coverage | Track attack scenarios and mitigations in the project security material. | Threats being discussed without any evidence or explicit limitations. | [Security and governance guide](lloydsagent/M3_SECURITY_AND_GOVERNANCE_GUIDE.md), [go-live toolkit audit](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md#5a-security-and-governance-toolkit-implementation-audit). No maintained MITRE ATLAS mapping or Microsoft Threat Modeling Tool model was found. |

### 11.2 Agent & Application Security

**Focus:** Protect the model interaction, application data, tool calls, and
assessment flow.

| Feature / method | Purpose | Issue it helps address | Code / evidence and status |
|---|---|---|---|
| Presidio PII detection and anonymization | Locally detect and redact personal/sensitive values from model-bound and returned text. | Applicant identifiers being exposed to the model or in responses. | [`PIISanitizationMiddleware`](lloydsagent/privacy.py), [dependencies](requirements.txt), [tests](tests/test_mortgage_privacy.py). May miss identifiers or produce false positives. |
| Input validation and fail-closed source checks | Validate applicant and loan inputs; require verified documents, KYC/account fields, CRA data, and valid affordability results. Missing/invalid sources stop the assessment before a lending outcome or storage. | Unsafe defaults or incomplete/invalid data being treated as an assessment. | [`run_assessment_pipeline`](lloydsagent/agent.py), [tools and unknown-record behavior](lloydsagent/lloyds_tools.py), [CRA mock service](lloydsagent/cra_mcp_server.py), [tests](tests/test_mortgage_privacy.py). Does not prove source truth or model accuracy. |
| Tool output allow-lists and CRA minimization | Limit account, document, and credit results to fields needed for the workflow; omit identifiers and unnecessary CRA metadata from agent results. | Excessive personal-data exposure between application components. | [Tool projections](lloydsagent/lloyds_tools.py), [minimization tests](tests/test_mortgage_privacy.py). |
| Secured MCP gateway and tool allow-list | Validate request shape, size, tool name, and CRA arguments before forwarding the single permitted tool call. | Arbitrary tool use, malformed inputs, and unsafe direct backend calls. | [Gateway](lloydsagent/cra_mcp_gateway.py), [agent client](lloydsagent/lloyds_tools.py), [gateway tests](tests/test_mcp_gateway.py). Custom project gateway, not a general MCP security product. |
| RS256 JWT identity and scoped delegation | Validate token signature and claims; issue a short-lived downstream token scoped to one CRA operation. | Forged, expired, over-scoped, or wrongly targeted tool requests. | [JWT and argument validation](lloydsagent/cra_gateway_auth.py), [delegation](lloydsagent/cra_mcp_gateway.py), [backend enforcement](lloydsagent/cra_tool_server.py). JWT-based; OAuth 2.0 authorization flow is not implemented. |
| OPA authorization (Rego) | Make a default-deny policy decision for the verified identity, requested action, and validated tool metadata. | An authenticated caller performing an unauthorized action. | [Policy](security/opa/keystone.rego), [OPA client](lloydsagent/cra_gateway_policy.py), [policy tests](security/opa/keystone_test.rego), [integration tests](tests/test_mcp_gateway.py). |
| £500k mortgage-action OPA policy and human referral | Gate standard/affordable assessment requests through the gateway; refer amounts above £500k, adverse/non-standard cases, denials, and policy outages. | High-value or exceptional lending flows passing an application-only limit. | [Rego policy](security/opa/keystone.rego), [authenticated gateway route](lloydsagent/cra_mcp_gateway.py), [agent policy caller](lloydsagent/lloyds_tools.py), [OPA tests](security/opa/keystone_test.rego). Mock mode is the local default; passing the policy never approves or issues a DIP. |
| One-use downstream token check | Reject downstream token IDs that have already been consumed. | Replay of an intercepted CRA request. | [CRA service](lloydsagent/cra_tool_server.py). Replay state is in-memory and not shared across replicas. |
| Assessment decision guard | Block automated DIP issuance and return pending/referral statuses instead. | An automated assessment being mistaken for an authorized human lending decision. | [`evaluate_decision_authority`](lloydsagent/lloyds_tools.py), [pipeline backstop](lloydsagent/agent.py), [test](tests/test_mortgage_privacy.py). No authenticated reviewer workflow or recorded sign-off exists. |
| Strict decision output schema | Permit only referral or pending-human-review states and reject extra fields such as approval amounts or DIP references before storage. | Model/tool output smuggling an unauthorized approval into downstream state. | [`MortgageDecisionOutput`](lloydsagent/lloyds_tools.py), [pipeline validation](lloydsagent/agent.py), [schema tests](tests/test_mortgage_privacy.py). |

### 11.3 Platform Security & Red Team

**Focus:** Harden runtime and infrastructure, protect secrets and data at rest,
and verify resistance to attack.

| Feature / method | Purpose | Issue it helps address | Code / evidence and status |
|---|---|---|---|
| TLS and segmented internal networks | Encrypt service connections and restrict service-to-service reachability. | Network interception and lateral movement between agent, policy, gateway, and CRA services. | [Hardened Compose stack](docker-compose.hardened.yml), [gateway TLS](lloydsagent/cra_mcp_gateway.py), [CRA service TLS](lloydsagent/cra_tool_server.py). Deployment is not proven. |
| Provisioned credentials and Docker secrets | Mount keys/certificates as files and keep generated local secrets out of source control. | Credentials being committed, baked into images, or exposed as ordinary configuration. | [Credential provisioner](lloydsagent/cra_gateway_credentials.py), [Compose secrets](docker-compose.hardened.yml), [ignore rules](.gitignore). File-backed secrets are not HashiCorp Vault and do not provide managed rotation. |
| AES-256-GCM envelope and field encryption | Encrypt and authenticate the full application-record envelope and separately encrypt NI, bank-account, bank-summary, and CRA-summary fields with path-bound associated data. | Plaintext sensitive fields in stored records and undetected ciphertext modification. | [Vault implementation](lloydsagent/lloyds_tools.py), [vault tests](tests/test_mortgage_privacy.py). Same externally supplied key is used; no KMS, key separation, or retention/deletion workflow. |
| Mock role-based tenant row filtering | Restrict demo-vault reads to the principal's tenant and allow-list underwriter/privacy-officer versus metadata-only auditor permissions. | Cross-tenant reads and unnecessary access to applicant identifiers. | [`MockVaultPrincipal` and read helper](lloydsagent/lloyds_tools.py), [tests](tests/test_mortgage_privacy.py). Application-layer mock only, not database-enforced RLS; production identity must come from verified claims. |
| SHA-256 hash-chained gateway audit | Record minimized gateway metadata and detect local audit-chain modification. | Undetected edits to the CRA gateway log or PII unnecessarily appearing in it. | [Audit implementation](lloydsagent/cra_gateway_audit.py), [gateway integration](lloydsagent/cra_mcp_gateway.py), [tests](tests/test_mcp_gateway.py). Not a complete decision log or immutable external archive. |
| Hardened container configuration | Run non-root with read-only filesystems, dropped capabilities, no-new-privileges, resource limits, and network segmentation. | Container privilege escalation, persistence, and resource exhaustion. | [Hardened Dockerfile](Dockerfile.hardened), [Compose configuration](docker-compose.hardened.yml). Runtime verification and gVisor are not evidenced. |
| Focused security tests | Exercise selected input-defense, privacy, authorization, token, audit, and vault behaviors. | Regressions in existing security controls. | [Python test suite](tests/), [OPA tests](security/opa/keystone_test.rego). Limited coverage; not a substitute for independent red teaming. |
| External red-team and vulnerability-scan tools | No repeatable garak/PyRIT, Promptfoo, or Grype execution pipeline was found in this checkout. | Missing reproducible attack coverage and vulnerability scan evidence. | See [toolkit implementation audit](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md#5a-security-and-governance-toolkit-implementation-audit). Narrative-only Promptfoo/Grype claims are not verifiable here. |

### 11.4 Risk & Governance Lead

**Focus:** Classify intended use, maintain risk ownership, establish oversight,
and gate launch on evidence and accountability.

| Feature / method | Purpose | Governance issue it helps address | Code / evidence and status |
|---|---|---|---|
| Preliminary EU AI Act screening | Screen the mortgage creditworthiness use for a possible high-risk classification and list follow-up actions. | Failing to identify potential high-risk obligations. | [`classify_eu_ai_act`](lloydsagent/governance.py), agent metadata in [`agent.py`](lloydsagent/agent.py), [tests](tests/test_governance.py). Not a legal determination or conformity assessment. |
| Scored mortgage risk register | Score inherent and residual likelihood × impact, rank risks, and record controls, proposed actions, and functional owners. | Risks being unprioritized or lacking proposed mitigation and ownership. | [`Risk` and register](lloydsagent/governance.py), [risk register](#scored-risk-register), [tests](tests/test_governance.py). Illustrative scores; accountable owners must validate and accept residual risk. |
| Human decision authority gate | Keep decisions pending/referral and prevent the prototype from issuing a DIP. | Consequential lending outputs being treated as final without human authority. | [Decision tool](lloydsagent/lloyds_tools.py), [pipeline guard](lloydsagent/agent.py), [tests](tests/test_mortgage_privacy.py). Not an operational human-review workflow. |
| Assurance case and go-live decision | Summarize evidence, limitations, open launch conditions, and recommendation. | Prototype controls being mistaken for approval or readiness for customers. | [Governance Go-Live Pack](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md), which currently recommends **DO NOT LAUNCH** for live decisions. |
| Governance framework coverage | NIST AI RMF and ISO/IEC 42001 control mappings or management-system evidence are not present in this checkout. | Lack of organization-wide governance and continual-improvement evidence. | See the [toolkit audit](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md#5a-security-and-governance-toolkit-implementation-audit). |
| Live-use readiness evidence | Real CRA integration, fairness/performance validation, named risk acceptance, and authenticated/recorded human review are not implemented or evidenced. | Customer harm, unfair outcomes, unsupported decisions, and unclear accountability. | See the [go-live conditions](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md#8-go-live-review-submission). These remain blockers to live use. |

---

## 12. Tooling and governance capabilities not implemented or verified

For the complete per-tool audit, see the [toolkit implementation audit](MORTGAGE_AGENT_GOVERNANCE_GO_LIVE_PACK.md#5a-security-and-governance-toolkit-implementation-audit).

| Capability | Current evidence | Gap / risk |
|---|---|---|
| OAuth 2.0 | Signed JWT credentials are used. | No authorization server or OAuth flow/token lifecycle. |
| HashiCorp Vault / cloud KMS | File-backed Docker secrets and externally supplied vault key. | No managed access policy, rotation, revocation, or key lifecycle. |
| PostgreSQL Row-Level Security / production field access | Mock role/tenant filtering and field-level AES-GCM over the encrypted JSON vault. | No PostgreSQL or other database RLS; mock principal is not a trusted production identity; no separate KMS keys or managed rotation. |
| MITRE ATLAS / Microsoft Threat Modeling Tool | No maintained mapping/model artifact. | No formal traceable threat-model deliverable. |
| garak / PyRIT / Promptfoo / Grype | No reproducible integrated red-team or vulnerability-scanning pipeline. | No repeatable tool outputs or security release gate. |
| NIST AI RMF / ISO/IEC 42001 | No complete control mapping or management-system evidence. | Organization-level governance maturity is unverified. |
| Production CRA, fairness validation, human review | CRA is synthetic; fairness results and operational human-review workflow are absent. | Material live-deployment blockers. |

---

## Scope note

The CRA service in this repository uses a synthetic mock dataset; it is not connected to an actual bureau. These controls are an application-level demonstration, not a claim of complete GDPR compliance or production certification. Presidio can miss data or produce false positives. Production deployment still needs managed key rotation, certificate lifecycle management, durable replay protection for multiple backend replicas, externally anchored audit retention, authorization review, and data-retention/deletion policies. Existing tracked sample vault JSON may be legacy plaintext and must be treated separately from the encrypted runtime vault. Fairness and lending-performance validation, legal classification/conformity, named risk acceptance, and an authenticated, recorded human underwriting workflow are also open. Continue to treat this system as demo/test-only with synthetic data.
