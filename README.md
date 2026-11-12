# ai_governance_and_security_capstone
AI Governance and Security Final Project

See [EXECUTIONS_AND_OUTPUTS.md](./EXECUTIONS_AND_OUTPUTS.md) for feature-level
inputs and locally captured outputs using the project's synthetic demo data.

## Local governance demo UI

Start the loopback-only demo UI from the repository root:

```powershell
python -m lloydsagent.demo_ui
```

Open `http://127.0.0.1:8765`. The interface shows the prototype data flow,
trust boundaries, four security/governance roles, preliminary risk and
obligation registers, and an interactive synthetic scenario. The scenario
exercises the local prompt/document screening and mock decision policy; it
does not call an LLM or CRA, write to the mortgage vault, or issue approvals.
The server refuses non-loopback binds. Do not expose it to a network or use it
for customer decisions.

Run its focused tests with:

```powershell
python -B -m unittest tests.test_demo_ui -v
```

## Mortgage-agent data protection

The PII sanitization path uses Microsoft Presidio with its local spaCy model.
Install dependencies from `requirements.txt` before running the agent:

```powershell
python -m pip install -r requirements.txt
```

The pinned `en_core_web_sm` model is included there so analysis remains
on-device and does not call an external PII service. If Presidio or its model
cannot initialize, sanitization fails closed instead of silently falling back
to regex-only filtering.

The mortgage-agent chat entry point screens for prompt-injection attempts, redacts
common personal identifiers before model calls, and redacts identifiers in its
response. Tool outputs redact identifiers, and audit entries omit raw tool
payloads. Application records are stored using AES-256-GCM; the encryption key
is never generated or stored by the application.

Set `MORTGAGE_VAULT_KEY` to a URL-safe base64-encoded 32-byte key before running
an assessment. Generate one locally with:

```powershell
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Keep the key in a secret manager or an untracked local environment file, and back
it up separately from the vault. The key is required for every vault read/write;
there is no plaintext fallback. Existing JSON vault records are preserved and
migrated to the encrypted format on the next successful application write. The
repository's pre-existing tracked sample vault should be treated as legacy
plaintext and removed from source control through the normal repository data
cleanup process.

## CRA tool gateway

The agent no longer calls the in-process CRA MCP object. Its only CRA route is
the gateway (`CRA_MCP_GATEWAY_URL`), and the gateway delegates each permitted
lookup to the separately authenticated CRA tool service. Missing gateway URL
or agent token configuration is an error; there is no local/direct-call
fallback.

### Local loopback demo

Install dependencies, then generate fresh local JWT files. The helper does not
overwrite existing files; generated files are ignored by Git:

```powershell
python -m pip install -r requirements.txt
python -m lloydsagent.cra_gateway_credentials --valid-hours 12
```

In the first PowerShell terminal, configure and start the CRA tool service:

```powershell
$env:CRA_DOWNSTREAM_PUBLIC_KEY_FILE = "security\secrets\cra_gateway_public_key.pem"
python -m lloydsagent.cra_tool_server
```

Start OPA in another terminal before starting the gateway:

```powershell
opa run --server --addr=127.0.0.1:8181 security\opa
```

In the second terminal, configure and start the gateway:

```powershell
$env:CRA_AGENT_JWT_PUBLIC_KEY_FILE = "security\secrets\cra_agent_public_key.pem"
$env:CRA_DOWNSTREAM_PRIVATE_KEY_FILE = "security\secrets\cra_gateway_private_key.pem"
$env:CRA_TOOL_SERVICE_URL = "http://127.0.0.1:8444"
$env:OPA_DECISION_URL = "http://127.0.0.1:8181/v1/data/keystone/authz/allow"
$env:CRA_GATEWAY_AUDIT_FILE = "security\secrets\cra-gateway-audit.jsonl"
python -m lloydsagent.cra_mcp_gateway
```

OPA evaluates the verified agent identity and requested action against the
default-deny policy in `security\opa\keystone.rego`. Only the gateway can reach
the OPA API in the hardened Compose network; the policy input contains no
applicant name, NI number, token, or CRA result. A deny, malformed response, or
OPA outage blocks the CRA call. The local demo uses loopback HTTP; Compose uses
TLS with an internal-CA certificate whose SAN includes `cra-opa`.

In the agent terminal, set:

```powershell
$env:CRA_MCP_GATEWAY_URL = "http://127.0.0.1:8443"
$env:CRA_AGENT_JWT_FILE = "security\secrets\cra_agent_token.jwt"
```

Set `MORTGAGE_VAULT_KEY` as described above before an assessment. Loopback-only
HTTP is allowed for this local demonstration. Both services require TLS when
bound to non-loopback interfaces. The hardened Compose stack uses TLS and
Docker secrets; provision the expected `security\secrets` files from your
organization's approved key and certificate authorities before starting it.
The internal TLS certificates need SANs for `cra-mcp-gateway`, `cra-mcp-server`,
and `cra-opa`; both clients must trust the mounted internal CA.

The credential helper creates separate 3072-bit RS256 key pairs: the agent
private key is used only to provision/sign the short-lived agent token, while
the gateway private key is mounted only in the gateway and the matching public
key only in the CRA service. Never mount or commit the agent private key.
Rotate/replace the token before expiry; the helper limits its lifetime to
24 hours.

The gateway audit chain stores request metadata only, not identifiers,
credentials, request bodies, or CRA responses. A SHA-256 chain detects
tampering but is not immutable against an attacker able to rewrite the whole
log. Production deployments should externally anchor the chain and apply
storage encryption, access control, and retention policies.

The hardened Compose agent reads the base64 vault key from the mounted
`mortgage_vault_key` secret using `MORTGAGE_VAULT_KEY_FILE`. Local runs may use
`MORTGAGE_VAULT_KEY` directly as described above; do not set both variables.

Run the focused checks with:

```powershell
python -B -m unittest tests.test_mcp_gateway tests.test_mortgage_privacy -v
opa test security\opa -v
```
