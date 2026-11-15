# PromptShield AI — Policy Enforcement and Secure Tool Authorization

## 1. Executive Summary & Security Principle

In LLM agent architectures, allowing a model to directly authorize or trigger backend tool execution creates critical vulnerabilities. If an LLM is manipulated via direct or indirect prompt injection, it may instruct tools to exfiltrate confidential data, overwrite production files, or execute unauthorized operations.

**Core Architectural Rule:**
> **The LLM is NEVER an authorization authority.**
> Every proposed tool action must be independently validated, authorized, and gated by backend deterministic security policy before execution.

---

## 2. Authorization Lifecycle Architecture

The following Mermaid diagram illustrates the lifecycle of a tool request from initial proposal to execution:

```mermaid
flowchart TD
    A["LLM / Client Tool Proposal"] --> B["API Gateway<br/>POST /api/v1/tools/authorize"]
    B --> C["Identity & RBAC Validation<br/>(Reject Client-Side Spoofing)"]
    C --> D{"Tool Registered & Enabled?"}
    D -->|No| E["DENY<br/>(Unknown or Disabled Tool)"]
    D -->|Yes| F{"Argument Validation"}
    F -->|Invalid / Missing| G["DENY<br/>(Bad Arguments)"]
    F -->|Valid| H{"PromptShield Risk Score < 70?"}
    H -->|No| I["DENY<br/>(High Threat Context)"]
    H -->|Yes| J{"Role Authorized in Registry?"}
    J -->|No| K["DENY<br/>(RBAC Violation)"]
    J -->|Yes| L{"Context Trust & Critical Risk"}
    L -->|Untrusted + Critical| M["DENY<br/>(Untrusted Context Boundary)"]
    L -->|Within Policy| N{"Requires Human Approval?"}
    N -->|No (Low/Medium Risk)| O["ALLOW<br/>(Proceed to Execution)"]
    N -->|Yes (High/Critical Risk)| P{"Valid Approved Token Provided?"}
    P -->|No / None| Q["REQUIRE_APPROVAL<br/>(Create Pending Approval Token)"]
    P -->|Yes| R{"Approval Valid, Unexpired, Unused,<br/>& Arguments Match?"}
    R -->|No| S["DENY<br/>(Expired/Replay/Tampered)"]
    R -->|Yes| T["ALLOW<br/>(Approval Verified)"]
    
    Q --> U["Admin Human Review<br/>POST /api/v1/tools/approvals/{id}/decision"]
    U -->|Approved| T
    U -->|Rejected| V["DENY<br/>(Rejected by Reviewer)"]

    O --> W["Secure Tool Executor Simulator<br/>POST /api/v1/tools/execute"]
    T --> W
    W --> X["Token Consumed + Sandboxed Result<br/>(Never Execute Real Shell)"]
```

---

## 3. Tool Permission Matrix

The Tool Permission Registry (`backend/app/policies/tool_registry.py`) enforces strict least-privilege defaults:

| Tool Name | Description | Allowed Roles | Risk Level | Required Arguments | Approval Required | Default Status |
|---|---|---|---|---|---|---|
| `search_knowledge_base` | Query enterprise knowledge base | `USER`, `DEVELOPER`, `ADMIN` | `LOW` | `query` | No | **Enabled** |
| `get_weather` | Retrieve weather forecast | `USER`, `DEVELOPER`, `ADMIN` | `LOW` | `location` | No | **Enabled** |
| `read_file` | Read non-sensitive repository files | `DEVELOPER`, `ADMIN` | `MEDIUM` | `filepath` | No | **Enabled** |
| `send_email` | Send outbound email communication | `DEVELOPER`, `ADMIN` | `HIGH` | `recipient`, `subject`, `body` | **Yes** | **Enabled** |
| `delete_file` | Permanently delete storage target | `ADMIN` | `CRITICAL` | `filepath` | **Yes** | **Disabled** (Least Privilege) |
| `execute_command` | Simulated administrative execution | `ADMIN` | `CRITICAL` | `command` | **Yes** | **Disabled** (No Shell) |

### Key Registry Guarantees
- **Unregistered Tools**: Automatically denied with `DENY`.
- **Critical Tools Disabled by Default**: High-impact destructive tools are disabled out-of-the-box. An administrator policy must explicitly enable them.
- **Unrestricted Shell Elimination**: The `execute_command` tool is simulated in a mock sandbox. It **never** evaluates Python `eval()`, `exec()`, or system shell `subprocess` / `os.system()`.

---

## 4. Trust Boundaries & Invariants

| Component | Trust Level | Security Invariant |
|---|---|---|
| Client / Caller Claims | Untrusted | Client-supplied `is_admin: true`, `approved: true`, or `context_trust_level` flags are stripped/ignored. |
| User Inputs | Untrusted | Cannot grant permissions or bypass RBAC controls. |
| Retrieved RAG Documents | Untrusted | `DOCUMENT_UNTRUSTED` context cannot invoke or approve `CRITICAL` tools. |
| Tool Outputs | Untrusted | Outputs from tool executions retain `TOOL_UNTRUSTED` classification. |
| Analysis Decision | Server-Authoritative | Only `ALLOW` analysis contexts may authorize tools. `SANITIZE` and `BLOCK` fail closed. |
| Context Intent Binding | Server-Authoritative | `AnalysisContextStore` binds context to tool name and canonical arguments hash; prevents reuse for unrelated tools. |
| Backend Policy Engine | Trusted | Evaluates and enforces all decisions server-side. |
| Approval Store | Trusted | Server-generated token verification bound to cryptographic parameter hashes. |

---

## 5. Analysis Context & Tool Intent Binding (Day 9)

To prevent LLM agent workflows from reusing a benign prompt's analysis context to execute unauthorized or tampered tools:
1. **ALLOW-Only Authorization**: Only contexts with `ctx.decision == "ALLOW"` may authorize tools. `SANITIZE` prompts (containing PII or credentials) must be resubmitted as sanitized prompts for fresh analysis. `BLOCK` prompts (injections, policy violations) are permanently rejected.
2. **Atomic Intent Binding**: During the first valid authorization attempt, the server-controlled `AnalysisContextStore` atomically binds the context to:
   - Normalized tool name.
   - Canonical JSON representation of validated arguments (`sort_keys=True`, no extra whitespace).
   - SHA-256 cryptographic intent hash.
3. **Execution Verification**: Tool execution strictly enforces that the invoked tool and arguments match the bound intent hash. Changed tools, modified parameters, and nested type confusion attempts are rejected.
4. **Server-Authoritative Context Trust**: Client-supplied `context_trust_level` in request bodies is ignored. Context trust is always resolved server-side from `ctx.context_trust_level` (`UNTRUSTED` by default). Unknown trust values fail closed.

---

## 6. Human Approval Workflow (`ApprovalManager`)

For `HIGH` and `CRITICAL` risk tools, tool authorization transitions to `REQUIRE_APPROVAL` and mints an approval request token (`appr-<uuid>`).

### Security Controls in Approval Lifecycle:
1. **Parameter Binding**: The approval record stores a canonical copy of `tool_name`, `arguments`, `requester_id`, and `risk_level`. When execution is requested, arguments are checked against the approved state. Any modification (e.g. changing an email recipient from `client@corp.com` to `attacker@evil.com`) is rejected as argument tampering.
2. **Replay Attack Prevention**: Upon successful execution, the approval token transitions to `CONSUMED`. Subsequent requests attempting to reuse the same approval ID fail closed.
3. **Expiration Time-to-Live (TTL)**: Approvals carry a strict expiration window (default: 300 seconds). Expired approvals cannot be approved or executed.
4. **Separation of Duties**: A requester cannot approve their own high-risk action (`requester_id != approver_id`). Approving `HIGH` or `CRITICAL` actions requires `ADMIN` privileges.

---

## 7. Threat Model & Mitigations

| Threat ID | Threat Description | Attack Vector | Planned Mitigation |
|---|---|---|---|
| **T-07** | LLM Tool Confused Deputy | Model hijacked by prompt injection proposes `delete_file` or `send_email`. | Backend authorizer validates role, risk score, and requires human approval. |
| **T-08** | Client Role Spoofing | Client sends `requester_role: "ADMIN"` or `is_admin: true`. | Client privilege flags are ignored; production binds roles to validated server session tokens (JWT/mTLS). |
| **T-09** | Approval Replay Attack | Attacker captures a valid approval ID and resubmits it for unauthorized actions. | `ApprovalManager` transitions tokens to `CONSUMED` after single-use and blocks replay. |
| **T-10** | Argument Tampering | Approval is granted for a benign argument, but execution is invoked with malicious payload. | Canonical JSON argument comparison rejects tampered parameters. |
| **T-11** | Arbitrary Shell Execution | Model or attacker attempts shell command injection (`rm -rf /`, `curl evil.com`). | `ToolExecutor` strictly dispatches to controlled mock handlers. Shell binaries are never invoked. |
| **T-12** | Directory Traversal | Attacker supplies `../../etc/passwd` to `read_file`. | Traversal patterns (`..`) are detected and rejected. |
| **T-13** | Analysis Context Reuse | Attacker reuses an ALLOW analysis ID to authorize an unrelated destructive tool. | Day 9 intent binding locks context to tool name and canonical argument hash. |
| **T-14** | SANITIZE / BLOCK Bypass | Attacker invokes tools using an analysis ID resulting from a blocked prompt injection. | Day 9 policy restricts tool authorization exclusively to ALLOW contexts. |

---

## 8. Fail-Closed Behavior

The authorization engine adheres strictly to **fail-closed** security:
- If analysis decision is `BLOCK`, `SANITIZE`, or unrecognized $\rightarrow$ `DENY`.
- If analysis intent does not match previously bound tool or arguments $\rightarrow$ `DENY`.
- If a tool name is missing or unrecognized $\rightarrow$ `DENY`.
- If an argument is missing or invalid $\rightarrow$ `DENY`.
- If PromptShield risk score is $\ge 70$ $\rightarrow$ `DENY`.
- If context is untrusted and tool is critical $\rightarrow$ `DENY`.
- If context trust is unknown or unrecognized $\rightarrow$ fail closed to `UNTRUSTED`.
- If approval has expired, been consumed, or arguments differ $\rightarrow$ `DENY`.
- If any unexpected exception occurs during evaluation $\rightarrow$ `DENY`.

---

## 9. Current Development-Only Limitations & Production Requirements

### Current Limitations (Day 9 Prototype)
- **In-Memory Storage**: Analysis contexts, pending approvals, and audit event logs are held in memory. Server restarts or multi-pod deployments will lose state.
- **Client-Specified Identity Claims**: `requester_id`, `requester_role`, `approver_id`, and `approver_role` are passed in request bodies for development/test harness flexibility. In the approval endpoint, `ADMIN` claims are spoofable by any caller.
- **Context Binding Scope**: Intent binding prevents context reuse within a session but is not a substitute for cryptographically verified authentication.

### Production Readiness Roadmap
1. **Persistent Stores**: Back `AnalysisContextStore` and `ApprovalManager` with PostgreSQL or Redis with distributed locks.
2. **Server-Side Authentication**: Replace client role claims with cryptographically signed OAuth2/OIDC JWT tokens, mutual TLS (mTLS), or API gateway session cookies.
3. **Hardware Security / Secrets Management**: Store sensitive tool API credentials in Vault or AWS Secrets Manager rather than environment variables.
4. **Immutable Audit Storage**: Stream security events to an append-only, tamper-evident audit log (e.g. AWS CloudWatch / OpenSearch / Splunk).
