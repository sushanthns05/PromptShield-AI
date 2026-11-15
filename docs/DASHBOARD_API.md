# PromptShield AI — Security Dashboard API Reference (Day 9)

## 1. Executive Overview & Architecture

PromptShield AI provides an adaptive runtime security gateway for LLM applications. Day 9 introduces backend APIs specifically designed to power a modern React security monitoring dashboard, operational audit log viewer, and human-in-the-loop approval console, while strictly enforcing backend security invariants.

```
       +-------------------------------------------------------------+
       |             React Security Dashboard (Frontend)             |
       +-------------------------------------------------------------+
                |                    |                     |
   GET /dashboard/overview    GET /dashboard/events   GET /benchmarks
   GET /dashboard/approvals   GET /tools/registry     GET /health
                |                    |                     |
                v                    v                     v
+--------------------------------------------------------------------+
|               FastAPI Security Gateway (Port 8000)                |
|                                                                    |
|  +------------------------+        +----------------------------+  |
|  | AnalysisContextStore   |        | Bounded EventStore (10k)   |  |
|  | (Authoritative Scores) |        | (Sanitized Telemetry Log)  |  |
|  +------------------------+        +----------------------------+  |
|               ^                                  ^                 |
|               |                                  |                 |
|  +------------------------+        +----------------------------+  |
|  | Multi-Layer Evaluator  |        | ApprovalManager            |  |
|  | (Rules + ML + Privacy) |        | (Human-in-the-Loop RBAC)   |  |
|  +------------------------+        +----------------------------+  |
+--------------------------------------------------------------------+
```

---

## 2. Core Security Invariants

### 2.1 Server-Controlled Analysis Context & Decision Policy (`AnalysisContextStore`)
- **ALLOW-Only Policy**: Only analysis contexts with an authoritative `ALLOW` decision may authorize or execute tool operations.
  - `SANITIZE` contexts are strictly rejected: prompts containing sensitive data or credentials must be resubmitted as sanitized prompts for a fresh analysis.
  - `BLOCK` contexts are strictly rejected: prompt injection, high severity threats, and policy violations permanently block tool invocation.
  - Unknown or invalid decisions fail closed.
  - Checks are applied independently in both `/api/v1/tools/authorize` and `/api/v1/tools/execute`.
- **Server-Authoritative Context Trust**: Client-supplied `context_trust_level` in request bodies is untrusted and ignored. The gateway strictly retrieves context trust from `ctx.context_trust_level` (`UNTRUSTED` by default). Unknown or malformed trust values fail closed to `UNTRUSTED`.
- **Authoritative Risk Scoring**: The gateway retrieves the risk score directly from the server-side `AnalysisContextStore`. Client-supplied `risk_score` values are ignored.
- **No Zero-Risk Fallbacks**: If `analysis_id` is omitted, invalid, or expired, requests are rejected with HTTP 422 or HTTP 400. The gateway never falls back to `risk_score = 0`.
- **Identity Binding**: Each `analysis_id` is bound to the `requester_id` that initiated the analysis. Presenting another requester's `analysis_id` yields HTTP 403 Forbidden.
- **Positive Integer TTL Enforcement**: Analysis contexts strictly require positive integer TTLs (default: 300 seconds), validated via `validate_ttl()`. Non-integers, floats, booleans (`True`/`False`), strings, negative numbers, and `None` are rejected with `ValueError`.

### 2.2 Analysis-to-Tool Intent Binding, Context-Bound Approvals & Ordered Flow
- **Intent Protection**: An `analysis_id` cannot be reused to authorize or execute unrelated tool operations.
- **Ordered Authorization Sequence**:
  - Preliminary evaluation is completely side-effect-free (no approvals minted and no intent bound).
  - `DENY` decisions **NEVER** bind tool intent and never create approval records.
  - Only when policy checks pass (`ALLOW` or `REQUIRE_APPROVAL`) is intent atomically bound.
  - If approval is required, identical concurrent authorization requests are deduplicated under store locks so that only one pending approval is created.
- **Context-Bound Approval Tokens**:
  - Tool execution requiring approval strictly requires the exact `approval_id` bound to that analysis context (`ctx.bound_intent.approval_id`).
  - Cross-context approval substitution is rejected with HTTP 403 Forbidden, even if tool, arguments, and requester are identical.
  - Store-level association via `AnalysisContextStore.associate_approval_id()` and `get_or_create_approval_id()` is atomic and prevents overwriting an existing bound approval ID with a different ID.
- **Defensive Snapshotting of Approval Records**:
  - `ApprovalManager` returns defensive deep-copied snapshots (`copy.deepcopy`) of `ApprovalRequest` objects and nested `arguments` dictionaries. Caller mutations cannot affect internal gateway records.
- **Strict Execution Invariant (`/api/v1/tools/execute`)**:
  - Execution strictly requires `require_previously_bound=True`. An unbound analysis context is rejected with HTTP 403 Forbidden. Execution cannot mint an intent binding.
- **Unified Canonical Serialization & Integrity**:
  - Arguments are canonicalized via `backend/app/policies/canonicalization.py`.
  - Enforces sorted keys, compact separators `(',', ':')`, `ensure_ascii=True`, `allow_nan=False`.
  - Rejects non-string dictionary keys, `NaN`, `Infinity`, non-dict top-level arguments, and unsupported Python types.
  - Tamper detection verifies normalized tool name, canonical JSON, and SHA-256 hash (`sha256(tool:args)`).
- **In-Memory Immutability**:
  - `AnalysisContext` fields are protected against in-memory mutation via read-only properties and controlled transition methods.
- **Research Prototype Notice**: Intent binding is a context-consistency mechanism, not a replacement for authentication.

### 2.3 Strict Privacy Guarantees & Recursive Event Sanitization
- **Deep Recursive Metadata Sanitization**: The `EventStore` enforces a conservative allowlist of approved metadata fields (`SAFE_METADATA_KEYS`) and rejects sensitive/credential keys at every depth (`FORBIDDEN_KEY_FRAGMENTS`, matching camelCase and snake_case fragments such as `apiKey`, `userPassword`, `secretToken`).
- **Embedded Credential Redaction**: All string metadata values are capped to 120 characters and scanned with `redact_sensitive_data()`, stripping API keys, tokens, and PII embedded in text fields.
- **Zero Raw Data Exposure**: Raw prompt text, user passwords, API keys, tokens, and PII are never logged or persisted in audit event metadata.
- **Argument Redaction in Dashboards**: When listing approval requests via `GET /api/v1/dashboard/approvals`, tool argument payloads are strictly omitted from the API response to prevent sensitive argument leakage to monitoring viewers.

### 2.4 Strict Schema Validation (`ConfigDict(extra="forbid")`)
- All security-sensitive request models (`ScanDocumentRequest`, `ToolAuthorizeRequest`, `ToolExecuteRequest`, `ApprovalDecisionRequest`) forbid extra parameters. Malformed or unrecognized fields trigger HTTP 422 Unprocessable Entity.

### 2.5 Limitations & Development Notices
> [!WARNING]
> **In-Memory Storage Limitation**: The `AnalysisContextStore`, `EventStore`, and `ApprovalManager` are session-scoped and in-memory. All event history, active contexts, and pending approvals are cleared upon server restart. Production environments must back these stores with durable, encrypted persistence (e.g., PostgreSQL / Redis) and distributed locking.

> [!WARNING]
> **Development Identity & Approval Limitations**: Client-supplied `requester_id`, `requester_role`, `approver_id`, and `approver_role` fields represent development-only assertions and do not constitute authenticated identities. Request-body `ADMIN` claims are spoofable by any caller in this prototype. Separation-of-duties checks are enforced against these development claims, but production deployments must enforce cryptographically verified tokens (OAuth2/OIDC, mTLS, JWT) with server-resolved RBAC roles.

---

## 3. API Endpoints

### 3.1 `POST /api/v1/analyze`
Inspects an incoming prompt across rule-based detection, ML threat classification, and sensitive data extraction. Returns an authoritative `analysis_id`.

**Request Body**:
```json
{
  "prompt": "Summarize the project timeline for Q4.",
  "requester_id": "dev-user-01"
}
```

**Response (HTTP 200)**:
```json
{
  "analysis_id": "anls-4d7a8c392f1a4e25bb84379e491c121e",
  "decision": "ALLOW",
  "risk_score": 0,
  "risk_level": "low",
  "sanitized_prompt": "Summarize the project timeline for Q4.",
  "reasons": [
    "Prompt passed all security checks"
  ],
  "details": {
    "rule_findings": [],
    "ml_prediction": {
      "prediction": "benign",
      "confidence": 0.985,
      "class_id": 0,
      "status": "success"
    },
    "sensitive_data_findings": []
  }
}
```

---

### 3.2 `POST /api/v1/tools/authorize`
Evaluates whether a tool invocation is allowed, requires administrator approval, or must be denied.

**Request Body**:
```json
{
  "tool_name": "send_email",
  "arguments": {
    "recipient": "security@example.com",
    "subject": "System Status",
    "body": "All systems operational"
  },
  "requester_id": "dev-user-01",
  "requester_role": "DEVELOPER",
  "analysis_id": "anls-4d7a8c392f1a4e25bb84379e491c121e"
}
```

**Response (HTTP 200)**:
```json
{
  "decision": "REQUIRE_APPROVAL",
  "tool_name": "send_email",
  "requester_id": "dev-user-01",
  "requester_role": "DEVELOPER",
  "risk_level": "HIGH",
  "reasons": [
    "High-risk tool 'send_email' requires human approval before execution"
  ],
  "approval_id": "appr-01a4e2b83c19",
  "requires_approval": true
}
```

---

### 3.3 `POST /api/v1/tools/execute`
Securely executes an authorized tool in a sandbox. Requires valid `analysis_id` and (if required) a consumed/valid `approval_id`.

**Request Body**:
```json
{
  "tool_name": "send_email",
  "arguments": {
    "recipient": "security@example.com",
    "subject": "System Status",
    "body": "All systems operational"
  },
  "requester_id": "dev-user-01",
  "requester_role": "DEVELOPER",
  "analysis_id": "anls-4d7a8c392f1a4e25bb84379e491c121e",
  "approval_id": "appr-01a4e2b83c19"
}
```

**Response (HTTP 200)**:
```json
{
  "execution_id": "exec-9c8e12ab34cd",
  "tool_name": "send_email",
  "status": "SUCCESS",
  "result": {
    "status": "queued",
    "recipient": "security@example.com",
    "subject": "System Status"
  },
  "executed_at": "2026-11-15T14:30:00Z"
}
```

---

### 3.4 `GET /api/v1/dashboard/overview`
Aggregated session statistics for the security dashboard overview cards.

**Response (HTTP 200)**:
```json
{
  "total_analyzed_prompts": 142,
  "allow_decisions": 118,
  "sanitize_decisions": 14,
  "block_decisions": 10,
  "documents_scanned": 28,
  "tool_authorization_requests": 65,
  "tool_deny_decisions": 12,
  "tool_require_approval_decisions": 18,
  "tool_execution_attempts": 35,
  "pending_approvals": 3,
  "privacy_findings": 19,
  "recent_security_event_count": 270,
  "storage": "in_memory",
  "session_only": true
}
```

---

### 3.5 `GET /api/v1/dashboard/events`
Paginated audit log of sanitized security gateway events in reverse-chronological order.

**Query Parameters**:
- `limit` (integer, default 50, max 500)
- `offset` (integer, default 0)
- `category` (optional string, e.g., `PROMPT_ANALYSIS`, `DOCUMENT_SCAN`, `TOOL_AUTHORIZATION`, `TOOL_EXECUTION`, `APPROVAL`)
- `event_type` (optional string, e.g., `PROMPT_EVALUATED`, `TOOL_AUTHORIZED`, `TOOL_DENIED`)
- `decision` (optional string, e.g., `ALLOW`, `SANITIZE`, `BLOCK`, `DENY`)

**Response (HTTP 200)**:
```json
{
  "items": [
    {
      "event_id": "evt-7a8b9c0d1e2f",
      "timestamp": "2026-11-15T14:32:10.123456+00:00",
      "category": "TOOL_AUTHORIZATION",
      "event_type": "TOOL_APPROVAL_REQUIRED",
      "decision": "REQUIRE_APPROVAL",
      "risk_score": 15,
      "requester_id": "dev-user-01",
      "metadata": {
        "tool_name": "send_email",
        "requester_role": "DEVELOPER",
        "risk_level": "HIGH",
        "requires_approval": true,
        "approval_id": "appr-01a4e2b83c19",
        "analysis_id": "anls-4d7a8c392f1a4e25bb84379e491c121e"
      },
      "session_only": true,
      "storage": "in_memory"
    }
  ],
  "total": 270,
  "limit": 50,
  "offset": 0,
  "storage": "in_memory",
  "session_only": true
}
```

---

### 3.6 `GET /api/v1/dashboard/approvals`
Listing of human approval requests for the security governance dashboard.

**Query Parameters**:
- `status` (optional string: `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `CONSUMED`)
- `limit` (integer, default 50, max 200)
- `offset` (integer, default 0)

**Response (HTTP 200)**:
```json
{
  "items": [
    {
      "approval_id": "appr-01a4e2b83c19",
      "tool_name": "send_email",
      "requester_id": "dev-user-01",
      "requester_role": "DEVELOPER",
      "risk_level": "HIGH",
      "status": "PENDING",
      "created_at": "2026-11-15T14:32:10.000000+00:00",
      "expires_at": "2026-11-15T14:37:10.000000+00:00",
      "decided_by": null,
      "decided_at": null,
      "decision_reason": null,
      "consumed_at": null
    }
  ],
  "total": 3,
  "limit": 50,
  "offset": 0,
  "storage": "in_memory",
  "session_only": true
}
```
*(Notice: Tool argument dictionary is strictly omitted for privacy preservation).*

---

### 3.7 `GET /api/v1/tools/registry`
Returns safe tool metadata and Pydantic argument schemas for all registered gateway tools.

**Response (HTTP 200)**:
```json
{
  "tools": [
    {
      "name": "get_weather",
      "description": "Fetch current weather conditions for a specified location.",
      "allowed_roles": ["USER", "DEVELOPER", "ADMIN"],
      "risk_level": "LOW",
      "required_args": ["location"],
      "argument_schema": {
        "title": "GetWeatherArgs",
        "type": "object",
        "properties": {
          "location": {
            "title": "Location",
            "type": "string",
            "minLength": 1,
            "description": "Target city, state, or location name"
          }
        },
        "required": ["location"],
        "additionalProperties": false
      },
      "schema_name": "GetWeatherArgs",
      "requires_approval": false,
      "is_enabled": true
    }
  ],
  "total": 6
}
```

---

### 3.8 `GET /api/v1/benchmarks`
Reads verified Day 8.5 hardened benchmark results directly from machine-readable JSON/CSV files under `research/results/day8_5_hardened/`.

**Response (HTTP 200)**:
```json
{
  "status": "success",
  "source": "research/results/day8_5_hardened",
  "metadata": {
    "framework": "PromptShield AI Benchmark Harness",
    "version": "Day 8.5 Hardened Revalidation",
    "dataset_hash": "e605d3cbcfd150244dbcae2a7adfb2fcefb751c16ae3f47e3371f49615a01bc8"
  },
  "metrics_summary_table": [ ... ],
  "confusion_matrices": {
    "Exp1_Stratified": { ... },
    "Exp2_Grouped_OOD": { ... }
  },
  "experiment_1_stratified": {
    "name": "Experiment 1: In-Distribution Stratified Split",
    "sample_count": 81,
    "configurations": { ... },
    "pii_secret_evaluation": { ... },
    "tool_policy_evaluation": { ... }
  },
  "experiment_2_grouped_ood": {
    "name": "Experiment 2: Out-of-Distribution Grouped Split",
    "sample_count": 215,
    "configurations": { ... },
    "pii_secret_evaluation": { ... },
    "tool_policy_evaluation": { ... }
  },
  "adversarial_scenarios_evaluation": { ... }
}
```

---

### 3.9 `GET /health`
System health check indicating ML classifier status and in-memory storage telemetry.

**Response (HTTP 200)**:
```json
{
  "status": "healthy",
  "classifier_status": "ready",
  "environment": "development_prototype",
  "in_memory_storage": true,
  "recent_event_count": 270
}
```

---

## 4. CORS Configuration

To support React frontend development (e.g. Vite dev server on port 5173), FastAPI is configured with `CORSMiddleware`:
- Default allowed origins: `http://localhost:5173`, `http://127.0.0.1:5173`.
- Configurable origin override via `PROMPTSHIELD_ALLOWED_ORIGINS` environment variable (comma-separated list).
- `allow_credentials=True`.
- **Security Invariant**: Wildcard `*` origin is strictly forbidden and automatically removed when credentials are enabled.
