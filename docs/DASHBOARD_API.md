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

### 2.1 Server-Controlled Analysis Context (`AnalysisContextStore`)
- **No Client Risk Manipulation**: Tool authorization and execution endpoints (`/api/v1/tools/authorize` and `/api/v1/tools/execute`) strictly require a valid, server-issued `analysis_id` obtained from `/api/v1/analyze`.
- **Authoritative Risk Scoring**: The gateway retrieves the risk score and policy decision directly from the server-side `AnalysisContextStore`. Any client-supplied `risk_score` in requests is strictly ignored and logged as a warning.
- **No Zero-Risk Fallbacks**: If `analysis_id` is omitted, invalid, or expired, requests are rejected with HTTP 422 or HTTP 400. The gateway never falls back to `risk_score = 0`.
- **Identity Binding**: Each `analysis_id` is bound to the `requester_id` that initiated the analysis. If an unauthorized client attempts to present another requester's `analysis_id`, the request is rejected with HTTP 403 Forbidden.
- **Context Trust Boundary**: External clients cannot unilaterally declare `context_trust_level="TRUSTED"` or `"SYSTEM_TRUSTED"`. The gateway automatically coerces all client-supplied trust assertions to `"UNTRUSTED"`.
- **Configurable TTL**: Analysis contexts expire after a configurable TTL (default: 300 seconds).

### 2.2 Strict Privacy Guarantees
- **Zero Raw Data Exposure**: Raw prompt text, user passwords, API keys, tokens, and PII are never logged or persisted in audit event metadata.
- **Argument Redaction in Dashboards**: When listing approval requests via `GET /api/v1/dashboard/approvals`, tool argument payloads are strictly omitted from the API response to prevent sensitive argument leakage to monitoring viewers.
- **Sanitized Audit Events**: The `EventStore` runs all event metadata through a defensive sanitizer (`_sanitize_metadata`) that strips forbidden keys (`prompt`, `arguments`, `password`, `secret`, `token`, `key`, `content`, `command`, etc.) before in-memory storage.

### 2.3 Limitations & Development Notices
> [!WARNING]
> **In-Memory Storage Limitation**: The `AnalysisContextStore`, `EventStore`, and `ApprovalManager` are session-scoped and in-memory. All event history, active contexts, and pending approvals are cleared upon server restart. Production environments must back these stores with durable, encrypted persistence (e.g., PostgreSQL / Redis) and distributed locking.

> [!NOTE]
> **Development Identity Notice**: Client-supplied `requester_id` and `requester_role` fields represent development-only assertions and do not constitute authenticated identities. Production deployments must enforce cryptographically verified tokens (OAuth2/OIDC, mTLS, JWT).

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
