
# PromptShield AI — System Architecture

## 1. High-Level Architecture

```mermaid
flowchart TD
    A["User / AI Application"] --> B["PromptShield API Gateway"]

    B --> C["Input Validation"]
    C --> D["Context Extraction"]

    D --> E["Multi-Layer Detection Engine"]

    E --> F["Rule-Based Detector"]
    E --> G["ML Threat Classifier"]
    E --> H["PII & Secret Detector"]
    E --> I["Context Analyzer"]

    F --> J["Risk Scoring Engine"]
    G --> J
    H --> J
    I --> J

    J --> K{"Risk Assessment"}

    K -->|Low Risk| L["Allow"]
    K -->|Medium Risk| M["Sanitize / Require Approval"]
    K -->|High Risk| N["Block"]

    L --> O["Protected AI / RAG"]
    M --> P["Human Approval"]
    P -->|Approved| O
    P -->|Rejected| N

    O --> Q["Restricted Tool Execution"]
    Q --> R["Backend Authorization"]

    R --> S["Output Security Inspection"]
    S --> T["Response to User"]

    N --> U["Security Event Logging"]
    T --> U
    P --> U
    U --> V["Monitoring Dashboard"]
```

## 2. Request Processing Workflow

```mermaid
sequenceDiagram
    actor User
    participant Gateway
    participant Detector
    participant Policy
    participant AI
    participant Tools
    participant Logs

    User->>Gateway: Submit prompt
    Gateway->>Gateway: Validate input
    Gateway->>Detector: Analyze request
    Detector-->>Gateway: Threat findings and risk

    Gateway->>Policy: Evaluate risk

    alt Request allowed
        Policy-->>Gateway: Allow
        Gateway->>AI: Forward approved request
        AI-->>Gateway: Generate response
        Gateway->>Gateway: Inspect output
        Gateway-->>User: Return response
    else Request requires approval
        Policy-->>Gateway: Require approval
        Gateway-->>User: Approval required
    else Request blocked
        Policy-->>Gateway: Block
        Gateway-->>User: Request rejected
    end

    Gateway->>Logs: Record redacted security event
```

## 3. Core Modules

| Module | Responsibility |
|---|---|
| API Gateway | Accept and validate incoming requests |
| Rule Detector | Identify known malicious patterns |
| ML Classifier | Classify potentially malicious prompts |
| Privacy Detector | Identify PII and secrets |
| Context Analyzer | Inspect trust boundaries and retrieved content |
| Risk Engine | Calculate combined risk |
| Policy Engine | Decide allow, sanitize, approval or block |
| RAG Security | Inspect retrieved documents |
| Tool Authorization | Enforce backend permissions |
| Audit System | Store redacted security events |
| Dashboard | Display alerts and evaluation results |

## 4. Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI |
| Machine Learning | Scikit-learn |
| Detection | Python, Regex, TF-IDF |
| Database | PostgreSQL |
| Frontend | React, Tailwind CSS |
| Testing | Pytest |
| Deployment | Docker |
| Optional Local AI | Ollama |

## 5. Architectural Security Principle

The AI model is not an authorization authority.

Every sensitive tool action must be independently validated by the backend before execution. Retrieved documents and user inputs must be treated as untrusted data.

---

**Project:** PromptShield AI  
**Document:** System Architecture  
**Status:** Initial Architecture Draft
