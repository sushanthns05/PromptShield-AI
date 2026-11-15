
# PromptShield AI — Threat Model

## 1. Project Overview

PromptShield AI is an adaptive runtime security gateway designed to protect Large Language Model (LLM) applications against prompt injection, sensitive information leakage, malicious retrieved content and unauthorized tool execution.

## 2. Security Objectives

| ID | Security Objective | Description |
|---|---|---|
| SO-01 | Prompt Security | Detect malicious instructions in user prompts |
| SO-02 | Data Protection | Prevent sensitive information leakage |
| SO-03 | Context Security | Identify malicious instructions in retrieved documents |
| SO-04 | Tool Authorization | Prevent unauthorized tool execution |
| SO-05 | Monitoring | Maintain privacy-preserving security audit logs |
| SO-06 | Explainability | Explain why a request was flagged |

## 3. Assets to Protect

| Asset ID | Protected Asset | Potential Impact |
|---|---|---|
| A-01 | API Keys and Secrets | Unauthorized API access |
| A-02 | User Personal Information | Privacy violation |
| A-03 | System Prompts | Instruction disclosure |
| A-04 | RAG Knowledge Base | Data poisoning |
| A-05 | External Tools | Unauthorized operations |
| A-06 | Audit Logs | Exposure of sensitive information |

## 4. Threat Identification

| Threat ID | Threat | Example Attack | Potential Impact | Planned Mitigation |
|---|---|---|---|---|
| T-01 | Direct Prompt Injection | Ignore previous instructions | Instruction manipulation | Rule-based and ML detection |
| T-02 | Indirect Prompt Injection | Malicious instructions inside a PDF | Retrieved context manipulation | Document scanning and trust boundaries |
| T-03 | Sensitive Data Leakage | Request an API key | Secret exposure | PII and secret detection |
| T-04 | Jailbreak | Attempts to bypass restrictions | Policy circumvention | Multi-layer threat detection |
| T-05 | Unauthorized Tool Usage | Invoke restricted functions | Unauthorized actions | Backend authorization |
| T-06 | RAG Poisoning | Insert malicious documents | Retrieval manipulation | Document validation and provenance |

## 5. Trust Boundaries

| Component | Trust Level | Reason |
|---|---|---|
| User Input | Untrusted | User may submit malicious prompts |
| Uploaded Documents | Untrusted | Documents may contain hidden instructions |
| Retrieved RAG Content | Untrusted | Retrieved content may be manipulated |
| Detection Engine | Controlled | Applies security analysis |
| Policy Engine | Trusted | Makes enforcement decisions |
| Backend Authorization | Trusted | Independently verifies permissions |
| External Tools | Restricted | Must follow explicit authorization |

## 6. Risk Assessment

| Severity | Description | Example |
|---|---|---|
| Critical | Unauthorized access or major data exposure | Secret disclosure |
| High | Successful prompt injection | Malicious tool invocation |
| Medium | Suspicious prompt or attempted policy bypass | Jailbreak attempt |
| Low | Unusual but potentially harmless input | Security-related keywords |

Risk classifications are preliminary and will be refined through testing.

## 7. Security Controls

| Control ID | Security Control | Implementation |
|---|---|---|
| SC-01 | Input Validation | Pydantic validation |
| SC-02 | Threat Detection | Rules and ML classifier |
| SC-03 | Sensitive Data Detection | PII and secret scanning |
| SC-04 | Context Isolation | Trusted/untrusted content separation |
| SC-05 | Risk Scoring | Weighted risk calculation |
| SC-06 | Policy Enforcement | Allow, sanitize, approval or block |
| SC-07 | Tool Authorization | Backend permission checks |
| SC-08 | Audit Logging | Redacted security event records |

## 8. Out of Scope

- Unauthorized testing against external systems.
- Attacking real production LLM services.
- Collecting real personal or confidential information.
- Allowing unrestricted autonomous tool execution.
- Claiming detection accuracy without experimental evidence.

## 9. Research Evaluation Metrics

| Metric | Purpose |
|---|---|
| Precision | How many flagged attacks are actually malicious |
| Recall | How many malicious inputs are detected |
| F1 Score | Balance between precision and recall |
| False Positive Rate | How often legitimate inputs are incorrectly flagged |
| Detection Latency | Time required to analyze a request |
| Attack Blocking Rate | Percentage of attacks successfully blocked |
| Leakage Rate | Percentage of test cases resulting in sensitive-data exposure |

## 10. Research Question

Can a context-aware, multi-layer detection and policy enforcement framework reduce successful prompt injection and sensitive information leakage in RAG-based LLM applications while maintaining acceptable detection latency and false-positive rates?

---

**Project:** PromptShield AI  
**Document:** Threat Model  
**Status:** Initial Research Draft
