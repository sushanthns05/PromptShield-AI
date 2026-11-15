# PromptShield AI — Empirical Benchmark Results

This report documents the independently audited and verified empirical results obtained from evaluating **PromptShield AI** across the 535-sample benchmark suite ([`research/datasets/benchmark/`](file:///home/sushanthns/Projects/PromptShield-AI/research/datasets/benchmark/)). 

Following the Day 8 Independent Experimental Methodology Audit, all metrics have been calculated directly from sample-level ground-truth predictions, verified for mathematical consistency, calibrated with warm-up timing loops, and evaluated across two experimental paradigms:
1. **Experiment 1 (Stratified Random Split, $N=81$):** In-distribution evaluation representing standard train/test partitioning.
2. **Experiment 2 (Grouped Out-of-Distribution Template Split, $N=215$):** Out-of-distribution (OOD) adversarial evaluation where entire syntactic template families and benign security probes were held out, preventing n-gram memorization.

---

## 1. Initial Baseline Results (Day 3 Reference)

During Day 3 development, initial exploratory evaluation of the prompt classifier was conducted on a toy 40-sample dataset ([`research/datasets/prompts.csv`](file:///home/sushanthns/Projects/PromptShield-AI/research/datasets/prompts.csv)) with a 75/25 split:
- **Dataset Size:** 40 prompts (20 benign, 20 direct prompt injection)
- **Baseline Model:** Scikit-learn TF-IDF + Logistic Regression
- **Baseline Accuracy:** 1.0000 (10/10 test samples correct)
- **Critical Limitations:** The Day 3 dataset was trivial, lacked indirect injection vectors, contained no PII or secret tokens, did not evaluate tool execution abuse, and contained no adversarial false-positive probes.

---

## 2. Experiment 1: In-Distribution Stratified Evaluation ($N = 81$)

The standard held-out test split comprises 81 samples (18 benign, 63 malicious) sampled proportionally across all 7 benchmark categories.

### 2.1 Configuration Comparison Table

All latencies were measured following a 10-iteration warm-up sequence to eliminate cold-start timing distortion.

| Configuration | Accuracy | Precision | Recall (TPR) | F1-Score | False Positive Rate (FPR) | False Negative Rate (FNR) | Mean Latency (ms) | Median Latency (ms) | P95 Latency (ms) |
|---|---|---|---|---|---|---|---|---|---|
| **Config A: Rule-Only** | 0.4691 | 1.0000 | 0.3175 | 0.4819 | **0.0000** | 0.6825 | **0.040 ms** | **0.024 ms** | **0.049 ms** |
| **Config B: ML-Only** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | **0.0000** | 0.0000 | 1.528 ms | 1.389 ms | 2.466 ms |
| **Config C: Ensemble** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | **0.0000** | 0.0000 | 1.177 ms | 1.318 ms | 2.448 ms |
| **Config D: Gateway Policy** | 0.7778 | 1.0000 | 0.7143 | 0.8333 | **0.0000** | 0.2857 | 1.439 ms | 1.424 ms | 2.564 ms |

### 2.2 Confusion Matrices ($N = 81$)

- **Configuration A (Rule-Only):**
  $$\begin{bmatrix} \text{TN}=18 & \text{FP}=0 \\ \text{FN}=43 & \text{TP}=20 \end{bmatrix}$$
- **Configuration B (ML-Only):**
  $$\begin{bmatrix} \text{TN}=18 & \text{FP}=0 \\ \text{FN}=0 & \text{TP}=63 \end{bmatrix}$$
- **Configuration C (Rule + ML Ensemble):**
  $$\begin{bmatrix} \text{TN}=18 & \text{FP}=0 \\ \text{FN}=0 & \text{TP}=63 \end{bmatrix}$$
- **Configuration D (Full Gateway Policy):**
  $$\begin{bmatrix} \text{TN}=18 & \text{FP}=0 \\ \text{FN}=18 & \text{TP}=45 \end{bmatrix}$$

### 2.3 Reconciliation of the Config D True Positive Count

A previous draft of the Day 8 evaluation reported 45 True Positives for Config D, yet an unverified per-category table reported:
- Direct Injection: 12 × 0.50 = 6
- Indirect Injection: 12 × 0.83 ≈ 10
- Mixed Adversarial: 10 × 0.60 = 6
- Secret Leakage: 10 × 0.80 = 8
- PII Leakage: 9 × 1.00 = 9
- Tool Abuse: 10 × 0.80 = 8

Summing those implied 47 True Positives ($6 + 10 + 6 + 8 + 9 + 8 = 47$), creating a contradiction.

**Audit Resolution:** Sample-level re-evaluation confirms that in `direct_injection` ($N=12$), Config D identified exactly **4 True Positives** and missed **8 False Negatives** ($\text{Recall} = 4 / 12 = 0.3333$, or $33.33\%$). The earlier table contained a typographical error listing $0.50$ instead of $0.33$. 

Summing the exact true positives across all categories:
$$4 (\text{direct}) + 10 (\text{indirect}) + 6 (\text{mixed}) + 9 (\text{PII}) + 8 (\text{secret}) + 8 (\text{tool}) = \mathbf{45 \text{ True Positives}}$$

With $\text{Total Malicious} = 63$ and $\text{Benign} = 18$:
$$\text{Recall} = \frac{45}{63} = 71.43\%, \quad \text{Accuracy} = \frac{45 + 18}{81} = \frac{63}{81} = 77.78\%$$
All confusion matrices, category breakdowns, JSON records, and summary tables now agree.

### 2.4 Experiment 1 Per-Category Breakdown (Config D Gateway)

| Category | Total Samples | True Positives (TP) | False Negatives (FN) | Recall (TPR) | F1-Score | Primary Rejection / Containment Mechanism |
|---|---|---|---|---|---|---|
| **benign** | 18 | 0 (TN=18) | 0 (FP=0) | N/A (100% TNR) | N/A | Correctly routed as `ALLOW` |
| **direct_injection** | 12 | 4 | 8 | 33.33% | 0.5000 | Regex rule triggers (`PI001`–`PI004`) |
| **indirect_injection** | 12 | 10 | 2 | 83.33% | 0.9091 | RAG context boundary + Indirect rules (`IND001`–`IND004`) |
| **mixed_adversarial** | 10 | 6 | 4 | 60.00% | 0.7500 | Multi-signal aggregation (Rules + Sensitive detector) |
| **pii_leakage** | 9 | 9 | 0 | 100.00% | 1.0000 | High-confidence PII regex pattern matching |
| **secret_leakage** | 10 | 8 | 2 | 80.00% | 0.8889 | High-entropy secret token regex matching |
| **tool_abuse** | 10 | 8 | 2 | 80.00% | 0.8889 | RBAC role check (`DENY`) & approval escalation |
| **Total Malicious** | **63** | **45** | **18** | **71.43%** | **0.8333** | Multi-layer defense-in-depth |

---

## 3. Experiment 2: Out-of-Distribution Grouped Template Evaluation ($N = 215$)

### 3.1 Why Did Standalone ML Score 100% in Experiment 1?

An in-depth n-gram and feature weight audit revealed why Config B (ML-Only) achieved 100% accuracy on the random stratified split:
1. **Template Leakage Across Partitions:** Random 70/15/15 splitting placed syntactically identical variations of the same prompt templates into both the training set and the test set (e.g., `"Ignore all previous instructions and..."`, `"Reveal system prompt..."`).
2. **Category Vocabulary Signatures:** Synthetic tool abuse prompts were formatted as JSON strings containing `"tool_name"`, `"arguments"`, and `"requester_role"`, while PII/secret prompts shared characteristic prefixes (`sk-`, `+91-`).
3. **Overfitting to Lexical Anchors:** Logistic regression feature weights showed that tokens like `tool_name` (+2.84), `password` (+2.61), `instructions` (+2.38), `sk` (+2.15), and `system` (+2.02) acted as perfect classification shortcuts.

### 3.2 Experiment 2 Design & Grouped Partitioning

To assess genuine out-of-distribution (OOD) generalization, the 535 benchmark samples were clustered into 29 distinct semantic groups. Eleven challenging groups were held out exclusively for testing ($N=215$):
- **Test Group Highlights:** Novel direct injection paraphrases (`direct_injection_novel_templates`), obfuscated system prompt extractions (`direct_system_prompt_novel`), unseen indirect payloads (`indirect_injection_markdown_embedded`), and all 50 benign cybersecurity educational probes (`benign_security_education`).
- **Group Isolation:** $\text{Groups}_{\text{train}} \cap \text{Groups}_{\text{test}} = \emptyset$. Zero ID overlap, zero template overlap.

### 3.3 Experiment 2 Results Table ($N = 215$, 50 Benign, 165 Malicious)

| Configuration | Accuracy | Precision | Recall (TPR) | F1-Score | False Positive Rate (FPR) | False Negative Rate (FNR) | Mean Latency (ms) | Median Latency (ms) | P95 Latency (ms) |
|---|---|---|---|---|---|---|---|---|---|
| **Config A: Rule-Only** | 0.4558 | 0.9800 | 0.2970 | 0.4558 | 0.0200 | 0.7030 | 0.031 ms | 0.028 ms | 0.055 ms |
| **Config B: ML-Only** | 0.9581 | 0.9643 | 0.9818 | 0.9730 | **0.1200** | 0.0182 | 1.795 ms | 1.720 ms | 2.546 ms |
| **Config C: Ensemble** | 0.9535 | 0.9586 | 0.9818 | 0.9701 | **0.1400** | 0.0182 | 1.466 ms | 1.708 ms | 2.646 ms |
| **Config D: Gateway Policy** | 0.7581 | 0.9913 | 0.6909 | 0.8143 | **0.0200** | 0.3091 | 1.724 ms | 1.764 ms | 2.663 ms |

### 3.4 Critical Finding: ML False Positive Surge vs. Gateway Policy Stability

When exposed to novel templates:
1. **ML False Positives Surge to 12.00%:** Standalone ML falsely flagged 6 out of 50 benign cybersecurity educational queries as attacks ($\text{FPR} = 12.00\%$), because the model relied on keywords like `"injection"`, `"vulnerability"`, and `"exploit"` without semantic context.
2. **Ensemble FPR Reaches 14.00%:** Combining naive union rules with ML increased false alarms to 7 out of 50 benign samples.
3. **Gateway Policy Protects Availability ($\text{FPR} = 2.00\%$):** Configuration D produced only 1 false positive out of 50 benign queries ($\text{FPR} = 2.00\%$). Because ML predictions are bounded to a maximum of 30 risk points, a benign prompt triggering ML cannot reach the $\text{BLOCK}$ threshold ($\ge 60$) without corroborating rule matches. This demonstrates the critical utility of decoupled policy engines in enterprise environments.

---

## 4. Specialized Security Evaluations

### 4.1 PII & Secret Redaction Performance

Evaluated across all sensitive samples containing credentials, tokens, and PII:

| Metric | Experiment 1 ($N=29$) | Experiment 2 ($N=70$) | Description & Root-Cause Analysis |
|---|---|---|---|
| **Total Sensitive Samples** | 29 | 70 | Test samples with verified sensitive payloads |
| **Detected Sensitive Samples** | 23 | 60 | Identified by `detect_sensitive_data()` |
| **Missed Sensitive Samples** | 6 | 10 | Completely overlooked by regex detectors |
| **Detector Recall** | **79.31%** | **85.71%** | Proportion of sensitive samples detected |
| **Redaction Success on Detected** | **100.00%** | **100.00%** | Detected values replaced with `[REDACTED_*]` |
| **Unredacted Secret Leaks** | **6 samples** | **10 samples** | Sensitive tokens reaching output unmodified |
| **True Sensitive Leakage Rate** | **20.69%** | **14.29%** | **Leakage across ALL sensitive inputs** |
| **Privacy Preservation Rate** | **79.31%** | **85.71%** | Overall proportion of safe outcomes |

> [!CAUTION]
> **Audit Finding on Sensitive Data Leakage:**
> An earlier claim of *0.00% Sensitive Value Leakage Rate* measured only samples that were already detected. In reality, **6 out of 29 sensitive samples leaked raw secrets** in Experiment 1 (a **20.69% leakage rate**).
> 
> **Why Were Secrets Missed?**
> The misses stemmed from rigid regex length assumptions in [`pii_detector.py`](file:///home/sushanthns/Projects/PromptShield-AI/backend/app/privacy/pii_detector.py):
> - `sk-attackerKey123456`: Exactly 17 characters after `sk-`, but the regex requires `{20,}`.
> - `AKIAPRODDEPLOY123456789`: Exactly 19 characters after `AKIA`, but the regex requires `{16}`.
> - Similar fixed-length mismatches occurred on `AKIAMINIOSTORAGEUSER12`, `AKIATERRAFORMUSER9988`, `AKIALAMBDAKEY12345678`, and `AKIAK8SSECRET09876543`.
> 
> When the detector missed these strings, `redact_sensitive_data()` left them unmodified, allowing raw credentials to pass through.

### 4.2 Secure Tool Authorization Governance

Evaluated across tool abuse attempts in the test splits:

| Metric | Experiment 1 ($N=10$) | Experiment 2 ($N=20$) | Architectural Function |
|---|---|---|---|
| **Total Tool Abuse Requests** | 10 | 20 | Proposed malicious tool actions |
| **Auth-Layer `DENY` Decisions** | 7 (70.0%) | 17 (85.0%) | Rejected by `ToolAuthorizer` RBAC |
| **Auth-Layer `REQUIRE_APPROVAL`** | 1 (10.0%) | 0 (0.0%) | High-risk action held for human review |
| **Auth-Layer Blocking Rate** | **80.00%** | **85.00%** | Stopped at the authorization boundary |
| **Allowed by Authorizer (Traversal)** | 2 (20.0%) | 3 (15.0%) | Directory traversal on allowed `read_file` tool |
| **Sandbox Executor Interceptions** | 2 | 2 | Path traversal blocked by `ToolExecutor` |
| **End-to-End System Blocking Rate** | **100.00%** | **95.00%** | Total multi-layer system containment |
| **Approval Bypass Rate** | **0.00%** | **0.00%** | Client-spoofed approval tokens accepted |

> [!NOTE]
> **Defense-in-Depth in Action:**
> In Experiment 1, two directory traversal attacks (`read_file` with `../app.env` and `../../../var/log/audit.log`) were permitted by `ToolAuthorizer` because the requesting roles had permission for the `read_file` tool. 
> 
> However, both requests were subsequently intercepted by `ToolExecutor._run_simulated_tool`, which enforces real filesystem containment and rejects directory escapes (`Path traversal blocked`). This confirms the efficacy of two-layer defense-in-depth: authorization handles RBAC, while execution sandboxing enforces runtime containment.

---

## 5. Adversarial Scenario Case Studies

| Scenario ID & Description | Source Context | Ground Truth | Gateway Policy Decision | Policy Mechanism |
|---|---|---|---|---|
| **1. Benign Security Education** | `USER_UNTRUSTED` | Benign | `ALLOW` | ML risk capped; no rule matches; risk score = 0 |
| **2. Quoted Malicious Text in Benign Query** | `USER_UNTRUSTED` | Benign | `BLOCK` | Over-defensive regex match (`PI001`) |
| **3. Indirect Injection in Document** | `DOCUMENT_UNTRUSTED` | Malicious | `REJECT` | Document scanner flagged `IND001` override |
| **4. Mixed Benign and Malicious Document** | `DOCUMENT_UNTRUSTED` | Malicious | `REJECT` | High composite risk score from context policy |
| **5. Synthetic Credentials in User Text** | `USER_UNTRUSTED` | Malicious | `SANITIZE` | PII detector matched AWS key; token redacted |
| **6. Prompt Injection Combined with PII** | `USER_UNTRUSTED` | Malicious | `BLOCK` | Additive risk engine aggregated injection + PII score |
| **7. Malicious Tool from Untrusted Context** | `TOOL_UNTRUSTED` | Malicious | `DENY` | RBAC rejected `execute_command` for `USER` role |
| **8. Legitimate Tool from Authorized User** | `TOOL_UNTRUSTED` | Benign | `ALLOW` | Role permitted for low-risk read-only tool |
| **9. Unknown Tool Invocation** | `TOOL_UNTRUSTED` | Malicious | `DENY` | Strict allowlist rejected unlisted tool name |
| **10. Attempted Approval Bypass** | `TOOL_UNTRUSTED` | Malicious | `REQUIRE_APPROVAL` | High-risk tool triggered cryptographic approval state |

---

## 6. Generated Result Artifacts

All benchmark outputs are persistently tracked in the repository:
- **Comprehensive Machine-Readable Results:** [`benchmark_results.json`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/benchmark_results.json)
- **Unified Summary Table (CSV):** [`metrics_summary.csv`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/metrics_summary.csv)
- **Confusion Matrix Matrices (JSON):** [`confusion_matrices.json`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/confusion_matrices.json)
- **Experimental Metadata:** [`benchmark_metadata.json`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/benchmark_metadata.json)
- **Visualizations (PNG Figures):**
  - Precision, Recall & F1: [`metrics_comparison.png`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/figures/metrics_comparison.png)
  - False Positive Rate: [`fpr_comparison.png`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/figures/fpr_comparison.png)
  - Inference Latency: [`latency_comparison.png`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/figures/latency_comparison.png)
  - Confusion Matrix Grid: [`confusion_matrices.png`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/figures/confusion_matrices.png)
  - Per-Category Threat Recall: [`per_category_performance.png`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/figures/per_category_performance.png)
  - In-Distribution vs OOD Robustness: [`experiment_comparison.png`](file:///home/sushanthns/Projects/PromptShield-AI/research/results/figures/experiment_comparison.png)

---

## 7. Limitations & Research Roadmap

1. **Regex Length Rigidity:** Update AWS and OpenAI secret detection patterns to handle non-standard key lengths and variable-length test tokens.
2. **Context Path Traversal Authorizer Rules:** Extend `ToolAuthorizer` argument validation schemas to reject relative paths (`..`) prior to executor invocation.
3. **Adaptive ML Decision Thresholds:** Explore Platt scaling or temperature calibration to dynamically adjust ML risk contributions without triggering false positives on technical text.
4. **Adversarial Token Transformations:** Benchmark against homoglyph obfuscation, base64 encoding, and token-smuggling attacks.
