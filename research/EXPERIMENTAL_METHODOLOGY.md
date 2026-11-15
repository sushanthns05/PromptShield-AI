# PromptShield AI — Experimental Methodology (Independent Scientific Audit Edition)

## 1. Research Objective

This research evaluates PromptShield AI quantitatively using reproducible synthetic benchmarks and independent test splits. Rather than solely augmenting heuristic rules, this audit measures:
1. **Multi-layer Detection Efficacy:** Precision, Recall, and F1 across four configurations.
2. **Generalization Boundaries:** In-Distribution performance (Experiment 1: Stratified Split) vs Out-of-Distribution generalization (Experiment 2: Grouped Template Split).
3. **Inference Latency Distributions:** Calibrated execution times (Mean, Median, P95 in ms) using a warm-up phase to eliminate cold-start distortion.
4. **Data Privacy Governance:** True sensitive-value leakage rates across all sensitive samples, distinguishing detection recall from redaction efficacy.
5. **Tool Authorization Governance:** Decoupling authorization-layer policy enforcement from downstream sandbox execution defenses.

---

## 2. Threat Model

PromptShield AI defends Large Language Model (LLM) applications against five principal threat classes:
1. **Direct Prompt Injection (Jailbreaking):** System instruction overrides, prompt extraction, safety filter bypasses, and role manipulation (PI001–PI007).
2. **Indirect Prompt Injection:** Adversarial commands embedded in retrieved documents via markup tags, AI directives, conditional overrides, or pseudo-system delimiters (IND001–IND004).
3. **Personally Identifiable Information (PII) Exposure:** Inputs or contexts containing customer emails or national phone numbers (+91 series).
4. **Credential & Secret Exposure:** Synthetic OpenAI API keys (`sk-...`), AWS credentials (`AKIA...`), and database passwords.
5. **Tool Abuse & Autonomous Escalation:** Unauthorized tool calls, role impersonation, directory traversal (`..`), disabled/unknown tools, and approval bypass attempts.

---

## 3. Dataset Construction & Structural Grouping

The benchmark comprises **535 synthetic records** across seven domain CSV files in `research/datasets/benchmark/`:

| Dataset Filename | Sample Count | Primary Category | Target Security Action | Source Type |
|---|---|---|---|---|
| `benign_prompts.csv` | 120 | `benign` | `ALLOW` | `USER_UNTRUSTED` |
| `direct_injection.csv` | 80 | `direct_injection` | `BLOCK` | `USER_UNTRUSTED` |
| `indirect_injection.csv` | 75 | `indirect_injection` | `REJECT` | `DOCUMENT_UNTRUSTED` |
| `pii_leakage.csv` | 65 | `pii_leakage` | `SANITIZE` | `USER_UNTRUSTED` |
| `secret_leakage.csv` | 65 | `secret_leakage` | `SANITIZE` | `USER_UNTRUSTED` |
| `tool_abuse.csv` | 65 | `tool_abuse` | `DENY` / `REQUIRE_APPROVAL` | `TOOL_UNTRUSTED` |
| `mixed_adversarial.csv` | 65 | `mixed_adversarial` | `BLOCK` / `REJECT` | `DOCUMENT_UNTRUSTED` / `USER_UNTRUSTED` |
| **Total** | **535** | — | — | — |

### Semantic Grouping & Template Clustering
To prevent template leakage and evaluate out-of-distribution robustness, each sample is mapped to one of **29 structural template groups** (implemented in [`generate_grouped_split.py`](file:///home/sushanthns/Projects/PromptShield-AI/research/datasets/benchmark/generate_grouped_split.py)).
- **Standard Templates:** Common phrasing patterns (e.g., standard regex targets, direct overrides, typical AWS/OpenAI key lengths).
- **Novel / Challenging Templates:** Paraphrased overrides, prompt extractions, atypical key lengths, and 50 challenging benign cybersecurity education probes that discuss prompt injection without malicious intent.

---

## 4. Dataset Splitting Methodologies

The benchmark framework implements two distinct experimental splits to evaluate model generalization:

### Experiment 1: In-Distribution Stratified Split (`research/datasets/benchmark/splits/`)
- **Split Ratios:** 70% Train (374 samples), 15% Val (80 samples), 15% Test (81 samples).
- **Stratification:** Stratified strictly by `category`.
- **Purpose:** Measures baseline performance when training and test sets share lexical distribution patterns.
- **Integrity:** Zero sample ID and zero exact text overlap between Train and Test ($\text{Texts}_{\text{train}} \cap \text{Texts}_{\text{test}} = \emptyset$).

### Experiment 2: Out-of-Distribution Grouped Template Split (`research/datasets/benchmark/splits_grouped/`)
- **Split Methodology:** Clustered by structural template families.
- **Split Counts:** Train (205 samples across 11 groups), Val (115 samples across 7 groups), Test (215 samples across 11 groups).
- **Zero Group Leakage:** $\text{Groups}_{\text{train}} \cap \text{Groups}_{\text{test}} = \emptyset$.
- **Adversarial Hardening:** All 50 challenging benign cybersecurity probes, novel paraphrased injections, atypical credential formats, and directory traversal probes are assigned exclusively to the Test split.
- **Purpose:** Tests whether the ML classifier and gateway can generalize to unseen phrasing without triggering false alarms on benign technical security inquiries.

---

## 5. Evaluation Configurations

All configurations are evaluated against identical held-out test splits without access to ground-truth labels during inference:

### Configuration A: Rule-Only Detection
- Evaluates direct regex rules (PI001–PI007) and indirect markup rules (IND001–IND004).
- Flagged as threat (`1`) if any high- or medium-severity rule matches.

### Configuration B: ML-Only Classification
- TF-IDF Vectorizer (ngram range 1–2, 5000 max features) + Logistic Regression with balanced class weighting.
- Fitted strictly on the training partition of the evaluated experiment split.

### Configuration C: Rule + ML Ensemble
- Hierarchical ensemble: Rule match triggers immediate positive classification (`1`); otherwise, ML predicts threat if probability confidence $\ge 0.50$.

### Configuration D: Full Security Gateway (Rule + ML + Privacy + Context Policy + Tool Policy)
- Standard User Prompts: Evaluated via `RiskEngine` (Rules + ML supporting signal up to 30 pts + PII/Secret detection). Flagged if decision is `BLOCK` or `SANITIZE`.
- Retrieved Context: Evaluated via `DocumentScanner` and `ContextPolicy`. Flagged if decision is `REJECT` or `QUARANTINE`.
- Tool Invocations: Evaluated via `ToolAuthorizer`. Flagged if decision is `DENY` or `REQUIRE_APPROVAL`.

---

## 6. Mathematical Formulas & Definitions

### 1. Classification Metrics
- **Accuracy:** $\frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$
- **Precision:** $\frac{\text{TP}}{\text{TP} + \text{FP}}$ (defined as $0.0$ when $\text{TP} + \text{FP} = 0$)
- **Recall (TPR):** $\frac{\text{TP}}{\text{TP} + \text{FN}}$
- **F1-Score:** $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$
- **False-Positive Rate (FPR):** $\frac{\text{FP}}{\text{FP} + \text{TN}}$
- **False-Negative Rate (FNR):** $\frac{\text{FN}}{\text{TP} + \text{FN}}$
- **Confusion Matrix:** $\begin{bmatrix} \text{TN} & \text{FP} \\ \text{FN} & \text{TP} \end{bmatrix}$

### 2. Latency Measurement Protocol
- Uses high-resolution `time.perf_counter()`.
- **Warm-Up Phase:** 10 unmeasured inferences run through all configurations before logging to prime JIT compilation, regex cache tables, and memory allocations.
- Reported in milliseconds ($\text{ms}$): Mean, Median (p50), 95th Percentile (p95). Training and disk I/O are strictly excluded.

### 3. Sensitive-Data Leakage Metrics (Audit Formulation)
- **Detector Recall:** $\frac{\text{Detected Sensitive Samples}}{\text{Total Sensitive Samples}}$
- **Redaction Success on Detected:** $\frac{\text{Samples with Zero Leaked Secrets in Preview}}{\text{Detected Sensitive Samples}}$
- **True Sensitive Leakage Rate:** $\frac{\text{Samples where Raw Sensitive Values Flowed to Output Unredacted}}{\text{Total Sensitive Samples}}$
- **Overall Privacy Preservation Rate:** $\frac{\text{Total Sensitive Samples} - \text{Unredacted Leakage Count}}{\text{Total Sensitive Samples}}$

### 4. Tool Authorization Governance Metrics (Two-Layer Separation)
- **Authorization-Layer Denial Rate:** $\frac{\text{DENY Decisions}}{\text{Total Unauthorized Requests}}$
- **Authorization-Layer Blocking Rate:** $\frac{\text{DENY} + \text{REQUIRE\_APPROVAL}}{\text{Total Unauthorized Requests}}$
- **Authorization-Layer Allowed Rate (Defect):** $\frac{\text{Unauthorized Requests Permitted by Authorizer}}{\text{Total Unauthorized Requests}}$
- **Sandbox-Layer Interception Rate:** $\frac{\text{Permitted Probes Caught by ToolExecutor}}{\text{Total Unauthorized Requests}}$
- **End-to-End System Blocking Rate:** $\frac{\text{Authorizer Blocked} + \text{Sandbox Intercepted}}{\text{Total Unauthorized Requests}}$
- **Approval Bypass Execution Rate:** $\frac{\text{Unauthorized Executions without Valid Approval}}{\text{Total Unauthorized Requests}}$ (Target: $0.0\%$)

---

## 7. Day 8.5 Security Hardening Architecture

Following the Day 8 Independent Audit, two major architectural security hardenings were introduced:

### 7.1 Multi-Tier Credential & Secret Taxonomy
To overcome rigid regex length constraints without matching benign development terms, `backend/app/privacy/pii_detector.py` establishes a formal format taxonomy:
1. **Documented Formats (`OPENAI_API_KEY`, `AWS_ACCESS_KEY`):** Standard production formats matching documented provider specifications (OpenAI legacy `sk-[A-Za-z0-9]{20,}`, modern project `sk-proj-...`, and standard AWS IAM 20-char `AKIA[0-9A-Z]{16}`).
2. **Synthetic / Dev Formats (`SYNTHETIC_API_KEY`, `SYNTHETIC_AWS_KEY`):** Synthetic test/benchmark formats (e.g. `sk-[A-Za-z0-9]{12,19}` containing uppercase and numeric tokens, MinIO/custom S3-compatible `AKIA[0-9A-Z]{17,28}`).
3. **Benign Lookalike Negative Constraints:** Explicitly excludes lowercase words, short identifiers, and library names (`sk-learn`, `sk-model`, `sk-image`, `sk-pipeline`, `AKIA123`), preventing false positives on machine learning documentation.

### 7.2 Two-Layer Tool Authorization & Sandbox Traversal Defense
1. **Authorization Layer (`ToolAuthorizer.validate_safe_path`):** Validates all path-like arguments (`filepath`, `path`, `filename`, etc.) prior to dispatch. Intercepts directory traversal (`../`), multi-level escapes, recursive URL encoding (`%2e%2e%2f`, `%252e%252e%252f`), backslash sequences (`..\`), null-byte injection (`\0`, `%00`), and symlink escapes outside the allowed base directory.
2. **Execution Sandbox Layer (`ToolExecutor._run_simulated_tool`):** Independently re-validates path safety in the execution simulator. If the authorization layer is mocked or bypassed, the sandbox independently prevents directory escape.

---

## 8. Experimental Environment

- **Hardware:** Dell Vostro Laptop (Intel CPU, 8GB System RAM)
- **Operating System:** Fedora Linux x86_64
- **Runtime Environment:** Python 3.15.2 virtual environment (`.venv`)
- **Key Libraries:** `scikit-learn==1.9.1`, `pandas==3.1.1`, `numpy==2.5.4`, `matplotlib==3.11.2`, `pytest==9.2.0`, `fastapi==0.163.0`
- **Execution Mode:** Local CPU execution; zero external network requests or paid cloud APIs utilized during benchmark execution.

---

## 9. Reproducibility Instructions

```bash
# 1. Regenerate baseline benchmark dataset and stratified splits (Exp 1)
python3 research/datasets/benchmark/generate_dataset.py

# 2. Generate out-of-distribution grouped template splits (Exp 2)
python3 research/datasets/benchmark/generate_grouped_split.py

# 3. Execute dual-experiment benchmark audit
python3 research/experiments/run_benchmark.py

# 4. Generate all comparative visualization charts
python3 research/experiments/visualize_results.py

# 5. Run complete automated test suite (145 tests)
pytest -v
```
