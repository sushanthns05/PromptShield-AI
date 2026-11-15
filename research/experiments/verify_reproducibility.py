"""
PromptShield AI — Independent Benchmark Reproducibility Verifier
Executes consecutive evaluation passes under identical environment parameters and verifies
deterministic reproducibility across all metrics, confusion matrices, and security checks.
"""

import hashlib
import json
import logging
from pathlib import Path
import platform
import sys
from typing import Any
import numpy as np
import pandas as pd
import sklearn

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.experiments.run_benchmark import BenchmarkPipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("promptshield.reproducibility")

BENCHMARK_DIR = PROJECT_ROOT / "research" / "datasets" / "benchmark"
RESULTS_DIR = PROJECT_ROOT / "research" / "results"


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_dataset_inventory() -> dict[str, Any]:
    """Catalog and compute cryptographic hashes for all benchmark datasets and splits."""
    inventory = {}
    for csv_file in sorted(BENCHMARK_DIR.rglob("*.csv")):
        rel_path = csv_file.relative_to(PROJECT_ROOT).as_posix()
        df = pd.read_csv(csv_file)
        inventory[rel_path] = {
            "sha256": compute_sha256(csv_file),
            "rows": len(df),
            "columns": list(df.columns),
        }
    return inventory


def run_single_iteration(iteration_id: int) -> dict[str, Any]:
    """Execute a complete independent benchmark run."""
    logger.info(f"--- Starting Reproducibility Run {iteration_id} ---")
    pipeline = BenchmarkPipeline()
    results = pipeline.run_all_experiments()
    return results


def verify_reproducibility() -> dict[str, Any]:
    """Run benchmark twice and verify zero-variance determinism across all metrics."""
    logger.info("Verifying benchmark dataset integrity and calculating SHA-256 hashes...")
    dataset_inventory = get_dataset_inventory()

    env_details = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "scikit_learn_version": sklearn.__version__,
        "numpy_version": np.__version__,
        "pandas_version": pd.__version__,
        "random_seed": 42,
    }

    # Execute Run 1 and Run 2
    run1 = run_single_iteration(1)
    run2 = run_single_iteration(2)

    discrepancies: list[dict[str, Any]] = []

    configs = ["Config_A_Rules", "Config_B_ML", "Config_C_Ensemble", "Config_D_Gateway"]
    metric_keys = [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "true_positives",
        "false_positives",
        "true_negatives",
        "false_negatives",
    ]

    # 1. Compare Experiment 1 (Stratified) Configurations
    exp1_run1 = run1["experiment_1_stratified"]["configurations"]
    exp1_run2 = run2["experiment_1_stratified"]["configurations"]

    for cfg in configs:
        res1 = exp1_run1[cfg]["classification_metrics"]
        res2 = exp1_run2[cfg]["classification_metrics"]

        for m in metric_keys:
            val1 = res1[m]
            val2 = res2[m]
            if val1 != val2:
                discrepancies.append({
                    "experiment": "Experiment_1_Stratified",
                    "configuration": cfg,
                    "metric": m,
                    "run1": val1,
                    "run2": val2,
                })

        cm1 = res1["confusion_matrix"]
        cm2 = res2["confusion_matrix"]
        if cm1 != cm2:
            discrepancies.append({
                "experiment": "Experiment_1_Stratified",
                "configuration": cfg,
                "confusion_matrix": "mismatch",
                "run1": cm1,
                "run2": cm2,
            })

    # 2. Compare Experiment 2 (Grouped OOD) Configurations
    exp2_run1 = run1["experiment_2_grouped_ood"]["configurations"]
    exp2_run2 = run2["experiment_2_grouped_ood"]["configurations"]

    for cfg in configs:
        res1 = exp2_run1[cfg]["classification_metrics"]
        res2 = exp2_run2[cfg]["classification_metrics"]

        for m in metric_keys:
            val1 = res1[m]
            val2 = res2[m]
            if val1 != val2:
                discrepancies.append({
                    "experiment": "Experiment_2_Grouped_OOD",
                    "configuration": cfg,
                    "metric": m,
                    "run1": val1,
                    "run2": val2,
                })

        cm1 = res1["confusion_matrix"]
        cm2 = res2["confusion_matrix"]
        if cm1 != cm2:
            discrepancies.append({
                "experiment": "Experiment_2_Grouped_OOD",
                "configuration": cfg,
                "confusion_matrix": "mismatch",
                "run1": cm1,
                "run2": cm2,
            })

    # 3. Compare PII and Credential Detection & Leakage Metrics
    pii1 = run1["experiment_1_stratified"]["pii_secret_evaluation"]
    pii2 = run2["experiment_1_stratified"]["pii_secret_evaluation"]
    for k in [
        "total_sensitive_samples",
        "detected_samples",
        "missed_samples",
        "redaction_success_on_detected",
        "unredacted_leakage_count",
        "overall_leakage_rate",
        "overall_privacy_preservation_rate",
    ]:
        if pii1[k] != pii2[k]:
            discrepancies.append({
                "section": "pii_secret_evaluation",
                "field": k,
                "run1": pii1[k],
                "run2": pii2[k],
            })

    # 4. Compare Tool Authorization & Governance Metrics
    tool1 = run1["experiment_1_stratified"]["tool_policy_evaluation"]
    tool2 = run2["experiment_1_stratified"]["tool_policy_evaluation"]
    for k in [
        "total_tool_requests",
        "auth_layer_deny_count",
        "auth_layer_require_approval_count",
        "auth_layer_allowed_unauthorized",
        "auth_layer_blocking_rate",
        "sandbox_executor_interception_count",
        "end_to_end_system_blocking_rate",
        "approval_bypass_rate",
    ]:
        if tool1[k] != tool2[k]:
            discrepancies.append({
                "section": "tool_policy_evaluation",
                "field": k,
                "run1": tool1[k],
                "run2": tool2[k],
            })

    # 5. Compare Adversarial Scenario Decisions
    scenarios1 = run1["adversarial_scenarios_evaluation"]
    scenarios2 = run2["adversarial_scenarios_evaluation"]
    for s_name in scenarios1:
        s1 = scenarios1[s_name]
        s2 = scenarios2.get(s_name, {})
        for field in ["expected", "gateway_threat_flag"]:
            if s1.get(field) != s2.get(field):
                discrepancies.append({
                    "section": "adversarial_scenarios",
                    "scenario": s_name,
                    "field": field,
                    "run1": s1.get(field),
                    "run2": s2.get(field),
                })

    is_perfectly_reproducible = (len(discrepancies) == 0)

    # Latency comparison (physical time has minor variance, measure delta)
    latency_comparison = {}
    for cfg in configs:
        l1 = exp1_run1[cfg]["latency_metrics"]["mean_ms"]
        l2 = exp1_run2[cfg]["latency_metrics"]["mean_ms"]
        latency_comparison[cfg] = {
            "run1_mean_ms": l1,
            "run2_mean_ms": l2,
            "delta_ms": round(abs(l1 - l2), 4),
        }

    report = {
        "verification_timestamp_utc": pd.Timestamp.now(tz="UTC").isoformat(),
        "is_perfectly_reproducible": is_perfectly_reproducible,
        "discrepancy_count": len(discrepancies),
        "discrepancies": discrepancies,
        "environment": env_details,
        "dataset_inventory": dataset_inventory,
        "latency_stability": latency_comparison,
        "run1_summary": {
            "exp1_stratified": {
                cfg: exp1_run1[cfg]["classification_metrics"] for cfg in configs
            },
            "exp2_grouped_ood": {
                cfg: exp2_run1[cfg]["classification_metrics"] for cfg in configs
            },
            "privacy": pii1,
            "tool_governance": tool1,
        },
        "run2_summary": {
            "exp1_stratified": {
                cfg: exp1_run2[cfg]["classification_metrics"] for cfg in configs
            },
            "exp2_grouped_ood": {
                cfg: exp2_run2[cfg]["classification_metrics"] for cfg in configs
            },
            "privacy": pii2,
            "tool_governance": tool2,
        },
    }

    report_path = RESULTS_DIR / "reproducibility_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Reproducibility report saved to {report_path}")
    if is_perfectly_reproducible:
        logger.info("SUCCESS: 100% mathematical reproducibility confirmed between Run 1 and Run 2!")
    else:
        logger.error(f"FAILURE: {len(discrepancies)} discrepancies detected between Run 1 and Run 2.")

    return report


if __name__ == "__main__":
    rep = verify_reproducibility()
    if not rep["is_perfectly_reproducible"]:
        sys.exit(1)
