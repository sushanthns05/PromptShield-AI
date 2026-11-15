"""
PromptShield AI — Benchmark Visualization Suite (Audit Edition)
Generates publication-quality charts from actual experimental benchmark outputs:
1. Precision, Recall, and F1 Score Comparison (Exp 1: Stratified)
2. False-Positive Rate (FPR) Comparison across Configurations
3. Latency Distribution Comparison (Mean, Median, P95 in ms with warm-up calibration)
4. Confusion Matrix Grid for All 4 Configurations
5. Per-Category Detection Performance
6. In-Distribution vs Out-of-Distribution (OOD Grouped) Robustness Comparison
"""

import json
import os
from pathlib import Path
import sys

os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless execution
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJECT_ROOT / "research" / "results"
FIGURES_DIR = RESULTS_DIR / "figures"
BENCHMARK_FILE = RESULTS_DIR / "benchmark_results.json"


def load_results() -> dict:
    if not BENCHMARK_FILE.exists():
        raise FileNotFoundError(
            f"Benchmark results file not found at {BENCHMARK_FILE}. Run run_benchmark.py first."
        )
    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def plot_metrics_comparison(results: dict):
    """Chart 1: Precision, Recall, and F1 Comparison across Configurations."""
    configs = list(results["configurations"].keys())
    display_names = [c.replace("Config_", "").replace("_", " ") for c in configs]

    precisions = [results["configurations"][c]["classification_metrics"]["precision"] for c in configs]
    recalls = [results["configurations"][c]["classification_metrics"]["recall"] for c in configs]
    f1s = [results["configurations"][c]["classification_metrics"]["f1"] for c in configs]

    x = np.arange(len(configs))
    width = 0.25

    fig, ax = plt.subplots(figsize=(9, 5))
    rects1 = ax.bar(x - width, precisions, width, label="Precision", color="#2b5c8f")
    rects2 = ax.bar(x, recalls, width, label="Recall", color="#3b9ab2")
    rects3 = ax.bar(x + width, f1s, width, label="F1-Score", color="#e15759")

    ax.set_ylabel("Score (0.0 - 1.0)", fontsize=11, fontweight="bold")
    ax.set_title("PromptShield AI: Precision, Recall, and F1 by Configuration", fontsize=13, fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(display_names, fontsize=10)
    ax.set_ylim(0, 1.15)
    ax.legend(loc="upper left", frameon=True)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    def autolabel(rects):
        for rect in rects:
            h = rect.get_height()
            ax.annotate(
                f"{h:.2f}",
                xy=(rect.get_x() + rect.get_width() / 2, h),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center", va="bottom",
                fontsize=8, fontweight="bold",
            )

    autolabel(rects1)
    autolabel(rects2)
    autolabel(rects3)

    plt.tight_layout()
    out_path = FIGURES_DIR / "metrics_comparison.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved: {out_path.name}")


def plot_fpr_comparison(results: dict):
    """Chart 2: False-Positive Rate (FPR) Comparison across Configurations."""
    configs = list(results["configurations"].keys())
    display_names = [c.replace("Config_", "").replace("_", " ") for c in configs]
    fprs = [
        results["configurations"][c]["classification_metrics"]["false_positive_rate"] * 100.0
        for c in configs
    ]

    colors = ["#4e79a7", "#59a14f", "#edc948", "#e15759"]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.bar(display_names, fprs, color=colors, width=0.45, edgecolor="black", linewidth=0.8)

    ax.set_ylabel("False Positive Rate (%)", fontsize=11, fontweight="bold")
    ax.set_title("PromptShield AI: False Positive Rate across Configurations (Exp 1)", fontsize=13, fontweight="bold", pad=15)
    ax.set_ylim(0, max(5.0, max(fprs) * 1.5 if fprs else 5.0))
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    for bar in bars:
        h = bar.get_height()
        ax.annotate(
            f"{h:.2f}%",
            xy=(bar.get_x() + bar.get_width() / 2, h),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center", va="bottom",
            fontsize=9, fontweight="bold",
        )

    plt.tight_layout()
    out_path = FIGURES_DIR / "fpr_comparison.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved: {out_path.name}")


def plot_latency_comparison(results: dict):
    """Chart 3: Latency Distribution Comparison (Mean, Median, P95 in ms)."""
    configs = list(results["configurations"].keys())
    display_names = [c.replace("Config_", "").replace("_", " ") for c in configs]

    means = [results["configurations"][c]["latency_metrics"]["mean_ms"] for c in configs]
    medians = [results["configurations"][c]["latency_metrics"]["median_ms"] for c in configs]
    p95s = [results["configurations"][c]["latency_metrics"]["p95_ms"] for c in configs]

    x = np.arange(len(configs))
    width = 0.25

    fig, ax = plt.subplots(figsize=(9, 5))
    r1 = ax.bar(x - width, means, width, label="Mean Latency (ms)", color="#4e79a7")
    r2 = ax.bar(x, medians, width, label="Median Latency (ms)", color="#76b7b2")
    r3 = ax.bar(x + width, p95s, width, label="95th Percentile (ms)", color="#f28e2b")

    ax.set_ylabel("Inference Latency (Milliseconds)", fontsize=11, fontweight="bold")
    ax.set_title("PromptShield AI: Calibrated Inference Latency across Configurations", fontsize=13, fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(display_names, fontsize=10)
    max_lat = max(max(means), max(p95s)) if means else 1.0
    ax.set_ylim(0, max_lat * 1.35)
    ax.legend(loc="upper left", frameon=True)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    def autolabel(rects):
        for rect in rects:
            h = rect.get_height()
            ax.annotate(
                f"{h:.2f}ms",
                xy=(rect.get_x() + rect.get_width() / 2, h),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center", va="bottom",
                fontsize=8, fontweight="bold",
            )

    autolabel(r1)
    autolabel(r2)
    autolabel(r3)

    plt.tight_layout()
    out_path = FIGURES_DIR / "latency_comparison.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved: {out_path.name}")


def plot_confusion_matrices(results: dict):
    """Chart 4: 2x2 Grid of Confusion Matrices for All 4 Configurations."""
    configs = list(results["configurations"].keys())
    fig, axes = plt.subplots(2, 2, figsize=(10, 8))
    axes = axes.flatten()

    for idx, cfg in enumerate(configs):
        ax = axes[idx]
        cm = np.array(results["configurations"][cfg]["classification_metrics"]["confusion_matrix"])
        title = cfg.replace("Config_", "").replace("_", " ")

        im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        ax.set_title(title, fontsize=11, fontweight="bold", pad=10)

        tick_marks = np.arange(2)
        ax.set_xticks(tick_marks)
        ax.set_xticklabels(["Benign (0)", "Threat (1)"], fontsize=9)
        ax.set_yticks(tick_marks)
        ax.set_yticklabels(["Benign (0)", "Threat (1)"], fontsize=9)

        thresh = cm.max() / 2.0
        for i in range(2):
            for j in range(2):
                val = cm[i, j]
                ax.text(
                    j, i, format(val, "d"),
                    ha="center", va="center",
                    color="white" if val > thresh else "black",
                    fontsize=12, fontweight="bold",
                )

        ax.set_ylabel("True Class", fontsize=9, fontweight="bold")
        ax.set_xlabel("Predicted Class", fontsize=9, fontweight="bold")

    plt.suptitle("PromptShield AI: Confusion Matrices by Configuration (Exp 1)", fontsize=14, fontweight="bold", y=0.98)
    plt.tight_layout()
    out_path = FIGURES_DIR / "confusion_matrices.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved: {out_path.name}")


def plot_per_category_performance(results: dict):
    """Chart 5: Per-Category Detection Performance for Config C and Config D."""
    cfg_c_cats = results["configurations"]["Config_C_Ensemble"]["per_category_metrics"]
    cfg_d_cats = results["configurations"]["Config_D_Gateway"]["per_category_metrics"]

    categories = sorted(cfg_c_cats.keys())
    display_cats = [c.replace("_", " ").title() for c in categories]

    c_recalls = [cfg_c_cats[c]["recall"] for c in categories]
    d_recalls = [cfg_d_cats[c]["recall"] for c in categories]

    y = np.arange(len(categories))
    height = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    r1 = ax.barh(y - height / 2, c_recalls, height, label="Config C (Ensemble Recall)", color="#4e79a7")
    r2 = ax.barh(y + height / 2, d_recalls, height, label="Config D (Gateway Recall)", color="#59a14f")

    ax.set_xlabel("Detection Recall (0.0 - 1.0)", fontsize=11, fontweight="bold")
    ax.set_title("PromptShield AI: Per-Category Threat Recall (Exp 1)", fontsize=13, fontweight="bold", pad=15)
    ax.set_yticks(y)
    ax.set_yticklabels(display_cats, fontsize=10)
    ax.set_xlim(0, 1.15)
    ax.legend(loc="lower right", frameon=True)
    ax.grid(axis="x", linestyle="--", alpha=0.5)

    def autolabel_h(rects):
        for rect in rects:
            w = rect.get_width()
            ax.annotate(
                f"{w:.2f}",
                xy=(w, rect.get_y() + rect.get_height() / 2),
                xytext=(3, 0),
                textcoords="offset points",
                ha="left", va="center",
                fontsize=8, fontweight="bold",
            )

    autolabel_h(r1)
    autolabel_h(r2)

    plt.tight_layout()
    out_path = FIGURES_DIR / "per_category_performance.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved: {out_path.name}")


def plot_in_vs_out_distribution(results: dict):
    """Chart 6: In-Distribution (Exp 1) vs Out-of-Distribution Grouped (Exp 2) Comparison."""
    if "experiment_1_stratified" not in results or "experiment_2_grouped_ood" not in results:
        return

    exp1_cfgs = results["experiment_1_stratified"]["configurations"]
    exp2_cfgs = results["experiment_2_grouped_ood"]["configurations"]
    configs = list(exp1_cfgs.keys())
    display_names = [c.replace("Config_", "").replace("_", " ") for c in configs]

    f1_exp1 = [exp1_cfgs[c]["classification_metrics"]["f1"] for c in configs]
    f1_exp2 = [exp2_cfgs[c]["classification_metrics"]["f1"] for c in configs]
    fpr_exp1 = [exp1_cfgs[c]["classification_metrics"]["false_positive_rate"] * 100 for c in configs]
    fpr_exp2 = [exp2_cfgs[c]["classification_metrics"]["false_positive_rate"] * 100 for c in configs]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    x = np.arange(len(configs))
    width = 0.35

    # F1 comparison
    ax1.bar(x - width / 2, f1_exp1, width, label="Exp 1: In-Distribution (F1)", color="#4e79a7")
    ax1.bar(x + width / 2, f1_exp2, width, label="Exp 2: Out-of-Distribution (F1)", color="#e15759")
    ax1.set_ylabel("F1 Score", fontsize=10, fontweight="bold")
    ax1.set_title("F1 Score Robustness (In-Dist vs OOD)", fontsize=11, fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(display_names, fontsize=9)
    ax1.set_ylim(0, 1.15)
    ax1.legend(loc="lower left")
    ax1.grid(axis="y", linestyle="--", alpha=0.5)

    # FPR comparison
    ax2.bar(x - width / 2, fpr_exp1, width, label="Exp 1: In-Distribution (FPR %)", color="#59a14f")
    ax2.bar(x + width / 2, fpr_exp2, width, label="Exp 2: Out-of-Distribution (FPR %)", color="#f28e2b")
    ax2.set_ylabel("False Positive Rate (%)", fontsize=10, fontweight="bold")
    ax2.set_title("False Positive Rate Comparison (In-Dist vs OOD)", fontsize=11, fontweight="bold")
    ax2.set_xticks(x)
    ax2.set_xticklabels(display_names, fontsize=9)
    ax2.set_ylim(0, max(max(fpr_exp2) * 1.35, 10.0))
    ax2.legend(loc="upper left")
    ax2.grid(axis="y", linestyle="--", alpha=0.5)

    plt.suptitle("PromptShield AI: Generalization & False-Alarm Analysis (Exp 1 vs Exp 2)", fontsize=13, fontweight="bold", y=0.98)
    plt.tight_layout()
    out_path = FIGURES_DIR / "experiment_comparison.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved: {out_path.name}")


def main():
    print("=" * 60)
    print("PROMPTSHIELD AI — GENERATING BENCHMARK VISUALIZATIONS")
    print("=" * 60)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    results = load_results()

    plot_metrics_comparison(results)
    plot_fpr_comparison(results)
    plot_latency_comparison(results)
    plot_confusion_matrices(results)
    plot_per_category_performance(results)
    plot_in_vs_out_distribution(results)

    print(f"\nAll visualization figures successfully generated in: {FIGURES_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    main()
