"""
Integration tests for the Adversarial Benchmark Pipeline and Runner
"""

import json
from pathlib import Path
import pandas as pd
import pytest

from research.experiments.run_benchmark import BenchmarkPipeline

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_ROOT / "research" / "results"
SPLITS_DIR = PROJECT_ROOT / "research" / "datasets" / "benchmark" / "splits"


@pytest.fixture
def pipeline():
    return BenchmarkPipeline()


def test_pipeline_load_data(pipeline):
    train_df, val_df, test_df = pipeline.load_data()
    assert len(train_df) > 0
    assert len(val_df) > 0
    assert len(test_df) > 0
    assert len(train_df) > len(test_df)


def test_pipeline_train_classifier_only_on_train_split(pipeline):
    train_df, _, test_df = pipeline.load_data()
    model = pipeline.train_classifier(train_df)
    assert model.is_trained is True

    # Confirm classifier can predict on a sample
    pred = model.predict("Explain how Python works")
    assert "prediction" in pred
    assert "confidence" in pred
    assert pred["class_id"] in (0, 1)


def test_pipeline_run_benchmark_outputs_exist():
    # Verify generated result files
    results_json = RESULTS_DIR / "benchmark_results.json"
    summary_csv = RESULTS_DIR / "metrics_summary.csv"
    cm_json = RESULTS_DIR / "confusion_matrices.json"
    meta_json = RESULTS_DIR / "benchmark_metadata.json"

    assert results_json.exists(), "benchmark_results.json missing"
    assert summary_csv.exists(), "metrics_summary.csv missing"
    assert cm_json.exists(), "confusion_matrices.json missing"
    assert meta_json.exists(), "benchmark_metadata.json missing"

    with open(results_json, "r", encoding="utf-8") as f:
        res = json.load(f)

    assert "configurations" in res
    assert "Config_A_Rules" in res["configurations"]
    assert "Config_B_ML" in res["configurations"]
    assert "Config_C_Ensemble" in res["configurations"]
    assert "Config_D_Gateway" in res["configurations"]

    assert "pii_secret_evaluation" in res
    assert "tool_policy_evaluation" in res
    assert "adversarial_scenarios_evaluation" in res

    df_summary = pd.read_csv(summary_csv)
    assert len(df_summary) == 4
    assert set(df_summary["Configuration"]) == {
        "Config_A_Rules", "Config_B_ML", "Config_C_Ensemble", "Config_D_Gateway"
    }


def test_no_test_data_used_in_training(pipeline):
    train_df, _, test_df = pipeline.load_data()
    train_texts = set(train_df["text"].str.strip().str.lower())
    test_texts = set(test_df["text"].str.strip().str.lower())

    assert len(train_texts & test_texts) == 0


def test_adversarial_scenarios_structure(pipeline):
    train_df, _, _ = pipeline.load_data()
    pipeline.train_classifier(train_df)
    scenarios = pipeline._evaluate_adversarial_scenarios()

    assert len(scenarios) == 10
    assert "1. Benign Security Education" in scenarios
    assert "7. Malicious Tool Request from Untrusted Context" in scenarios
    assert "10. Attempted Human Approval Bypass" in scenarios

    for sc_name, sc_data in scenarios.items():
        assert "expected" in sc_data
        assert "gateway_threat_flag" in sc_data
