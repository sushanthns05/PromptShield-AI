"""
Tests for PromptShield AI Benchmark Dataset Schema and Leakage Prevention
"""

import json
from pathlib import Path
import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_DIR = PROJECT_ROOT / "research" / "datasets" / "benchmark"
SPLITS_DIR = BENCHMARK_DIR / "splits"


def test_benchmark_files_exist():
    expected_files = [
        "benign_prompts.csv",
        "direct_injection.csv",
        "indirect_injection.csv",
        "pii_leakage.csv",
        "secret_leakage.csv",
        "tool_abuse.csv",
        "mixed_adversarial.csv",
        "dataset_metadata.json",
    ]
    for fname in expected_files:
        p = BENCHMARK_DIR / fname
        assert p.exists(), f"Expected benchmark file missing: {fname}"


def test_split_files_exist():
    assert (SPLITS_DIR / "train.csv").exists()
    assert (SPLITS_DIR / "val.csv").exists()
    assert (SPLITS_DIR / "test.csv").exists()


def test_benchmark_dataset_schema():
    expected_columns = {
        "sample_id",
        "text",
        "category",
        "label",
        "attack_type",
        "expected_security_action",
        "source_type",
        "difficulty",
    }
    train_df = pd.read_csv(SPLITS_DIR / "train.csv")
    test_df = pd.read_csv(SPLITS_DIR / "test.csv")
    val_df = pd.read_csv(SPLITS_DIR / "val.csv")

    for name, df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        assert expected_columns.issubset(df.columns), f"Missing required columns in {name}"
        assert len(df) > 0, f"Split {name} is empty"


def test_no_missing_or_null_values():
    for split in ["train.csv", "val.csv", "test.csv"]:
        df = pd.read_csv(SPLITS_DIR / split)
        assert df["sample_id"].isnull().sum() == 0
        assert df["text"].isnull().sum() == 0
        assert df["label"].isnull().sum() == 0
        assert (df["text"].astype(str).str.strip() == "").sum() == 0


def test_unique_sample_ids():
    train_df = pd.read_csv(SPLITS_DIR / "train.csv")
    val_df = pd.read_csv(SPLITS_DIR / "val.csv")
    test_df = pd.read_csv(SPLITS_DIR / "test.csv")

    all_ids = list(train_df["sample_id"]) + list(val_df["sample_id"]) + list(test_df["sample_id"])
    assert len(all_ids) == len(set(all_ids)), "Duplicate sample_ids detected across splits"


def test_zero_leakage_between_train_and_test():
    train_df = pd.read_csv(SPLITS_DIR / "train.csv")
    test_df = pd.read_csv(SPLITS_DIR / "test.csv")

    train_ids = set(train_df["sample_id"])
    test_ids = set(test_df["sample_id"])
    assert len(train_ids & test_ids) == 0, "ID leakage detected between train and test splits!"

    train_texts = set(train_df["text"].str.strip().str.lower())
    test_texts = set(test_df["text"].str.strip().str.lower())
    overlap = train_texts & test_texts
    assert len(overlap) == 0, f"Text leakage detected: {len(overlap)} prompts in both train and test!"


def test_metadata_consistency():
    meta_path = BENCHMARK_DIR / "dataset_metadata.json"
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["dataset_name"] == "PromptShield-AI-Benchmark"
    assert meta["total_samples"] >= 500
    assert meta["leakage_verification"]["status"] == "VERIFIED_ZERO_LEAKAGE"
    assert meta["splits"]["train"]["count"] > meta["splits"]["test"]["count"]
