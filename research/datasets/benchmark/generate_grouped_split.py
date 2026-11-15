"""
PromptShield AI — Grouped Template Dataset Splitter (Experiment 2: Out-of-Distribution Adversarial Evaluation)
Partitions benchmark samples by semantic template families and structural groups.
Guarantees that entire template clusters (e.g. novel instruction overrides, paraphrased extractions,
challenging security-education benign probes) appear EXCLUSIVELY in either Train or Test.
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = PROJECT_ROOT / "research" / "datasets" / "benchmark"
SPLITS_GROUPED_DIR = BENCHMARK_DIR / "splits_grouped"


def assign_template_group(row: pd.Series) -> str:
    """
    Assign a structural template group identifier to each record.
    Used for Group-based splitting so that related prompt templates remain together.
    """
    sid = str(row["sample_id"])
    cat = str(row["category"])
    txt = str(row["text"]).lower()

    if cat == "benign":
        if "BEN-SEC" in sid:
            # High-difficulty cybersecurity education & prompt injection discussions
            # Assigned to Test to rigorously evaluate Out-of-Distribution False Positive Rate
            return "benign_security_probes"
        elif any(k in txt for k in ["python", "function", "sql", "docker", "git", "api", "compiler", "code"]):
            return "benign_technical_software"
        elif any(k in txt for k in ["relativity", "photosynthesis", "battery", "mitochondria", "dna", "quantum"]):
            return "benign_science_physics"
        else:
            return "benign_general_knowledge"

    elif cat == "direct_injection":
        if "DIR-INJ" in sid:
            num = int(sid.split("-")[-1])
            # Common patterns (PI001-PI007 exact matches) vs Paraphrased / Stealth attacks
            if num <= 10:
                return "direct_standard_override"
            elif num <= 20:
                return "direct_novel_override"
            elif num <= 30:
                return "direct_standard_extraction"
            elif num <= 40:
                return "direct_novel_extraction"
            elif num <= 50:
                return "direct_standard_bypass"
            elif num <= 60:
                return "direct_novel_bypass"
            elif num <= 70:
                return "direct_standard_roleplay"
            else:
                return "direct_novel_roleplay"

    elif cat == "indirect_injection":
        if "IND-INJ" in sid:
            num = int(sid.split("-")[-1])
            if num <= 10 or (40 < num <= 50):
                return "indirect_standard_system_tags"
            elif num <= 20 or (50 < num <= 60):
                return "indirect_standard_ai_directives"
            elif num <= 30 or (60 < num <= 70):
                return "indirect_novel_conditional_overrides"
            else:
                return "indirect_novel_delimiters"

    elif cat == "pii_leakage":
        if "PII-EXP" in sid:
            num = int(sid.split("-")[-1])
            if num <= 20:
                return "pii_standard_emails_phones"
            elif num <= 45:
                return "pii_contextual_employee_profiles"
            else:
                return "pii_mixed_corporate_addresses"

    elif cat == "secret_leakage":
        if "SEC-EXP" in sid:
            num = int(sid.split("-")[-1])
            if num <= 20:
                return "secret_standard_apikeys_aws"
            elif num <= 40:
                return "secret_standard_database_passwords"
            else:
                return "secret_atypical_keylengths_vault"

    elif cat == "tool_abuse":
        if "TOOL-ABU" in sid:
            num = int(sid.split("-")[-1])
            if num <= 15:
                return "tool_standard_role_violations"
            elif num <= 30:
                return "tool_untrusted_context_violations"
            elif num <= 45:
                return "tool_approval_bypass_attempts"
            else:
                return "tool_path_traversal_and_malformed"

    elif cat == "mixed_adversarial":
        if "MIX-ADV" in sid:
            num = int(sid.split("-")[-1])
            if num <= 20:
                return "mixed_standard_injection_pii"
            elif num <= 40:
                return "mixed_standard_injection_secrets"
            else:
                return "mixed_complex_multivector_stealth"

    return f"{cat}_misc"


def generate_grouped_splits():
    print("=" * 70)
    print("PROMPTSHIELD AI — GENERATING GROUPED TEMPLATE SPLIT (EXPERIMENT 2)")
    print("=" * 70)

    SPLITS_GROUPED_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load all category CSVs
    cat_files = [
        "benign_prompts.csv",
        "direct_injection.csv",
        "indirect_injection.csv",
        "pii_leakage.csv",
        "secret_leakage.csv",
        "tool_abuse.csv",
        "mixed_adversarial.csv",
    ]

    all_dfs = []
    for fname in cat_files:
        p = BENCHMARK_DIR / fname
        if not p.exists():
            raise FileNotFoundError(f"Missing {p}. Please generate base datasets first.")
        df_cat = pd.read_csv(p)
        all_dfs.append(df_cat)

    full_df = pd.concat(all_dfs, ignore_index=True)
    full_df["template_group"] = full_df.apply(assign_template_group, axis=1)

    print(f"Total Loaded Records: {len(full_df)}")
    print(f"Total Unique Template Groups: {full_df['template_group'].nunique()}")

    # 2. Assign Groups to Train, Val, and Test
    # Test receives the novel/challenging groups so the model is evaluated Out-of-Distribution!
    test_groups = {
        "benign_security_probes",                # 50 samples: Challenging security false-positive tests
        "direct_novel_override",                 # 10 samples
        "direct_novel_extraction",               # 10 samples
        "direct_novel_bypass",                   # 10 samples
        "direct_novel_roleplay",                 # 10 samples
        "indirect_novel_conditional_overrides",  # 15 samples
        "indirect_novel_delimiters",             # 15 samples
        "pii_mixed_corporate_addresses",         # 20 samples
        "secret_atypical_keylengths_vault",      # 25 samples
        "tool_path_traversal_and_malformed",     # 20 samples
        "mixed_complex_multivector_stealth",     # 25 samples
    }

    val_groups = {
        "benign_science_physics",
        "direct_standard_roleplay",
        "indirect_standard_system_tags",
        "pii_contextual_employee_profiles",
        "secret_standard_database_passwords",
        "tool_untrusted_context_violations",
        "mixed_standard_injection_secrets",
    }

    # All remaining groups go to Train
    train_groups = set(full_df["template_group"].unique()) - test_groups - val_groups

    # Filter dataframes
    test_df = full_df[full_df["template_group"].isin(test_groups)].copy()
    val_df = full_df[full_df["template_group"].isin(val_groups)].copy()
    train_df = full_df[full_df["template_group"].isin(train_groups)].copy()

    # 3. Verify Zero Group Leakage
    train_g = set(train_df["template_group"])
    test_g = set(test_df["template_group"])
    val_g = set(val_df["template_group"])

    leak_tt = train_g & test_g
    leak_tv = train_g & val_g
    leak_vt = val_g & test_g

    if leak_tt or leak_tv or leak_vt:
        raise AssertionError("CRITICAL GROUP LEAKAGE DETECTED!")

    # Verify ID and Text zero-leakage
    id_overlap = set(train_df["sample_id"]) & set(test_df["sample_id"])
    text_overlap = set(train_df["text"].str.strip().str.lower()) & set(test_df["text"].str.strip().str.lower())

    if id_overlap or text_overlap:
        raise AssertionError("ID or Text leakage detected across grouped splits!")

    # 4. Save splits
    train_path = SPLITS_GROUPED_DIR / "train_grouped.csv"
    val_path = SPLITS_GROUPED_DIR / "val_grouped.csv"
    test_path = SPLITS_GROUPED_DIR / "test_grouped.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    print("\nGrouped Split Counts:")
    print("-" * 50)
    print(f"  * Train Grouped:      {len(train_df):>4} records ({len(train_df)/len(full_df)*100:.1f}%) | Groups: {len(train_g)}")
    print(f"  * Val Grouped:        {len(val_df):>4} records ({len(val_df)/len(full_df)*100:.1f}%) | Groups: {len(val_g)}")
    print(f"  * Test Grouped (OOD): {len(test_df):>4} records ({len(test_df)/len(full_df)*100:.1f}%) | Groups: {len(test_g)}")

    print("\nLeakage Verification:")
    print("-" * 50)
    print("  [PASSED] Group overlap between Train and Test: 0")
    print("  [PASSED] Sample ID overlap:                   0")
    print("  [PASSED] Text exact overlap:                  0")

    def sha256_file(filepath: Path) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    metadata = {
        "experiment_name": "Experiment_2_Grouped_Template_Split",
        "description": "Out-of-Distribution Adversarial Evaluation with clustered template groups",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(full_df),
        "split_counts": {
            "train": len(train_df),
            "val": len(val_df),
            "test": len(test_df),
        },
        "group_distribution": {
            "train_groups": sorted(list(train_g)),
            "val_groups": sorted(list(val_g)),
            "test_groups": sorted(list(test_g)),
        },
        "checksums": {
            "train_sha256": sha256_file(train_path),
            "val_sha256": sha256_file(val_path),
            "test_sha256": sha256_file(test_path),
        },
        "leakage_verification": "VERIFIED_ZERO_GROUP_LEAKAGE",
    }

    meta_path = SPLITS_GROUPED_DIR / "grouped_metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nSaved Grouped Metadata: {meta_path}")
    print("=" * 70)


if __name__ == "__main__":
    generate_grouped_splits()
