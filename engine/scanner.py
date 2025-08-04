import os
import joblib
import pandas as pd

from .feature_extract import extract_static_features
from .rule_manager import load_ruleset


def is_pe(filepath):
    PE_file_endings = (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr")
    return filepath.lower().endswith(PE_file_endings)


def scan_file(filepath, use_ml, use_yara, model=None, yara_rules=None):
    result = {
        "file_path": filepath,
        "ml_result": "Not scanned",
        "yara_result": "Not scanned",
        "error": None
    }

    if use_ml and model and is_pe(filepath):
        features = extract_static_features(filepath)
        if features:
            try:
                X = pd.DataFrame([features])
                pred = model.predict(X)[0]
                if pred == 1:
                    result["ml_result"] = "malware"
                else:
                    result["ml_result"] = "benign"
            except Exception as e:
                result["error"] = f"ML fail: {e}"
        else:
            result["error"] = "feature extraction failed"

    if use_yara and yara_rules:
        try:
            matches = yara_rules.match(filepath)
            if matches:
                result["yara_result"] = "malware (matched rule)"
            else:
                result["yara_result"] = "clean"
        except Exception as e:
            result["error"] = f"YARA fail: {e}"

    return result


def scan_path(path, use_ml, use_yara, model=None, yara_rules=None):
    results = []

    if os.path.isfile(path):
        results.append(scan_file(path, use_ml, use_yara, model, yara_rules))
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for filename in files:
                full_path = os.path.join(root, filename)
                if use_ml and not use_yara:
                    if not is_pe(full_path):
                        continue
                results.append(
                    scan_file(full_path, use_ml, use_yara, model, yara_rules)
                )
    else:
        print(f"Invalid path: {path}")

    return results


def summarize(results):
    total = len(results)
    ml_mal = 0
    yara_mal = 0
    both = 0
    errs = 0

    for r in results:
        if r["ml_result"] == "malware":
            ml_mal += 1
        if r["yara_result"] == "malware (matched rule)":
            yara_mal += 1
        if r["ml_result"] == "malware" and r["yara_result"] == "malware (matched rule)":
            both += 1
        if r["error"] is not None:
            errs += 1

    return {
        "total": total,
        "ml_malware": ml_mal,
        "yara_malware": yara_mal,
        "both_malware": both,
        "errors": errs,
    }

