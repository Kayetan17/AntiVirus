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
                result["ml_result"] = "malware" if model.predict(X)[0] == 1 else "benign" #code this in ur own style
            except Exception as e:   #Change up the exception to your own code
                result["error"] = "ML fail: %s" % e
        else:
            result["error"] = "feature extraction failed"

    # ---- YARA part ----
    if use_yara and yara_rules:
        try:
            matches = yara_rules.match(filepath)
            result["yara_result"] = "malware (matched rule)" if matches else "clean"
        except Exception as e:
            result["error"] = "YARA fail: %s" % e

    return result

def scan_path(path, use_ml, use_yara, model=None, yara_rules=None):
    results = []

    if os.path.isfile(path):
        result = scan_file(path, use_ml, use_yara, model, yara_rules)
        results.append(result)

    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for filename in files:
                full_path = os.path.join(root, filename)
                if use_ml and not is_pe(full_path):
                    continue  
                result = scan_file(full_path, use_ml, use_yara, model, yara_rules)
                results.append(result)
    else:
        print(f"Invalid path: {path}")

    return results


def summarize(results):
    total = len(results)
    ml_mal = sum(r["ml_result"] == "malware" for r in results if r["ml_result"] != "Not scanned")
    yara_mal = sum(r["yara_result"] == "malware (matched rule)" for r in results if r["yara_result"] != "Not scanned")
    both = sum(
        r["ml_result"] == "malware" and r["yara_result"] == "malware (matched rule)"
        for r in results
    )
    errs = sum(r["error"] is not None for r in results)

    return {
        "total": total,
        "ml_malware": ml_mal,
        "yara_malware": yara_mal,
        "both_malware": both,
        "errors": errs,
    }
    
if __name__ == "__main__":
    import argparse
    import joblib
    from rule_manager import load_ruleset

    parser = argparse.ArgumentParser(description="Scan a file or directory for malware.")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--ml", action="store_true", help="Use machine learning model")
    parser.add_argument("--yara", action="store_true", help="Use YARA ruleset")

    args = parser.parse_args()

    model = joblib.load("ml_model/static_model.joblib") if args.ml else None
    yara_rules = load_ruleset("yara_rules/rules/") if args.yara else None

    results = scan_path(args.path, use_ml=args.ml, use_yara=args.yara, model=model, yara_rules=yara_rules)

    print("\nScan Summary:")
    for result in results:
        print(result)
