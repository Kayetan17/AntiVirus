import yara
from engine.scanner import scan_directory, scan_files_yara
from engine.rule_manager import load_ruleset

def main():
    # ✅ 1. Load your compiled YARA rules using your existing load_ruleset
    rules_directory = "/Users/kayetanprotas/Desktop/Anti-Virus/data/test2"  
    # adjust this to your actual yara rules location
    compiled_rules = load_ruleset(rules_directory)
    if compiled_rules is None:
        print("[✖] Failed to load YARA rules, exiting.")
        return
    print("[✓] YARA rules loaded successfully.")

    # ✅ 2. Select your clean test directory
    directory_to_scan = "/Users/kayetanprotas/Documents/GR 12 Computer science"  # replace as needed
    files_to_scan = scan_directory(directory_to_scan)
    print(f"[✓] Found {len(files_to_scan)} files to scan in '{directory_to_scan}'.")

    # ✅ 3. Scan files with your compiled YARA rules
    suspicious_files = scan_files_yara(compiled_rules, files_to_scan)

    # ✅ 4. Display results clearly
    if suspicious_files:
        print(f"\n[!] Suspicious files detected ({len(suspicious_files)}):")
        for file in suspicious_files:
            print(f"  - {file}")
    else:
        print("\n[✓] No suspicious files detected. All clear.")

if __name__ == "__main__":
    main()
