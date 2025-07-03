from engine.rule_manager import load_ruleset

if __name__ == "__main__":
    rules_folder = "/Users/kayetanprotas/Desktop/Anti-Virus/data/test2" 
    # adjust if your path is different
    
    # Its def a issue with the yara rules them selves 

    try:
        rules = load_ruleset(rules_folder)
        print("[✔] YARA rules loaded successfully.")
    except Exception as e:
        print("[✖] Failed to load YARA rules.")
        print(e)

# He uses a api u dont, thats prob why try and download a different rule set