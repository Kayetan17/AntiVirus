import yara 
import os 

def load_ruleset(ruleset_path):
    rules = {}
    for file in os.listdir(ruleset_path):
        if (file.endswith(".yar") or file.endswith(".yara")):
            rule_name = os.path.splitext(file)[0]
            full_path = os.path.join(ruleset_path, file)
            rules[rule_name] = full_path
            
    compiled_rules = yara.compile(filepaths = rules)
    return compiled_rules


# Only works if all rules compile
# TODO change this so that not all rules need to compile sucsefully in order to run

# Fix the current yara rule paths and then get it github ready so we can test on a vm