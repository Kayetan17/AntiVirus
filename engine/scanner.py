import os
import yara

# change name to smth else, maybe retrive directory or smth
def scan_directory(dir_path):
    
    files_for_scan = []
    
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            full_path = os.path.join(root, file)
            files_for_scan.append(full_path)
    
    return files_for_scan

# we basicaly j loop through every file and return a huge list of every path from a certain starting root

def scan_files_yara(compiled_rules, files_for_scan):
    
    results = []
    total_matches = 0
    
    for file in files_for_scan:
        try: #use try block cuz maybe we will run into corrupted / system files which cause error
            sussy_baka_files = compiled_rules.match(file)
            
            if sussy_baka_files:
                for match in sussy_baka_files:
                    print(f"Match found {match.rule} matched in {file}")
                
                    results.append(file)
                    total_matches +=1
                
        except Exception as e:
            print(f"[!] Could not scan '{file}': {e}")
            
            
    print(f"[✓] Scan complete. Total matches found: {total_matches}")
    
    
    return results