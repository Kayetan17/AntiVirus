import os

def scan_directory(dir_path):
    
    files_for_scan = []
    
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            full_path = os.path.join(root, file)
            files_for_scan.append(full_path)
    
    return files_for_scan

# we basicaly j loop through every file and return a huge list of every path from a certain starting root