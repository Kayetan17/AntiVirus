# Jackal Antivirus

*Machine-learning & signature-based static malware scanner*

<img width="940" height="623" alt="Screenshot 2025-08-04 at 6 51 32 PM" src="https://github.com/user-attachments/assets/c3149ce9-fe95-4a42-880e-7f6ce3955293" />



## About the project

Jackal is a light weight static malware scanner that offers dual layer threat detection, it offers:

* **File and Folder Scanning:** Users can scan a single file or recursively scan a directory and all of its subfolders.
  
* **Static Analysis:** Jackal never executes files it analyzes. Instead it inspects static features like metadata and byte patterns which allows it to quickly and safely scan files for threats without risking running a dangerous file or requiring a sandboxed environment
  
* **Machine Learning Detection:** For Windows PE files, Jackal uses a trained machine learning model to identify malicious files.
  
* **Signature-Based Detection:** Using YARA rules, Jackal can scan a wide variety of file types—including executables, documents, and scripts—for known malware signatures.
  
* **Threat Summary:** After scanning Jackal provides a summary showing how many files were scanned, how many threats were detected by each engine, and the corresponding file paths
  
* **Modern GUI:** GUI built in CustomTkinter that simplifies malware scanning by letting users select files or folders, choose between detection modes and view scan summaries in real-time.


### Machine Learning Model

Jackal utilizes a machine learning model that was trained off of a [malware dataset](https://www.kaggle.com/datasets/amauricio/pe-files-malwares/data) containing features extracted from PE (Portable Executable) files. To improve accuarcy and to disregard dynamic features the top 20 most important static features were identified using feature importance analysis performed with a Random Forest classifier implemented with Scikit-learn.


<img width="1000" height="600" alt="featureImportance" src="https://github.com/user-attachments/assets/2714da75-e1e0-4db6-b729-09431f86bbf1" />


From there 18 of the most important and staticly extractable features where selected. The model was retrained with only these features using Scikit-learn, then a feature extractor was developed to extract these features from unknown PE files, allowing the model to make predictions on new input at runtime. Since the model relies on static PE features, the ML scanner only supports Windows executable formats such as .exe, .dll, .sys, and .scr.


### Signature Detection

Jackal uses YARA rules for signature-based detection, the engine scans files against a set of anti-malware YARA rules from the [YARA Forge repository](https://github.com/YARAHQ/yara-forge).
The rule set is designed to provide protection and flag many malware families such as:

* Remote Access Trojans (RATS)
* Backdoors
* Wipers
* Downloaders
* Trojans
* Information Stealers
* Credential Harvesters
* APT Toolkits
* Ransomware
* Miscellaneous Threats

Unlike the Machine learning model the YARA scanner can analyze a larger range of file types like documents, scripts, and executables.



## Installation

### Prerequisites 

**Python 3.9 or newer**

**YARA binary**

* Windows: https://github.com/VirusTotal/yara/releases or ```choco install yara```
* Mac: ```brew install yara``` (need homebrew)
* Linux Ubuntu: ```sudo apt install yara```

**Step by step**

1. ```git clone https://github.com/Kayetan17/static-malware-detector.git```
2. ```cd static-malware-detector```
3. ```pip install -r requirements.txt```
4. ```python main.py``` (run the gui)



## License

This project is licensed under the **GPLv3 License**.

YARA rules used by this project were sourced from the [YARA Forge project](https://github.com/YARAHQ/yara-forge) and fall under the GPLv3 license. As such, this project as a whole is also distributed under GPLv3.

See [LICENSE](./LICENSE) for full terms.



## Built With & Citations

- **PE Malware Dataset:** <br>
  Malware Dataset https://www.kaggle.com/datasets/amauricio/pe-files-malwares/data

- **Signature Scanning** <br>
  YARA https://virustotal.github.io/yara/

- **YARA Rules:** <br>
  YARA Forge repository https://github.com/YARAHQ/yara-forge

- **ML Tools:** <br>
  Scikit-learn https://scikit-learn.org/ <br>
  Pandas https://pandas.pydata.org/

- **GUI:** <br>
  GUI FrameWork CustomTkinter https://github.com/TomSchimansky/CustomTkinter <br>
  GUI Font Lemon Milk https://www.dafont.com/lemon-milk.font

- **Static Feature Extraction** <br>
  PEfile https://github.com/erocarrera/pefile



## Contact

Kayetan Protas - kayetanp@gmail.com <br>
Project Link: - https://github.com/Kayetan17/static-malware-detector.git
