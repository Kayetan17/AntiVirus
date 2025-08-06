# Jackal Antivirus
*Machine-learning & signature-based static malware scanner*
<img width="940" height="623" alt="Screenshot 2025-08-04 at 6 51 32 PM" src="https://github.com/user-attachments/assets/c3149ce9-fe95-4a42-880e-7f6ce3955293" />

## About the project

Jackal is a light weight anti-virus engine that uses machine-learning classifier trained on PE features and YARA signature rules. The scanner is satic, meaning that it never opens or executes the files it analyzes. Instead it inspects static features like metadata and byte patterns to quickly and safely scan files for threats without risking running a dangerous file or requiring a sandboxed environment.


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


