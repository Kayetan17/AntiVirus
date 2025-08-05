# Jackal Antivirus
* Machine-learning & signature-based static malware scanner
<img width="940" height="623" alt="Screenshot 2025-08-04 at 6 51 32 PM" src="https://github.com/user-attachments/assets/c3149ce9-fe95-4a42-880e-7f6ce3955293" />

## About the project

Jackal is a light weight anti-virus engine that uses machine-learning classifier trained on PE-header features and YARA signature rules. The scanner is satic, meaning that it never opens or executes the files it analyzes. Instead it inspects static features like metadata and byte patterns which allows it to quickly and safely scan files for threats without risking running a dangerous file or requiring a sandboxed environment.


### Machine Learning Model

Jackal utilizes a machine learning model that was trained off of a [malware dataset](https://www.kaggle.com/datasets/amauricio/pe-files-malwares/data) containing features extracted from PE (Portable Executable) files. 




