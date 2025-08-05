# Jackal Antivirus
* Machine-learning & signature-based static malware scanner
<img width="940" height="623" alt="Screenshot 2025-08-04 at 6 51 32 PM" src="https://github.com/user-attachments/assets/c3149ce9-fe95-4a42-880e-7f6ce3955293" />

## About the project

Jackal is a light weight anti-virus engine that uses machine-learning classifier trained on PE-header features and YARA signature rules. The scanner is satic, meaning that it never opens or executes the files it analyzes. Instead it inspects static features like metadata and byte patterns which allows it to quickly and safely scan files for threats without risking running a dangerous file or requiring a sandboxed environment.


### Machine Learning Model

Jackal utilizes a machine learning model that was trained off of a [malware dataset](https://www.kaggle.com/datasets/amauricio/pe-files-malwares/data) containing features extracted from PE (Portable Executable) files. To improve accuarcy and to disregard non static features the top 20 most important features were identified using feature importance analysis performed with a Random Forest classifier.

<img width="1008" height="625" alt="top20" src="https://github.com/user-attachments/assets/a58c325e-11a0-4151-844b-a3d4073748eb" />

From there 18 of the most import features where selected, 


