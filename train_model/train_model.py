import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Train the model using the features included in the feature extractor

csv_path = "data/malware-data/dataset_malwares.csv"
df = pd.read_csv(csv_path)

features = [
    "MinorOperatingSystemVersion", "MajorLinkerVersion", "SizeOfStackReserve",
    "MajorSubsystemVersion", "TimeDateStamp", "ImageBase", "Characteristics",
    "MajorOperatingSystemVersion", "Subsystem", "MinorImageVersion",
    "MinorSubsystemVersion", "DllCharacteristics", "SizeOfInitializedData",
    "MajorImageVersion", "DirectoryEntryImportSize", "DirectoryEntryExport",
    "AddressOfEntryPoint", "CheckSum",
]

df = df.dropna(subset=features + ["Malware"])
X = df[features].astype(int)          
y = df["Malware"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred), "\n")
print(classification_report(y_test, y_pred))
print(f"Accuracy: {model.score(X_test, y_test):.4f}")


joblib.dump(model, "static_model.joblib")


