import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# ─── 1. Load dataset ───────────────────────────────────────────────────────────
csv_path = "data/malware-data/dataset_malwares.csv"  # adjust if needed
df = pd.read_csv(csv_path)

# ─── 2. 18 extractor-ready features ────────────────────────────────────────────
selected_features = [
    "MinorOperatingSystemVersion", "MajorLinkerVersion", "SizeOfStackReserve",
    "MajorSubsystemVersion", "TimeDateStamp", "ImageBase", "Characteristics",
    "MajorOperatingSystemVersion", "Subsystem", "MinorImageVersion",
    "MinorSubsystemVersion", "DllCharacteristics", "SizeOfInitializedData",
    "MajorImageVersion", "DirectoryEntryImportSize", "DirectoryEntryExport",
    "AddressOfEntryPoint", "CheckSum",
]

# ─── 3. Clean & split ──────────────────────────────────────────────────────────
df = df.dropna(subset=selected_features + ["Malware"])
X = df[selected_features].astype(int)          # ensure numeric dtypes
y = df["Malware"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ─── 4. Train model ────────────────────────────────────────────────────────────
model = RandomForestClassifier(
    n_estimators=100, random_state=42, n_jobs=-1
)
model.fit(X_train, y_train)

# ─── 5. Evaluate ───────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred), "\n")
print(classification_report(y_test, y_pred))
print(f"Accuracy: {model.score(X_test, y_test):.4f}")

# (Optional) quick top-feature peek
importances = pd.Series(model.feature_importances_, index=selected_features)
print("\nTop 10 features:\n", importances.sort_values(ascending=False).head(10))

# ─── 6. Save model ─────────────────────────────────────────────────────────────
joblib.dump(model, "static_model.joblib")
print("\n✅ Model saved to 'static_model.joblib'")



# Not sure if included feature that states if a file is malware or not