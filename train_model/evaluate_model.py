import pandas as pd
import joblib

# Define the path to your test dataset and model
csv_path = "data/malware-data/dataset_test.csv"
model_path = "static_model.joblib"

# 18 static features your model was trained on
selected_features = [
    "MinorOperatingSystemVersion",
    "MajorLinkerVersion",
    "SizeOfStackReserve",
    "MajorSubsystemVersion",
    "TimeDateStamp",
    "ImageBase",
    "Characteristics",
    "MajorOperatingSystemVersion",
    "Subsystem",
    "MinorImageVersion",
    "MinorSubsystemVersion",
    "DllCharacteristics",
    "SizeOfInitializedData",
    "MajorImageVersion",
    "DirectoryEntryImportSize",
    "DirectoryEntryExport",
    "AddressOfEntryPoint",
    "CheckSum",
]

# Load test data
df = pd.read_csv(csv_path)

# Drop rows with missing values in any of the 18 features
df = df.dropna(subset=selected_features)

# Extract feature matrix
X_test = df[selected_features]

# Load trained model
model = joblib.load(model_path)

# Predict
predictions = model.predict(X_test)

# Add predictions to the dataframe
df["PredictedLabel"] = predictions  # 1 = malware, 0 = benign

# Save predictions
df.to_csv("test_predictions.csv", index=False)
print("✅ Predictions saved to 'test_predictions.csv'")
