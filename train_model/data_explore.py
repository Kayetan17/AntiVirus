import pandas as pd

df = pd.read_csv("data/malware-data/dataset_malwares.csv")
print("Shape:", df.shape)
print("\nFirst 5 rows:")
print(df.head())

# Column names
print("\nColumns:")
print(df.columns)

# Check for missing values
print("\nMissing values:")
print(df.isnull().sum())