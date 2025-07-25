import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Load the dataset
df = pd.read_csv("data/malware-data/dataset_malwares.csv")

# Drop non-useful columns
df = df.drop(columns=["Name"])

# Separate features and labels
X = df.drop(columns=["Malware"])
y = df["Malware"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Print evaluation results
y_pred = model.predict(X_test)
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

importances = pd.Series(model.feature_importances_, index=X.columns)
top_features = importances.sort_values(ascending=False).head(20)
print("\nTop 20 Features:")
print(top_features)

plt.figure(figsize=(10, 10))
sns.barplot(x=top_features.values, y=top_features.index)
plt.title("Most usefull features in dataset")
plt.xlabel("Importance")
plt.tight_layout()
plt.show()
