import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

#Finding the most important static features so that i can create a feature extractor for them

df = pd.read_csv("data/malware-data/dataset_malwares.csv")
df = df.drop(columns=["Name"])

X = df.drop(columns=["Malware"])
y = df["Malware"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\nconfusion matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nclassification report:")
print(classification_report(y_test, y_pred))

importances = pd.Series(model.feature_importances_, index=X.columns)
top_features = importances.sort_values(ascending=False).head(20)

print("\nTop 20 Features:")
rank = 1
for feature_name, score in top_features.items():
    print(f"{rank:2}. {feature_name:<35}  {score:.5f}")
    rank += 1
