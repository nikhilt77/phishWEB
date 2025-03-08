import os
import shutil
import kagglehub
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import classification_report, confusion_matrix
import joblib

import matplotlib.pyplot as plt
import seaborn as sns

# --- Step 0: Clear the entire Kagglehub cache ---
kagglehub_cache = os.path.expanduser("~/.cache/kagglehub")
if os.path.exists(kagglehub_cache):
    print("Deleting entire Kagglehub cache directory:", kagglehub_cache)
    shutil.rmtree(kagglehub_cache)

# --- Step 1: Download the dataset (force a fresh download) ---
path = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls", force_download=True)
print("Path to dataset files:", path)
files = os.listdir(path)
print("Files in the dataset directory:", files)

# --- Step 2: Set the file name ---
file_name = "phishing_site_urls.csv"
print("Using file:", file_name)

# --- Step 3: Load the dataset using pandas ---
csv_file = os.path.join(path, file_name)
df = pd.read_csv(csv_file)
print("Dataset loaded. First 5 rows:")
print(df.head())

# --- Step 4: Standardize column names (convert to lowercase) ---
df.columns = [col.lower() for col in df.columns]
print("Columns after lowercasing:", df.columns)

# --- Step 5: Map labels (e.g., 'bad' -> 1, 'good' -> 0) ---
label_map = {
    "bad": 1,
    "good": 0
}
df['label'] = df['label'].map(label_map)

# --- Step 6: Extract features using CountVectorizer ---
vectorizer = CountVectorizer(analyzer='char', ngram_range=(2, 3))
X = vectorizer.fit_transform(df['url'])
y = df['label']

# --- Step 7: Split the data into training and testing sets ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# --- Step 8: Train the Random Forest classifier ---
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# --- Step 9: Evaluate the model ---
y_pred = rf_model.predict(X_test)
print("Classification Report:")
print(classification_report(y_test, y_pred))

# --- (Optional) Step 9.1: Plot Confusion Matrix Heatmap ---
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(5, 4))
sns.heatmap(
    cm,
    annot=True,
    fmt='d',
    cmap='Blues',
    xticklabels=['Good (0)', 'Bad (1)'],
    yticklabels=['Good (0)', 'Bad (1)']
)
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("True")
plt.tight_layout()
plt.show()

# --- Step 10: Save the model and vectorizer ---
joblib.dump(rf_model, 'phishing_rf_model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
print("Model and vectorizer saved to disk.")
