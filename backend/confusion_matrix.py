import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import csv
import random

# -----------------------------
# STEP 1: Load dataset safely
# -----------------------------
rows = []

with open("dataset.csv", encoding="utf-8") as f:
    reader = csv.reader(f)
    for r in reader:
        if len(r) >= 2 and r[0] != "url":
            rows.append([r[0], r[-1].strip()])  # URL, attack_type

df = pd.DataFrame(rows, columns=["url", "attack_type"])

# -----------------------------
# STEP 2: Convert labels
# safe = 0, malicious = 1
# -----------------------------
df['label'] = df['attack_type'].apply(lambda x: 0 if x == 'safe' else 1)

# -----------------------------
# STEP 3: Simulated predictions
# (Replace with your ML model later)
# -----------------------------
df['pred'] = df['label'].apply(lambda x: x if random.random() < 0.9 else 1 - x)

# -----------------------------
# STEP 4: Generate Confusion Matrix
# -----------------------------
cm = confusion_matrix(df['label'], df['pred'])

# -----------------------------
# STEP 5: Plot & Save
# -----------------------------
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Safe", "Malicious"])

disp.plot()

plt.title("Confusion Matrix - URL Attack Detection")

plt.savefig("confusion_matrix.png")  # Saved image for report
plt.show()

print("Confusion Matrix Generated Successfully!")