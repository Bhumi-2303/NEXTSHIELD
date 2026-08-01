from datasets import load_dataset
import pandas as pd
import sys

print("Downloading dataset...")
try:
    dataset = load_dataset("zefang-liu/phishing-email-dataset", split="train")
except Exception as e:
    print(f"Error downloading dataset: {e}")
    sys.exit(1)

print("Converting to pandas...")
df = dataset.to_pandas()
print(f"Columns: {df.columns.tolist()}")

# Ensure standard columns
# zefang-liu/phishing-email-dataset usually has 'text' and 'label' (or similar)
if 'spam' in df.columns and 'label' not in df.columns:
    df.rename(columns={'spam': 'label'}, inplace=True)
if 'Email Text' in df.columns and 'text' not in df.columns:
    df.rename(columns={'Email Text': 'text'}, inplace=True)
if 'Email Type' in df.columns and 'label' not in df.columns:
    df.rename(columns={'Email Type': 'label'}, inplace=True)
if 'email' in df.columns and 'text' not in df.columns:
    df.rename(columns={'email': 'text'}, inplace=True)
if 'content' in df.columns and 'text' not in df.columns:
    df.rename(columns={'content': 'text'}, inplace=True)

# Convert string labels like 'Phishing Email' / 'Safe Email' if needed
if 'label' in df.columns:
    df['label'] = df['label'].astype(str).str.lower().apply(lambda x: 1 if 'phishing' in x or x == 'spam' else 0)

# Keep only necessary columns to save space and time
if 'text' in df.columns and 'label' in df.columns:
    df = df[['text', 'label']]
else:
    print("Warning: Could not find standard 'text' and 'label' columns.")

df = df.dropna(subset=['text'])
df.to_csv("data/phishing/dataset.csv", index=False)
print(f"Saved {len(df)} rows to data/phishing/dataset.csv")
