import os
from datasets import load_dataset
import pandas as pd

def main():
    print("Downloading CIC-IDS2017 dataset from Hugging Face...")
    # Attempt to load a subset to avoid downloading the entire 5GB+ dataset if possible, 
    # but the user asked for a real dataset so we'll grab it. 
    # 'rdpahalavan/CIC-IDS2017' is a common cleaned version.
    try:
        # Load just the wednesday split if available, or train split
        dataset = load_dataset("rdpahalavan/CIC-IDS2017", split="train")
    except Exception as e:
        print(f"Error downloading: {e}")
        return

    print("Converting to pandas dataframe...")
    df = dataset.to_pandas()
    
    # We only need a fraction of the data for training locally without OOM
    # Let's take 100,000 samples to keep it manageable but real
    if len(df) > 100000:
        print(f"Dataset has {len(df)} rows. Sampling 100,000 to save memory and time...")
        df = df.sample(n=100000, random_state=42)
    
    os.makedirs("../data/network", exist_ok=True)
    out_path = "../data/network/cicids2017_wednesday.csv"
    print(f"Saving to {out_path}...")
    df.to_csv(out_path, index=False)
    print("Done!")

if __name__ == "__main__":
    main()
