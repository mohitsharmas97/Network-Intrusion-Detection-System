import pandas as pd
import joblib
import sys
import os

print(f"Pandas version: {pd.__version__}")

# Monkey patch for compatibility with older pickles
try:
    if not hasattr(pd, 'datetime'):
        print("Patching pd.datetime...")
        pd.datetime = pd.to_datetime
except Exception as e:
    print(f"Patching failed: {e}")

BASE_DIR = os.getcwd()
models = ['rf_model.pkl', 'iso_forest.pkl']

for m in models:
    print(f"Loading {m}...")
    try:
        path = os.path.join(BASE_DIR, m)
        model = joblib.load(path)
        print(f"  {m} loaded successfully!")
    except Exception as e:
        print(f"  {m} FAILED: {e}")
