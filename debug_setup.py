import sys
print(f"Python version: {sys.version}")

try:
    import pandas as pd
    print(f"Pandas version: {pd.__version__}")
except Exception as e:
    print(f"Pandas import failed: {e}")

try:
    import joblib
    print(f"Joblib version: {joblib.__version__}")
except Exception as e:
    print(f"Joblib import failed: {e}")

# Try loading the models to pinpoint the failure
import os
BASE_DIR = os.getcwd()
try:
    print("Attempting to load rf_model.pkl...")
    rf_model = joblib.load(os.path.join(BASE_DIR, 'rf_model.pkl'))
    print("rf_model loaded successfully")
except Exception as e:
    print(f"rf_model load failed: {e}")

try:
    print("Attempting to load iso_forest.pkl...")
    iso_forest = joblib.load(os.path.join(BASE_DIR, 'iso_forest.pkl'))
    print("iso_forest loaded successfully")
except Exception as e:
    print(f"iso_forest load failed: {e}")
