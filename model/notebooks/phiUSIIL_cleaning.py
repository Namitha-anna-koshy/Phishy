import pandas as pd
import numpy as np
import re
from sklearn.impute import SimpleImputer
from sklearn.feature_extraction import FeatureHasher
from sklearn.preprocessing import LabelEncoder

# 1. Load the dataset
df=pd.read_csv(r'C:\Users\Namitha Anna Koshy\Documents\HONORS\PROJECT\Phishy\Phishy\model\datasets\PhiUSIIL_Phishing_URL_Dataset.csv')


# 2. Separate Target and Features
y = df['label']
X = df.drop(columns=['label'])

# 3. Handle Missing Values (Imputation)
# Numerical: Use Median (more robust to outliers than Mean)
num_cols = X.select_dtypes(include=[np.number]).columns
imputer_num = SimpleImputer(strategy='median')
X[num_cols] = imputer_num.fit_transform(X[num_cols])

# Categorical: Use Mode (Most Frequent)
cat_cols = X.select_dtypes(include=['object']).columns
# We exclude 'URL', 'Domain', and 'Title' from mode imputation as they are unique
text_cols = ['URL', 'Domain', 'Title', 'FILENAME', 'TLD']
remaining_cats = [c for c in cat_cols if c not in text_cols]

if remaining_cats:
    imputer_cat = SimpleImputer(strategy='most_frequent')
    X[remaining_cats] = imputer_cat.fit_transform(X[remaining_cats])

# 4. Feature Hashing for Text Columns (Preserving Info vs Dropping)
# This converts unique strings into a fixed set of numerical features
for col in ['Title', 'Domain', 'TLD']:
    if col in X.columns:
        hasher = FeatureHasher(n_features=5, input_type='string')
        hashed_features = hasher.transform(X[col].astype(str).apply(lambda x: x.split())).toarray()
        hashed_df = pd.DataFrame(hashed_features, columns=[f'{col}_hash_{i}' for i in range(5)])
        X = pd.concat([X, hashed_df], axis=1)

# 5. Drop the raw text and redundant ID columns now that they are hashed/processed
X = X.drop(columns=text_cols)

# 6. Encode the Target Label
# Converts 'phishing'/'legitimate' into 1/0
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# 7. Final Cleaning: Sanitize Column Names for LightGBM/XGBoost
X.columns = [re.sub(r'[^A-Za-z0-9_]+', '', str(col)) for col in X.columns]

# 8. Reconstruct and Save
final_df = pd.concat([X, pd.Series(y_encoded, name='label')], axis=1)
final_df.to_csv('phishydataset.csv', index=False)

print("--- Preprocessing Complete ---")
print(f"Original Columns: {df.shape[1]}")
print(f"New Columns (Hashed & Cleaned): {final_df.shape[1]}")
print("File saved as: phishydataset.csv")

print("New Label Counts:")
print(df['label'].value_counts())