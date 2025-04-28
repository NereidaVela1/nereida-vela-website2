import os
import pandas as pd

# La Banca Central Bank dataset for DAT 223 Project Three

def check_environment():
    """Verify pandas installation and working directory."""
    try:
        print("Pandas is installed:", pd.__version__)
    except ImportError:
        print("Error: Pandas is not installed. Install with 'pip install pandas'.")
        raise
    print("Current working directory:", os.getcwd())
    print("Files in current directory:", os.listdir('.'))

def load_datasets():
    """Load CSV files with error handling."""
    try:
        fraud_1_df = pd.read_csv('FraudDatasetSubset_1.csv')
        fraud_2_df = pd.read_csv('FraudDatasetSubset_2.csv')
        return fraud_1_df, fraud_2_df
    except FileNotFoundError as e:
        print(f"Error: {e}. Ensure FraudDatasetSubset_1.csv and FraudDatasetSubset_2.csv are in {os.getcwd()}.")
        print("Search for files with: dir FraudDatasetSubset_*.csv /s /p")
        raise

def merge_datasets(fraud_1_df, fraud_2_df):
    """Merge datasets using an outer join and fill missing values."""
    fraud_merged = fraud_1_df.merge(fraud_2_df, left_on='nameOrig', right_on='nameOrig', how='outer')
    fraud_merged.fillna(0, inplace=True)
    return fraud_merged

def display_results(fraud_1_df, fraud_2_df, fraud_merged):
    """Display dataset sizes and first 10 rows."""
    print(f'Original dataset sizes:  fraud_1_df={fraud_1_df.shape},  fraud_2_df={fraud_2_df.shape}')
    print(f'Merged dataset size:  fraud_merged={fraud_merged.shape}')
    print("\nFirst 10 rows of merged dataset:")
    print(fraud_merged.head(10))

def main():
    """Main function to execute fraud analysis."""
    try:
        check_environment()
        fraud_1_df, fraud_2_df = load_datasets()
        fraud_merged = merge_datasets(fraud_1_df, fraud_2_df)
        display_results(fraud_1_df, fraud_2_df, fraud_merged)
    except Exception as e:
        print(f"Error in fraud analysis: {e}")
        raise

if __name__ == "__main__":
    main()


