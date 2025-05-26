import os
import pandas as pd
from dotenv import load_dotenv
from supabase import create_client, Client
import Levenshtein
from fraud_detection import check_phishing_indicators

load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

def fetch_table_from_supabase(table_name):
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    response = supabase.table(table_name).select("*").execute()
    return pd.DataFrame(response.data)

def compare_dataframes_with_levenshtein(token_df, reference_df, symbol_threshold=0.75, name_threshold=0.75):
    """
    Compare token_df with reference_df using Levenshtein similarity.
    Returns a DataFrame of matches with similarity scores.
    """
    result_data = []
    for idx, token_row in token_df.iterrows():
        token_symbol = str(token_row['symbol']).lower()
        token_name = str(token_row['name']).lower()
        best_match = None
        best_combined_score = 0
        for _, ref_row in reference_df.iterrows():
            ref_symbol = str(ref_row['symbol']).lower()
            ref_name = str(ref_row['name']).lower()
            # Levenshtein similarity
            if token_symbol and ref_symbol:
                max_symbol_len = max(len(token_symbol), len(ref_symbol))
                symbol_distance = Levenshtein.distance(token_symbol, ref_symbol)
                symbol_similarity = 1 - (symbol_distance / max_symbol_len if max_symbol_len > 0 else 0)
            else:
                symbol_similarity = 0
            if token_name and ref_name:
                max_name_len = max(len(token_name), len(ref_name))
                name_distance = Levenshtein.distance(token_name, ref_name)
                name_similarity = 1 - (name_distance / max_name_len if max_name_len > 0 else 0)
            else:
                name_similarity = 0
            combined_score = (symbol_similarity * 0.6) + (name_similarity * 0.4)
            if combined_score > best_combined_score:
                best_combined_score = combined_score
                best_match = {
                    'ref_symbol': ref_row['symbol'],
                    'ref_name': ref_row['name'],
                    'symbol_similarity': symbol_similarity,
                    'name_similarity': name_similarity,
                    'combined_score': combined_score
                }
        result_row = token_row.to_dict()
        if best_match:
            result_row.update({
                'match_symbol': best_match['ref_symbol'],
                'match_name': best_match['ref_name'],
                'symbol_similarity': best_match['symbol_similarity'],
                'name_similarity': best_match['name_similarity'],
                'combined_score': best_match['combined_score'],
                'is_match': (best_match['symbol_similarity'] >= symbol_threshold and best_match['name_similarity'] >= name_threshold)
            })
        else:
            result_row.update({
                'match_symbol': '',
                'match_name': '',
                'symbol_similarity': 0.0,
                'name_similarity': 0.0,
                'combined_score': 0.0,
                'is_match': False
            })
        result_data.append(result_row)
    all_results_df = pd.DataFrame(result_data)
    matched_df = all_results_df[all_results_df['is_match'] == True].copy()
    return matched_df

# This file has been deprecated. Use fraud_orchestrator.py for the orchestration logic.

    """
    Hybrid fraud assessment for ERC20 tokens. Classifies each token as 'counterfeit', 'repeat_scam', 'phishing', 'suspicious', or 'legit'.
    - Compares against both safe_tokens and fake_pairs (from fake_directory)
    - Runs phishing detection
    - Returns DataFrame with fraud_type and match details
    """
    # Fetch reference tables
    safe_tokens = fetch_table_from_supabase("safe_tokens")
    fake_directory = fetch_table_from_supabase("fake_directory")
    # Deduplicate fake_directory
    fake_pairs = pd.DataFrame(set(zip(fake_directory['name'], fake_directory['symbol'])), columns=['name', 'symbol'])
    # Similarity checks
    safe_matches = compare_dataframes_with_levenshtein(token_df, safe_tokens)
    fake_matches = compare_dataframes_with_levenshtein(token_df, fake_pairs)
    # Prepare output
    token_df = token_df.copy()
    token_df['fraud_type'] = 'legit'
    # Assign 'counterfeit' if similar to safe token
    token_df.loc[token_df.index.isin(safe_matches.index), 'fraud_type'] = 'counterfeit'
    # Assign 'repeat_scam' if similar to known fake (takes precedence)
    token_df.loc[token_df.index.isin(fake_matches.index), 'fraud_type'] = 'repeat_scam'
    # Run phishing/suspicious check (reuse check_phishing_indicators)
    for idx, row in token_df.iterrows():
        phishing_result = check_phishing_indicators(row)
        if phishing_result['is_suspicious']:
            if phishing_resuaslt['risk_score'] >= 80:
                token_df.at[idx, 'fraud_type'] = 'phishing'
            elif token_df.at[idx, 'fraud_type'] == 'legit':
                token_df.at[idx, 'fraud_type'] = 'suspicious'
        token_df.at[idx, 'phishing_score'] = phishing_result['risk_score']
        token_df.at[idx, 'phishing_indicators'] = str(phishing_result['indicators'])
    # Optionally, merge match details from legit/fake checks
    # (left as exercise for further enrichment)
    return token_df

# Usage Example:
# tokens_to_check = pd.DataFrame([{ 'name': 'USDT', 'symbol': 'USDT', ... }])
# results = assess_token_fraud(tokens_to_check)
# print(results)
