import os
import pandas as pd
from dotenv import load_dotenv
from supabase import create_client, Client
import Levenshtein

load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

def fetch_table_from_supabase(table_name):
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    response = supabase.table(table_name).select("*").execute()
    return pd.DataFrame(response.data)

def compare_dataframes_with_levenshtein(token_df, reference_df, symbol_threshold=0.75, name_threshold=0.75):
    """
    Compare token_df with reference_df using Levenshtein similarity.
    Returns a DataFrame of matches with similarity scores.
    
    Parameters:
    - token_df: DataFrame with tokens to check
    - reference_df: DataFrame with reference tokens
    - symbol_threshold: Minimum similarity threshold for symbol (default 0.75)
    - name_threshold: Minimum similarity threshold for name (default 0.75)
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
            # Check if both symbol and name meet the similarity thresholds
            is_match = (best_match['symbol_similarity'] >= symbol_threshold and 
                        best_match['name_similarity'] >= name_threshold)
            
            result_row.update({
                'match_symbol': best_match['ref_symbol'],
                'match_name': best_match['ref_name'],
                'symbol_similarity': best_match['symbol_similarity'],
                'name_similarity': best_match['name_similarity'],
                'combined_score': best_match['combined_score'],
                'is_match': is_match
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

def assess_token_counterfeit(token_df):
    """
    Assess if tokens are counterfeit or repeat scams by comparing against safe_tokens and fake_directory.
    Returns DataFrame with match details and assigned types.
    """
    safe_tokens = fetch_table_from_supabase("safe_tokens")
    fake_directory = fetch_table_from_supabase("fake_directory")
    
    # Extract only the name and symbol columns from fake_directory
    # Use drop_duplicates to keep only unique combinations while preserving column names
    fake_pairs = fake_directory[['name', 'symbol']].drop_duplicates().copy()
    
    safe_matches = compare_dataframes_with_levenshtein(token_df, safe_tokens)
    fake_matches = compare_dataframes_with_levenshtein(token_df, fake_pairs)
    token_df = token_df.copy()
    token_df['counterfeit_type'] = 'unknown'
    # If a token matches either safe or fake, mark as 'counterfeit'
    is_counterfeit = token_df.index.isin(safe_matches.index) | token_df.index.isin(fake_matches.index)
    token_df.loc[is_counterfeit, 'counterfeit_type'] = 'counterfeit'
    token_df['counterfeit_match'] = is_counterfeit
    return token_df
