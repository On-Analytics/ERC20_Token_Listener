import pandas as pd
from phishing_detection import check_phishing_indicators
from counterfeit_detection import assess_token_counterfeit

def assess_token_fraud(token_df: pd.DataFrame) -> pd.DataFrame:
    """
    Orchestrates phishing and counterfeit detection to classify each token as:
    'phishing', 'counterfeit', 'repeat_scam', 'suspicious', or 'legit'.
    Combines results from both detection modules and applies priority logic.
    """
    # Run phishing detection
    phishing_results = []
    for _, row in token_df.iterrows():
        phishing_results.append(check_phishing_indicators(row))
    phishing_df = pd.DataFrame(phishing_results)
    
    # Run counterfeit detection
    counterfeit_df = assess_token_counterfeit(token_df)
    
    # Merge results
    result_df = token_df.copy()
    result_df['fraud_type'] = 'unknown'
    
    # Add phishing info
    result_df['phishing_indicators'] = phishing_df['indicators']
    result_df['urls_found'] = phishing_df['details'].apply(lambda d: d.get('urls_found', []))
    result_df['money_amounts'] = phishing_df['details'].apply(lambda d: d.get('money_amounts', []))
    # Final fraud_type assignment (priority: phishing > counterfeit > suspicious > unknown)
    for idx in result_df.index:
        has_url = bool(result_df.at[idx, 'urls_found'])
        has_indicator = bool(result_df.at[idx, 'phishing_indicators'])
        has_amount = bool(result_df.at[idx, 'money_amounts'])
        is_counterfeit = counterfeit_df.at[idx, 'counterfeit_type'] == 'counterfeit'
        
        if has_url and (has_indicator or has_amount):
            result_df.at[idx, 'fraud_type'] = 'phishing'
        elif is_counterfeit:
            result_df.at[idx, 'fraud_type'] = 'counterfeit'
        elif (has_indicator and has_amount) or has_url or has_indicator or has_amount:
            result_df.at[idx, 'fraud_type'] = 'suspicious'
        else:
            result_df.at[idx, 'fraud_type'] = 'unknown'
            
    # Set risk_category based on fraud_type
    def get_risk_category(fraud_type):
        if fraud_type in ['phishing', 'counterfeit']:
            return 'high risk'
        elif fraud_type == 'suspicious':
            return 'caution'
        else:  # 'unknown' or any other value
            return 'unknown'
    
    result_df['risk_category'] = result_df['fraud_type'].apply(get_risk_category)
    return result_df


# Example usage:
# tokens_to_check = pd.DataFrame([{ 'name': 'USDT', 'symbol': 'USDT', ... }])
# results = assess_token_fraud(tokens_to_check)
# print(results)
