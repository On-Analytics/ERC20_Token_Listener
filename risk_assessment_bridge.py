import sys
import json
from fraud_orchestrator import assess_token_fraud
import pandas as pd
import os
from dotenv import load_dotenv
from supabase import create_client, Client

if __name__ == "__main__":
    # Read JSON from stdin
    input_data = sys.stdin.read()
    tokens = json.loads(input_data)
    token_df = pd.DataFrame(tokens)
    result_df = assess_token_fraud(token_df)

    # Store results in Supabase table 'erc20_tokens'
    load_dotenv()
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

    # Upsert each row (assuming 'contract_address' is unique key; change if needed)
    for row in result_df.to_dict(orient='records'):
        # Combine all detection details into a single dict
        detection_details = {
            'phishing_indicators': row.get('phishing_indicators', []),
            'urls_found': row.get('urls_found', []),
            'money_amounts': row.get('money_amounts', []),
            'details': row.get('details', {}),
            'warnings': row.get('warnings', [])
        }
        
        # Ensure fraud_type is not None
        fraud_type = row.get('fraud_type')
        if fraud_type is None:
            fraud_type = 'unknown'
            
        # Ensure risk_category is not None
        risk_category = row.get('risk_category')
        if risk_category is None:
            risk_category = 'unknown'
        
        # Prepare row for insert: keep only columns that exist in the table schema
        upsert_row = {
            'contract_address': row.get('contract_address'),
            'blockchain': row.get('blockchain'),
            'name': row.get('name'),
            'symbol': row.get('symbol'),
            'decimals': row.get('decimals'),
            'creator_address': row.get('creator_address'),
            'created_block_timestamp': row.get('created_block_timestamp'),
            'fraud_type': fraud_type,
            'risk_category': risk_category,
            'detection_details': json.dumps(detection_details)  # Explicitly convert to JSON string
        }
        
        try:
            # Use upsert with the correct constraint name
            response = supabase.table("erc20_tokens").upsert(upsert_row, on_conflict="contract_address,blockchain").execute()
            # Use stderr for logs to avoid interfering with JSON output
            print(f"Saved to Supabase with fraud_type={fraud_type}, risk_category={risk_category}", file=sys.stderr)
        except Exception as e:
            print(f"Error saving to Supabase: {e}", file=sys.stderr)
            print(f"Attempted to save: {upsert_row}", file=sys.stderr)
            # Continue with next token even if this one fails

    print(result_df.to_json(orient='records'))
