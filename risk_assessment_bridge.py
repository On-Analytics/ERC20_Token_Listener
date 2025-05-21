import sys
import json
from fraud_detection import check_phishing_indicators

if __name__ == "__main__":
    # Read JSON from stdin
    input_data = sys.stdin.read()
    token_data = json.loads(input_data)
    result = check_phishing_indicators(token_data)
    print(json.dumps(result))
