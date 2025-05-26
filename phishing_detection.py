from typing import Dict, Any, List, Union, Optional, Set
import re
import unicodedata
from urlextract import URLExtract
import tldextract

def extract_urls_and_domains(row: Dict[str, Any]) -> List[str]:
    """
    Extract URLs and domains from token symbol and name.
    Args:
        row: Dictionary containing token data with 'symbol' and 'name' keys
    Returns:
        List of unique URLs/domains found (lowercase), or [] if none found
    """
    extractor = URLExtract()
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    text = f"{str(row.get('symbol', ''))} {str(row.get('name', ''))}"
    urls = set(extractor.find_urls(text))
    domains = set(re.findall(domain_pattern, text, flags=re.IGNORECASE))
    all_links = urls.union(domains)
    return list(map(str.lower, all_links)) if all_links else []

def parse_domains(urls: Union[List[str], str]) -> Union[List[str], str]:
    """
    Extract and normalize domain names from a list of URLs.
    Args:
        urls: List of URLs or "No URL found" string
    Returns:
        List of unique domain names (lowercase) or "No URL found" string
    """
    if not urls or urls == "No URL found":
        return "No URL found"
    domains = set()
    for url in urls:
        ext = tldextract.extract(url)
        domain = ".".join(part for part in [ext.domain, ext.suffix] if part)
        if domain:
            domains.add(domain.lower())
    return list(domains) if domains else "No URL found"

def preprocess_text(text: str) -> str:
    """
    Normalize and clean text for better phishing detection.
    Args:
        text: Input text to preprocess
    Returns:
        Preprocessed and normalized text
    """
    if not isinstance(text, str):
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r'[А-Яа-я]', lambda x: chr(ord(x.group(0)) - 848), text)
    text = text.lower()
    text = re.sub(r'[!\[\]#]', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'(?i)\b([a-zA-Z])\s+(?=[a-zA-Z])', r'\1', text)
    text = re.sub(r'(?<=\w)[^\w.-]+(?=\w)', ' ', text)
    text = re.sub(r'^[^\w.-]+', '', text)
    text = re.sub(r'[^a-zA-Z0-9.-]+$', '', text)
    return text.strip()

def find_phishing_indicators(name: Optional[str], symbol: Optional[str]) -> Union[List[str], str]:
    """
    Find phishing indicators in token name and symbol.
    Args:
        name: Token name
        symbol: Token symbol
    Returns:
        List of found phishing indicators or "No Match"
    """
    phishing_indicators = [
        "immediately", "now", "warning", "last chance", "final", "suspend", "limited time",
        "deadline", "important", "alert", "urgent", "scan", "qr", "activate", "breach", "security",
        "giveaway", "airdrop", "free", "claim", "reward", "bonus", "jackpot", "profit", "win", "double",
        "instant", "rewards", "cashout", "income", "earn", "gift", "collect", "voucher", "code", "loot",
        "fee", "congratulations", "congratz", "chance", "withdraw", "deposit", "redeem", "get", "promo",
        "limited", "lend", "swap", "bounty",
        "url", "login", "login page", "dashboard", "connect", "connect wallet", "verify", "access", "restore",
        "walletconnect", "web", "web3", "interface", "portal", "site", "website", "app", "application", "official",
        "exchange", "market", "swap", "pool", "bridge", "stake", "unstake", "farm", "mint", "burn", "token",
        "contract", "address", "approve", "sign", "signature", "transaction", "transfer", "send", "receive",
        "claim", "collect", "drop", "minting", "airdrops",
        "support", "help", "contact", "service", "customer", "team", "admin", "mod", "owner", "official",
        "announcement", "news", "update", "event", "info", "information"
    ]
    found_indicators = set()
    if name:
        cleaned_name = preprocess_text(name)
        found_indicators.update(
            indicator for indicator in phishing_indicators 
            if indicator in cleaned_name
        )
    if symbol:
        cleaned_symbol = preprocess_text(symbol)
        found_indicators.update(
            indicator for indicator in phishing_indicators 
            if indicator in cleaned_symbol
        )
    return list(found_indicators) if found_indicators else "No Match"

def extract_money_amounts(name: Optional[str], symbol: Optional[str]) -> Union[List[str], str]:
    """
    Extract money amounts from token name and symbol.
    Args:
        name: Token name
        symbol: Token symbol
    Returns:
        List of found money amounts or "No Match"
    """
    all_matches: List[str] = []
    money_pattern = re.compile(r'\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?', re.IGNORECASE)
    if name:
        text = unicodedata.normalize("NFKC", name)
        matches = money_pattern.findall(text)
        all_matches.extend(match.replace(" ", "") for match in matches)
    if symbol:
        text = unicodedata.normalize("NFKC", symbol)
        matches = money_pattern.findall(text)
        all_matches.extend(match.replace(" ", "") for match in matches)
    return all_matches if all_matches else "No Match"

def check_phishing_indicators(token_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check for potential phishing indicators in token data using multiple detection methods.
    Args:
        token_data: Dictionary containing token information with at least:
                  - name: Token name
                  - symbol: Token symbol
                  - contract_address: Token contract address
    Returns:
        Dictionary with analysis results including:
        - is_suspicious: Boolean indicating if token is suspicious
        - risk_score: Numeric score (0-100) indicating risk level
        - indicators: List of found indicators
        - details: Detailed findings from each check
    """
    result = {
        'indicators': [],
        'details': {
            'urls_found': [],
            'domains_found': [],
            'phishing_indicators':  [],
            'money_amounts': [],
            'warnings': []
        }
    }
    # 1. Check for URLs in symbol/name
    try:
        urls = extract_urls_and_domains(token_data)
        if urls and urls != "No URL found":
            result['details']['urls_found'] = urls

            result['indicators'].append('URLs found in token name/symbol')
            domains = parse_domains(urls)
            if domains and domains != "No URL found":
                result['details']['domains_found'] = domains
    except Exception as e:
        result['details']['warnings'].append(f'URL extraction failed: {str(e)}')
    # 2. Check for phishing indicators in name/symbol
    try:
        name = token_data.get('name', '')
        symbol = token_data.get('symbol', '')
        phishing_indicators = find_phishing_indicators(name, symbol)
        if phishing_indicators != "No Match":
            result['details']['phishing_indicators'] = phishing_indicators

            result['indicators'].extend(phishing_indicators)
    except Exception as e:
        result['details']['warnings'].append(f'Phishing indicator check failed: {str(e)}')
    # 3. Check for money amounts in name/symbol
    try:
        money_amounts = extract_money_amounts(name, symbol)
        if money_amounts != "No Match":
            result['details']['money_amounts'] = money_amounts

            result['indicators'].append('Money amount found in name/symbol')
    except Exception as e:
        result['details']['warnings'].append(f'Money amount extraction failed: {str(e)}')
    # 4. Additional checks can be added here
    result['details'] = {k: v for k, v in result['details'].items() if v}

    return result
