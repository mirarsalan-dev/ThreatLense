import re
import urllib.parse
import tldextract
from urllib.parse import urlparse

class FeatureExtractor:
    """
    Extracts 50+ structural and linguistic features from a given URL.
    Used for Machine Learning detection.
    """
    def __init__(self):
        # Common suspicious words found in phishing URLs
        self.suspicious_words = [
            'login', 'verify', 'account', 'secure', 'update', 
            'password', 'signin', 'confirm', 'bank', 'free', 
            'gift', 'wallet', 'auth', 'recovery', 'billing', 'support'
        ]

    def extract_features(self, url):
        features = {}
        
        # Ensure URL has scheme for accurate parsing
        if not url.startswith('http'):
            url = 'http://' + url

        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Basic Length Features (5)
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed_url.netloc)
        features['path_length'] = len(parsed_url.path)
        features['query_length'] = len(parsed_url.query)
        features['fragment_length'] = len(parsed_url.fragment)

        # Character/Symbol Counts (12)
        features['qty_dot'] = url.count('.')
        features['qty_hyphen'] = url.count('-')
        features['qty_underline'] = url.count('_')
        features['qty_slash'] = url.count('/')
        features['qty_questionmark'] = url.count('?')
        features['qty_equal'] = url.count('=')
        features['qty_at'] = url.count('@')
        features['qty_and'] = url.count('&')
        features['qty_percent'] = url.count('%')
        features['qty_plus'] = url.count('+')
        features['qty_asterisk'] = url.count('*')
        features['qty_hash'] = url.count('#')

        # Domain Specific (7)
        features['qty_dot_domain'] = parsed_url.netloc.count('.')
        features['qty_hyphen_domain'] = parsed_url.netloc.count('-')
        features['qty_vowels_domain'] = sum(1 for c in parsed_url.netloc if c.lower() in 'aeiou')
        features['domain_in_ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.netloc) else 0
        features['subdomain_length'] = len(extracted.subdomain)
        features['tld_length'] = len(extracted.suffix)
        features['server_client_domain'] = 1 if 'server' in parsed_url.netloc or 'client' in parsed_url.netloc else 0

        # Path Specific (5)
        features['qty_dot_path'] = parsed_url.path.count('.')
        features['qty_hyphen_path'] = parsed_url.path.count('-')
        features['qty_slash_path'] = parsed_url.path.count('/')
        features['qty_space_path'] = parsed_url.path.count('%20') + parsed_url.path.count(' ')
        features['path_extension'] = 1 if '.' in parsed_url.path.split('/')[-1] else 0

        # Directory / File (3)
        directories = [d for d in parsed_url.path.split('/') if d]
        features['qty_directories'] = len(directories)
        features['length_longest_dir'] = max([len(d) for d in directories]) if directories else 0
        features['length_shortest_dir'] = min([len(d) for d in directories]) if directories else 0

        # Query Specific (4)
        features['qty_params'] = parsed_url.query.count('=')
        features['qty_dot_query'] = parsed_url.query.count('.')
        features['qty_hyphen_query'] = parsed_url.query.count('-')
        features['tld_in_query'] = 1 if extracted.suffix in parsed_url.query else 0

        # Linguistic / Keywords (3)
        features['qty_suspicious_words'] = sum(1 for word in self.suspicious_words if word in url.lower())
        features['email_in_url'] = 1 if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url) else 0
        features['qty_digits'] = sum(c.isdigit() for c in url)

        # Obfuscation (3)
        features['is_encoded'] = 1 if '%' in url else 0
        features['is_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['qty_hexadecimal'] = len(re.findall(r'%[0-9a-fA-F]{2}', url))

        # We now have 42 features. Let's add 8 more for 50+.
        features['qty_digits_domain'] = sum(c.isdigit() for c in parsed_url.netloc)
        features['qty_letters_domain'] = sum(c.isalpha() for c in parsed_url.netloc)
        features['qty_digits_path'] = sum(c.isdigit() for c in parsed_url.path)
        features['tld_in_subdomain'] = 1 if extracted.suffix in extracted.subdomain else 0
        features['tld_in_path'] = 1 if extracted.suffix in parsed_url.path else 0
        features['qty_tilde'] = url.count('~')
        features['qty_comma'] = url.count(',')
        features['domain_entropy'] = self._calculate_entropy(parsed_url.netloc)

        return features

    def _calculate_entropy(self, string):
        import math
        from collections import Counter
        prob = [float(c) / len(string) for c in dict(Counter(string)).values()]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])
