import tldextract
import Levenshtein as lv
import logging
import re
from termcolor import colored  # For colored output

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Legitimate domains and suspicious keywords list
legitimate_domains = ['test.com', 'microsoft.com', 'google.com']
suspicious_keywords = ['login', 'secure', 'update', 'verify', 'account']

# URLs to test
test_urls = [
    'http:test.co',  # Malformed URL
    'https://google.com',
    'https://www.facebook.firewall-update.com',
    'http://facebOOK.com/login',
    'http://test.com',
    'http://secure-login.google.com',
    'http://microsoft-updates.fakeupdate.com',
    'http://paypal.verify.account.fake-site.com',
    'https://amaz0n.com',  # Phishing attempt with number substitution
    'https://sub.domain.with.hypens-login.com'
]

def normalize_url(url):
    # Ensure the URL starts with http:// or https://
    if not re.match(r'^https?:\/\/', url):
        url = 'http://' + url
    return url

def extract_domain_parts(url):
    # Normalize URL first
    url = normalize_url(url)
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain, extracted.suffix

def is_misspelled_domain(domain, legitimate_domains, threshold=0.8):
    for legit_domain in legitimate_domains:
        similarity = lv.ratio(domain.lower(), legit_domain.lower())
        if similarity >= threshold:
            return False  # It's a legitimate domain
    return True  # No close match found, possibly misspelled

def contains_suspicious_keywords(url):
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            logging.warning(colored(f"Suspicious keyword detected in URL: {url}", 'yellow'))
            return True
    return False

def has_suspicious_tld(suffix):
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz']
    return suffix.lower() in suspicious_tlds

def has_suspicious_pattern(domain):
    if re.search(r'[-]{2,}', domain) or re.search(r'\d', domain):
        logging.warning(colored(f"Suspicious pattern detected in domain: {domain}", 'yellow'))
        return True
    return False

def is_phishing_url(url, legitimate_domains):
    subdomain, domain, suffix = extract_domain_parts(url)
    full_domain = f"{domain}.{suffix}"
    
    # Check if it's a known legitimate domain
    if full_domain in legitimate_domains:
        return False, "Domain matches legitimate domains"

    # Check for misspelled domain names
    if is_misspelled_domain(domain, legitimate_domains):
        return True, "Misspelled domain"

    # Check for suspicious keywords
    if contains_suspicious_keywords(url):
        return True, "Suspicious keywords"

    # Check for suspicious subdomain patterns
    if subdomain and is_misspelled_domain(subdomain + "." + domain, legitimate_domains):
        return True, "Suspicious subdomain"

    # Check for suspicious TLDs
    if has_suspicious_tld(suffix):
        return True, "Suspicious TLD"

    # Check for suspicious patterns
    if has_suspicious_pattern(domain):
        return True, "Suspicious pattern"

    # Further checks could include analyzing URL path, special characters, etc.
    
    return False, "URL is safe"

# Press the green button in the gutter to run the script
if __name__ == '__main__':
    phishing_count = 0
    safe_count = 0

    for url in test_urls:
        result, reason = is_phishing_url(url, legitimate_domains)
        if result:
            print(colored(f"Potential phishing detected: {url} - Reason: {reason}", 'red'))
            phishing_count += 1
        else:
            print(colored(f"URL is considered safe: {url}", 'green'))
            safe_count += 1

    # Summary report
    print("\nSummary Report:")
    print(colored(f"Total URLs tested: {len(test_urls)}", 'cyan'))
    print(colored(f"Potential phishing attempts detected: {phishing_count}", 'red'))
    print(colored(f"Safe URLs: {safe_count}", 'green'))
