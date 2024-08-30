import tldextract
import Levenshtein as lv

legitimate_domains = ['test.com', 'microsoft.com', 'google.com']

test_urls = [
    'http:test.co',
    'https://google.com',
    'https://www.facebook.firewall-update.com',
    'http://facebOOK.com/login',
    'http://test.com'
]

def extract_domain_parts(url):
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain,extracted.suffix

def is_misspelled_domain(domain, legitimate_domains,threshold=0.9):
    for legit_domain in legitimate_domains:
        similarity = lv.ratio(domain, legit_domain)
        if similarity >= threshold:
            return False   # it's legitimate domain
    return True  #  no close match found, possibly misspelled


def is_phising_url(url, legitimate_domains):
    subdomain, domain, suffix = extract_domain_parts(url)

    #  check if it's a known legitimate domain
    if f"{domain}.{suffix}" in legitimate_domains:
        return False

    #  check for misspelled domain names
    if is_misspelled_domain(domain, legitimate_domains):
        print(f"potential phising detected: {url}")
        return True

    # Additional check: if subdomain looks suspicious or similar to a legitimate domain
    if subdomain and is_misspelled_domain(subdomain + "." + domain, legitimate_domains):
        print(f"Potential phishing detected with suspicious subdomain: {url}")
        return True    

    #  we can add more checks here, like suspicious subdomains
                         
    return False    


#  press the green button in the gutter to run the script 
if __name__ == '__main__':
    for url in test_urls:
        is_phising_url(url, legitimate_domains)

       
        