import requests
import time
import re
from itertools import cycle
import vt

# Function to load IP addresses and API keys from text files
def load_files():
    """Load IP addresses and API keys from respective files."""
    with open('data/input.txt', 'r') as ip_file, open('data/api_keys.txt', 'r') as key_file:
        ip_addresses = ip_file.read().splitlines()
        api_keys = key_file.read().splitlines()
    return ip_addresses, api_keys

# Function to validate IP addresses
def is_valid_ip(ip):
    """Validate if the string is a valid IP address."""
    ip_regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?')
    return ip_regex.match(ip)

# Function to validate URLs
def is_valid_url(url):
    """Validate if the string is a valid URL."""
    url_regex = re.compile(r'\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')
    return url_regex.match(url)

# Check IP reputation using VirusTotal API
def check_ip(ip, api_key):
    """Check IP reputation using VirusTotal API."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        malicious_value = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return malicious_value > 0
    return False

# Check URL reputation using VirusTotal API
def check_url(url, api_key):
    """Check URL reputation using VirusTotal API."""
    try:
        client = vt.Client(api_key)
        url_id = vt.url_id(url)
        url_info = client.get_object(f"/urls/{url_id}")
        return url_info.last_analysis_stats.get("malicious", 0) > 0
    except Exception:
        return False
    finally:
        if client:
            client.close()

# Main function to orchestrate the checks
def main():
    """Main function to perform malicious checks for IPs and URLs."""
    ip_addresses, api_keys = load_files()
    api_key_cycle = cycle(api_keys)
    malicious_addresses = []

    for each in ip_addresses:
        current_api_key = next(api_key_cycle)
        if is_valid_ip(each):
            if check_ip(each, current_api_key):
                print(f"{each} is malicious")
                malicious_addresses.append(each)
        elif is_valid_url(each):
            if check_url(each, current_api_key):
                print(f"{each} is malicious")
                malicious_addresses.append(each)

        time.sleep(20)  # Rate-limiting

    # Save results to file
    with open('malicious.txt', 'w') as malicious_file:
        malicious_file.write('\n'.join(malicious_addresses))

    print("Malicious IP addresses and URLs saved to malicious.txt")

if __name__ == "__main__":
    main()