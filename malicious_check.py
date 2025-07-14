from itertools import cycle
import requests
import time
import re
import vt

# Read IP addresses and API keys from files
with open('input.txt', 'r') as ip_file, open('api_keys.txt', 'r') as key_file:
    ip_addresses = ip_file.read().splitlines()
    api_keys = key_file.read().splitlines()

api_key_cycle = cycle(api_keys)

ip_regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?')
url_regex = re.compile(r'\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')

for each in ip_addresses:
    new_api_key = next(api_key_cycle)

    # Check if it's an IP
    if ip_regex.match(each):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{each}"
        headers = {"accept": "application/json", "x-apikey": new_api_key}
        print(f"\nMaking request for IP: {each} \nUsing API key: {new_api_key}")
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                malicious_value = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
                if malicious_value > 1:
                    print(f'Response for IP {each}: Malicious. \nNumber of malicious reports: {malicious_value}\n')
                    with open('malicious.txt', 'a') as malicious_file:
                        malicious_file.write(each + '\n')
                else:
                    print(f'Response for IP {each}: Not malicious')
            else:
                print(f"Request failed for IP {each} with status code: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"An error occurred while checking IP {each}: {e}")
        time.sleep(20)

    # Check if it's a URL
    elif url_regex.match(each):
        try:
            print(f"\nMaking request for URL: {each}\nUsing API key: {new_api_key}")
            client = vt.Client(new_api_key)
            url_id = vt.url_id(each)
            url_info = client.get_object(f"/urls/{url_id}")
            if not url_info:
                print(f"No results found for: {each} on VirusTotal\n")
                continue
            value = url_info.last_analysis_stats.get("malicious", 0)
            if value > 1:
                print(f"Response for URL {each}: Malicious. \nNumber of malicious reports: {value}")
                with open('malicious.txt', 'a') as malicious_file:
                    malicious_file.write(each + '\n')
            else:
                print(f"Response for URL {each}: Not malicious.")
        except Exception as e:
            print(f"An error occurred for {each}: {str(e)}\nMoving to the next URL...\n")
        finally:
            if 'client' in locals():
                client.close()
        time.sleep(20)

print("Scan completed. Malicious entries were written instantly to malicious.txt.")
