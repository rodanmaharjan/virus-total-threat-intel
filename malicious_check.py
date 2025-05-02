from itertools import cycle
import requests
import time
import re
import vt

with open('input.txt', 'r') as ip_file, open('api_keys.txt', 'r') as key_file:

    # Read IP addresses and API keys from a file 
    ip_addresses = ip_file.read().splitlines()
    api_keys = key_file.read().splitlines()

    # Cycle through API keys to stay within resource constraints
    api_key_cycle = cycle(api_keys)
    new_api_keys = next(api_key_cycle)
    malicious_addresses = []

    for each in ip_addresses:

        new_api_keys = next(api_key_cycle)

        # Define regexes for IP addresses and URLs
        ip_regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?')
        url_regex = re.compile(r'\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')

        # If IP regex matches then only query VirusTotal with the IP
        if ip_regex.match(each):

            with open('malicious.txt', 'w') as malicious_file:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{each}"
                headers = {"accept": "application/json", "x-apikey": new_api_keys}
                print(f"\nMaking request for IP: {each} \nUsing API key: {new_api_keys}")
                response = requests.get(url, headers=headers)

                # If a successful response is obtained, extract the malicious value for the IP and append them to the malicious list
                if response.status_code == 200:
                    malicious_value = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
                    if malicious_value > 0:
                        print(f'Response for IP {each}: Malicious. \n Number of malicious reports: {malicious_value}\n')
                        malicious_addresses.append(each)
                    else:
                        print(f'Response for IP {each}: Not malicious')
                    time.sleep(20)
                    # No need to check other API keys if malicious detection is found

                else:
                    print(f"Request failed for IP {ip_addresses} with status code: {response.status_code}")
                    print(response.text)  # Print the response content for debugging purposes

        # If URL regex matches then only query VirusTotal with the URL
        elif url_regex.match(each):
            new_api_keys = next(api_key_cycle)
            with open('malicious.txt', 'w') as malicious_file:

                try:
                    print(f"\nMaking request for URL: {each}\nUsing API key: {new_api_keys}")
                    # Initialize the VirusTotal client with the current API key
                    client = vt.Client(new_api_keys)
                    # Get the URL ID or IP address
                    url_id = vt.url_id(each)
                    # Retrieve the URL analysis information
                    url_info = client.get_object("/urls/{}".format(url_id))

                    # Check if the URL is not found on VirusTotal
                    if not url_info:
                        print(f"No results found for: {each} on VirusTotal")
                        print()
                        continue

                    # Check if it is malicious
                    value = url_info.last_analysis_stats.get("malicious", 0)
                    if value > 0:
                        print(f"Response of URL {each} : Malicious")
                        print("Number of malicious reports:", value)
                        malicious_addresses.append(each)

                    else:
                        print(f"Response of URL {each}: Not malicious.")
                    time.sleep(20)

                except Exception as e:
                    print(f"An error occurred for {each}: {str(e)}")
                    print("Moving to the next URL...")
                    print()
                    continue

                finally:
                    if client:
                        client.close()

    with open('malicious.txt', 'a') as malicious_file:
        malicious_file.write('\n'.join(malicious_addresses) + '\n')
        
print(f"Malicious IP addresses written to malicious.txt")
