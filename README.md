# VirusTotal Malicious IP, Domain and URL Check

## Overview

This Python tool is designed for Threat Intelligence (CTI) Analysts to automate the detection of malicious IPs and URLs using the [VirusTotal API](https://www.virustotal.com/). It supports checking multiple IPs, Domains and URLs, and outputs the results, allowing teams to monitor potential threats effectively.

### Features:
- **Automated Malicious IP and URL Detection**: Queries the VirusTotal API to check for malicious reports.
- **API Key Cycling**: Automatically rotates through multiple VirusTotal API keys to avoid hitting rate limits.
- **Malicious Report Logging**: Saves malicious IPs and URLs to a `malicious.txt` file for tracking and analysis.
- **Supports both IPs and URLs**: Checks both types of indicators in threat intelligence workflows.

### Requirements:
- **Python 3.x**
- `requests` library for making HTTP requests.
- `vt` (VirusTotal) Python client library.
- VirusTotal API key(s).

### Installation and Setup:

1. **Clone the repository:**
    ```bash
    git clone https://github.com/rodanmaharjan/cti-malicious-check.git
    cd cti-malicious-check
    ```

2. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3. **Obtain a VirusTotal API Key:**
    - Sign up for a VirusTotal account [here](https://www.virustotal.com/).
    - Copy your API key from your account settings.

4. **Prepare the input files:**
    - `input.txt`: List of IPs and URLs to check (one per line).
    - `api_keys.txt`: List of your VirusTotal API keys (one per line).

5. **Run the script:**
    ```bash
    python src/malicious_check.py
    ```

### Usage:
1. Add your IP addresses, domains and URLs to `data/input.txt`.
2. Add your VirusTotal API keys to `data/api_keys.txt`.
3. Run the script, and the results will be saved to `malicious.txt`.

Example output:
Making request for IP: 192.168.0.1 Using API key: your-api-key Response for IP 192.168.0.1: Malicious Number of malicious reports: 3


### Contributing:
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a pull request.

### License:
MIT License. See [LICENSE](LICENSE) for more details.

