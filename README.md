# Cloudflare IP Enrichment CLI

## Overview

This command-line tool is designed for security engineers to gather intelligence on IP addresses from various sources. It enriches IPs with data from IPQualityScore (IPQS) and Shodan's InternetDB, providing valuable context for threat analysis and security posture assessment.

## Features

- **Multiple IP Sources**: Fetch IPs from Cloudflare Access Rules, Cloudflare Zone Lockdown, a local file, or a single IP address.
- **Rich Data Enrichment**: Gathers information from IPQS and InternetDB.
- **Flexible Output**: Save enriched data in either CSV or JSON format.
- **Secure Credential Management**: Load API keys from a `.env` file or provide them as command-line arguments.

## Prerequisites

- Python 3
- `requests` and `python-dotenv` packages (`pip install -r requirements.txt`)
- API keys for:
    - Cloudflare (if using Cloudflare as a source)
    - IPQualityScore

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/cf-ip-enrichment.git
   cd cf-ip-enrichment
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your environment variables (optional but recommended):**
   Create a `.env` file in the project directory and add your API keys:
   ```
   CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"
   CLOUDFLARE_ZONE_ID="your_cloudflare_zone_id"
   IPQS_API_KEY="your_ipqs_api_key"
   ```

## Usage

The script is run from the command line with various options to specify the IP source, output format, and API keys.

### Examples

**1. Enrich IPs from Cloudflare Access Rules:**
```bash
python ip_enricher_cli.py --cf-access-rules --output cf_access_ips
```

**2. Enrich IPs from Cloudflare Zone Lockdown (JSON output):**
```bash
python ip_enricher_cli.py --cf-zone-lockdown --format json --output cf_lockdown_ips
```

**3. Enrich IPs from a local file (CSV output):**
```bash
python ip_enricher_cli.py --file /path/to/your/ips.txt --format csv --output enriched_from_file
```

**4. Enrich a single IP and specify API keys as arguments:**
```bash
python ip_enricher_cli.py --ip 8.8.8.8 --ipqs-api-key YOUR_IPQS_KEY --output single_ip_report
```

### All Command-Line Arguments

*   **IP Sources (choose one):**
    *   `--cf-access-rules`: Fetch IPs from Cloudflare Access Rules.
    *   `--cf-zone-lockdown`: Fetch IPs from Cloudflare Zone Lockdown.
    *   `--file <path>`: Path to a file with one IP per line.
    *   `--ip <address>`: A single IP address to enrich.

*   **API Credentials (optional if `.env` is used):**
    *   `--cf-zone-id <ID>`: Your Cloudflare Zone ID.
    *   `--cf-api-token <token>`: Your Cloudflare API token.
    *   `--ipqs-api-key <key>`: Your IPQS API key.

*   **Output Options:**
    *   `--output <filename>`: The base name for the output file (default: `enriched_output`).
    *   `--format <type>`: The output format, `csv` or `json` (default: `json`).

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
