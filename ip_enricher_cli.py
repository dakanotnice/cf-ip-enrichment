
import csv
import json
import requests
import os
import argparse
from datetime import datetime
import logging
from dotenv import load_dotenv
import time

# --- CONFIGURATION ---
LOG_FILE = "ip_enricher_cli.log"
INTERNETDB_TIMEOUT = 10
REQUEST_DELAY = 0.2

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# --- API FUNCTIONS ---

def get_auth_headers(token):
    """Constructs standard authorization headers for Cloudflare."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

def fetch_cloudflare_ips(zone_id, api_token, rule_type='access_rules'):
    """
    Fetches IPs from Cloudflare based on the specified rule type.
    :param rule_type: 'access_rules' or 'zone_lockdown'.
    """
    if not api_token or not zone_id:
        logging.critical(f"Cloudflare API token and Zone ID are required.")
        return []

    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
    endpoints = {
        'access_rules': f"{base_url}/firewall/access_rules/rules",
        'zone_lockdown': f"{base_url}/firewall/lockdowns"
    }
    
    api_endpoint = endpoints.get(rule_type)
    if not api_endpoint:
        logging.error(f"Invalid rule type specified: {rule_type}")
        return []

    headers = get_auth_headers(api_token)
    ips = []
    page_number = 1
    per_page = 150

    logging.info(f"Fetching '{rule_type}' from Cloudflare Zone ID: {zone_id}...")

    try:
        while True:
            params = {'page': page_number, 'per_page': per_page}
            if rule_type == 'access_rules':
                params['mode'] = 'whitelist'

            response = requests.get(api_endpoint, headers=headers, params=params, timeout=20)
            response.raise_for_status()
            results = response.json()

            if not results.get('success') or 'result' not in results:
                logging.error("Cloudflare API call failed.")
                return []

            rules = results['result']
            if not rules:
                break

            if rule_type == 'access_rules':
                for rule in rules:
                    if rule.get('configuration', {}).get('target') in ['ip', 'ip_range']:
                        ips.append(rule['configuration']['value'])
            elif rule_type == 'zone_lockdown':
                for rule in rules:
                    for config in rule.get('configurations', []):
                        if config.get('target') == 'ip_range':
                            ips.append(config['value'])
            
            page_number += 1
            time.sleep(REQUEST_DELAY)

        unique_ips = list(set(ips))
        logging.info(f"Found {len(unique_ips)} unique IPs/ranges from {rule_type}.")
        return unique_ips

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching Cloudflare rules: {e}")
        return []

def query_ipqs(ip_address, api_key):
    """Queries IPQS for IP information."""
    if not api_key:
        logging.error("IPQS API key not provided.")
        return None
    
    api_url = f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip_address}"
    try:
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"IPQS query failed for {ip_address}: {e}")
        return None

def query_internetdb(ip_address):
    """Queries InternetDB for IP information."""
    api_url = f"https://internetdb.shodan.io/{ip_address}"
    try:
        response = requests.get(api_url, timeout=INTERNETDB_TIMEOUT)
        if response.status_code == 404:
            return {"error": "Not found in InternetDB"}
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"InternetDB query failed for {ip_address}: {e}")
        return None

# --- I/O FUNCTIONS ---

def read_ips_from_file(filepath):
    """Reads a list of IPs from a text file."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.error(f"Input file not found: {filepath}")
        return []

def write_to_csv(data, filename):
    """Writes enriched data to a CSV file."""
    if not data:
        return
    
    fieldnames = list(data[0].keys())
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        logging.info(f"Data written to {filename}")
    except IOError as e:
        logging.error(f"Failed to write to CSV {filename}: {e}")

def write_to_json(data, filename):
    """Writes enriched data to a JSON file."""
    if not data:
        return

    try:
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=4)
        logging.info(f"Data written to {filename}")
    except IOError as e:
        logging.error(f"Failed to write to JSON {filename}: {e}")

# --- MAIN LOGIC ---

def process_ips(ip_list, ipqs_api_key):
    """Orchestrates the enrichment process for a list of IPs."""
    enriched_data = []
    for ip in ip_list:
        if '/' in ip:
            logging.warning(f"Skipping IP range: {ip}")
            continue

        logging.info(f"Enriching IP: {ip}")
        data = {'ip_address': ip, 'timestamp': datetime.now().isoformat()}
        
        # IPQS Enrichment
        ipqs_data = query_ipqs(ip, ipqs_api_key)
        if ipqs_data:
            data['ipqs'] = ipqs_data
        
        time.sleep(REQUEST_DELAY)

        # InternetDB Enrichment
        internetdb_data = query_internetdb(ip)
        if internetdb_data:
            data['internetdb'] = internetdb_data

        enriched_data.append(data)
        time.sleep(REQUEST_DELAY)
        
    return enriched_data

def main():
    """Main CLI entry point."""
    load_dotenv()
    parser = argparse.ArgumentParser(description="IP Enrichment CLI Tool for Security Engineers")

    # Input Sources
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cf-access-rules', action='store_true', help="Fetch IPs from Cloudflare Access Rules.")
    group.add_argument('--cf-zone-lockdown', action='store_true', help="Fetch IPs from Cloudflare Zone Lockdown.")
    group.add_argument('--file', type=str, help="Path to a file containing IPs to enrich.")
    group.add_argument('--ip', type=str, help="A single IP address to enrich.")

    # Cloudflare & API Keys
    parser.add_argument('--cf-zone-id', type=str, default=os.environ.get("CLOUDFLARE_ZONE_ID"))
    parser.add_argument('--cf-api-token', type=str, default=os.environ.get("CLOUDFLARE_API_TOKEN"))
    parser.add_argument('--ipqs-api-key', type=str, default=os.environ.get("IPQS_API_KEY"))

    # Output Options
    parser.add_argument('--output', type=str, default="enriched_output", help="Output file name (without extension).")
    parser.add_argument('--format', type=str, choices=['csv', 'json'], default='json', help="Output format.")

    args = parser.parse_args()

    # Determine IP list from source
    ip_list = []
    if args.cf_access_rules:
        ip_list = fetch_cloudflare_ips(args.cf_zone_id, args.cf_api_token, 'access_rules')
    elif args.cf_zone_lockdown:
        ip_list = fetch_cloudflare_ips(args.cf_zone_id, args.cf_api_token, 'zone_lockdown')
    elif args.file:
        ip_list = read_ips_from_file(args.file)
    elif args.ip:
        ip_list = [args.ip]

    if not ip_list:
        logging.warning("No IPs to process. Exiting.")
        return

    # Process IPs
    enriched_results = process_ips(ip_list, args.ipqs_api_key)

    # Write output
    if enriched_results:
        output_file = f"{args.output}.{args.format}"
        if args.format == 'csv':
            # Flatten data for CSV
            flat_data = []
            for item in enriched_results:
                row = {'ip_address': item['ip_address'], 'timestamp': item['timestamp']}
                if 'ipqs' in item:
                    for k, v in item['ipqs'].items():
                        row[f"ipqs_{k}"] = v
                if 'internetdb' in item:
                    for k, v in item['internetdb'].items():
                        row[f"internetdb_{k}"] = v
                flat_data.append(row)
            write_to_csv(flat_data, output_file)
        else:
            write_to_json(enriched_results, output_file)

if __name__ == "__main__":
    main()
