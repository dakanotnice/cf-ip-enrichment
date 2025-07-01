import csv
import json
import requests
import os
from datetime import datetime
import logging
from dotenv import load_dotenv
import time # Added for potential rate limiting

# Load env variables
load_dotenv()
CLOUDFLARE_API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN")
CLOUDFLARE_ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID")
IPQS_API_KEY = os.environ.get("IPQS_API_KEY")
OUTPUT_CSV_FILENAME = "cloudflare_ip_access_rules_enriched.csv"
LOG_FILE = "cloudflare_ip_enrich.log"
INTERNETDB_TIMEOUT = 10 # Timeout for InternetDB requests in seconds
REQUEST_DELAY = 0.2 # Small delay between API calls to not trigger rate limit or ddos protection

#  Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def fetch_cloudflare_allow_ips():
    """Fetches all IPs/IP ranges from Cloudflare IP Access Rules (action 'allow') using direct API calls."""
    # Check if Cloudflare credentials are provided
    if not CLOUDFLARE_API_TOKEN:
        logging.critical("CLOUDFLARE_API_TOKEN not configured in environment variables.")
        return []
    if not CLOUDFLARE_ZONE_ID:
         logging.critical("CLOUDFLARE_ZONE_ID not configured in environment variables.")
         return []

    # --- Direct API Call Setup ---
    api_endpoint = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/firewall/access_rules/rules"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }
    # -----------------------------

    ips = []
    page_number = 1
    per_page = 150 # Cloudflare API default is 25, max is probably 1000

    logging.info(f"Fetching 'Allow' IP rules from Cloudflare Zone ID: {CLOUDFLARE_ZONE_ID}...")

    try:
        while True:
            # Parameters for the API request
            params = {
                'page': page_number,
                'per_page': per_page,
                'mode': 'whitelist',      # Filter for 'allow' rules- this can be changed for whatever you need
                'match': 'all',       # How filters should match (all/any)
            }
            logging.debug(f"Requesting page {page_number} with params: {params}")

            try:
                # Make the GET request to the Cloudflare API
                response = requests.get(api_endpoint, headers=headers, params=params, timeout=20) # Added timeout
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

                # Parse the JSON response
                results = response.json()
                logging.debug(f"Raw API response (Page {page_number}): {results}") # Log raw response for debugging

                # Check API success and presence of 'result' list
                if results.get('success') and 'result' in results:
                    rules = results['result']
                    logging.debug(f"Received {len(rules)} rules on page {page_number}.")
                else:
                    # Log API failure or unexpected structure
                    error_messages = ", ".join([e.get('message', '') for e in results.get('errors', [])])
                    logging.error(f"Cloudflare API indicated failure or unexpected structure (Page {page_number}). Success: {results.get('success')}. Errors: {error_messages}. Full Response: {results}")
                    return [] # Stop if API reports failure

            except requests.exceptions.HTTPError as e:
                logging.error(f"HTTP error fetching Cloudflare rules (Page {page_number}): {e}. Status Code: {response.status_code}. Response Text: {response.text}", exc_info=True)
                return [] # Stop on HTTP error
            except requests.exceptions.RequestException as e:
                logging.error(f"Request error fetching Cloudflare rules (Page {page_number}): {e}", exc_info=True)
                return [] # Stop on other request errors (timeout, connection error)
            except json.JSONDecodeError as e:
                 logging.error(f"JSON decode error processing Cloudflare response (Page {page_number}): {e}. Response Text: {response.text}", exc_info=True)
                 return [] # Stop if response is not valid JSON

            # If no rules are returned, we've likely reached the end
            if not rules:
                logging.debug("No more rules found on this page.")
                result_info = results.get('result_info', {})
                total_pages = result_info.get('total_pages')
                if total_pages is not None and page_number >= total_pages:
                     logging.debug("Reached total pages indicated by API.")
                elif len(rules) == 0 and page_number > 1:
                     logging.debug("Assuming end of results as current page is empty.")
                elif len(rules) == 0 and page_number == 1:
                     logging.info("No 'allow' rules found in the zone.")
                break # Exit loop if no rules or assumed end

            # Extract IP or IP range from each 'allow' rule
            for rule in rules:
                if rule.get('mode') == 'whitelist':
                    config = rule.get('configuration', {})
                    config_target = config.get('target')
                    config_value = config.get('value')

                    if config_target in ['ip', 'ip_range'] and config_value:
                        ips.append(config_value)
                        logging.debug(f"Found allowed IP/range: {config_value} (Rule ID: {rule.get('id')})")
                    else:
                         logging.debug(f"Skipping rule ID {rule.get('id')} with non-IP/IP_range target ('{config_target}') or missing value.")
                else:
                     logging.warning(f"Received rule ID {rule.get('id')} with unexpected mode '{rule.get('mode')}' despite filter.")

            # Check pagination info
            result_info = results.get('result_info', {})
            count_on_page = result_info.get('count', len(rules))
            total_pages = result_info.get('total_pages')

            if total_pages is not None and page_number >= total_pages:
                 logging.debug("Reached the last page according to API result_info.")
                 break
            elif count_on_page < per_page:
                 logging.debug("Received fewer results than per_page, assuming last page.")
                 break

            page_number += 1
            time.sleep(REQUEST_DELAY) # Brief pause between pages

        unique_ips = list(set(ips))
        logging.info(f"Found {len(unique_ips)} unique 'Allow' IPs/ranges in Cloudflare Zone {CLOUDFLARE_ZONE_ID} via direct API.")
        return unique_ips

    except Exception as e:
        logging.critical(f"Fatal error in fetch_cloudflare_allow_ips (Direct API): {e}", exc_info=True)
        return []

def query_ipqs(ip_address):
    """Queries IPQS API for information about a given IP address."""
    if not IPQS_API_KEY:
        logging.error(f"IPQS API Key not configured. Cannot query IP: {ip_address}")
        return None

    api_url = f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip_address}"
    params = {} # Add any desired IPQS parameters here (e.g., {'strictness': '1'})
    try:
        logging.info(f"Querying IPQS for: {ip_address}")
        response = requests.get(api_url, params=params, timeout=15)
        response.raise_for_status()
        ipqs_data = response.json()
        logging.debug(f"IPQS response for {ip_address}: {ipqs_data}")
        return ipqs_data
    except requests.exceptions.HTTPError as e:
        # Handle 429 Too Many Requests specifically if needed- if your list is very big. Ive tested this only with <1000 IPs. Make sure you don't hit your API usage limits.
        if response.status_code == 429:
             logging.warning(f"IPQS rate limit hit for {ip_address}. Consider adding delays.")
        logging.error(f"HTTP error {response.status_code} querying IPQS for {ip_address}: {e}. Response: {response.text}")
        return None
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error querying IPQS for {ip_address}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        logging.error(f"Timeout error querying IPQS for {ip_address} after 15 seconds: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"General request error querying IPQS for {ip_address}: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error for IPQS IP {ip_address}. Response Text: {response.text}. Error: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error querying IPQS for {ip_address}: {e}", exc_info=True)
        return None

# --- InternetDB Function- Shodan historical data with more free access ---
def query_internetdb(ip_address):
    """Queries Shodan InternetDB API for information about a given IP address."""
    api_url = f"https://internetdb.shodan.io/{ip_address}"
    try:
        logging.info(f"Querying InternetDB for: {ip_address}")
        response = requests.get(api_url, timeout=INTERNETDB_TIMEOUT)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        # Check for empty response before trying to decode JSON
        if not response.content:
             logging.warning(f"InternetDB returned an empty response for {ip_address}. Status: {response.status_code}")
             return None # Or return an empty dict: {}

        internetdb_data = response.json()
        logging.debug(f"InternetDB response for {ip_address}: {internetdb_data}")
        return internetdb_data
    except requests.exceptions.HTTPError as e:
        # InternetDB often returns 404 for IPs not found, treat this as non-error
        if response.status_code == 404:
            logging.info(f"IP {ip_address} not found in InternetDB (404).")
            return {"error": "Not found in InternetDB"} # Return specific marker
        else:
            logging.error(f"HTTP error {response.status_code} querying InternetDB for {ip_address}: {e}. Response: {response.text}")
            return None
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error querying InternetDB for {ip_address}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        logging.error(f"Timeout error querying InternetDB for {ip_address} after {INTERNETDB_TIMEOUT} seconds: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"General request error querying InternetDB for {ip_address}: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error for InternetDB IP {ip_address}. Response Text: {response.text}. Error: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error querying InternetDB for {ip_address}: {e}", exc_info=True)
        return None
# --- End InternetDB Function ---

def write_to_csv(data, filename):
    """Writes the enriched IP data to a CSV file."""
    # --- FIELDNAMES ---
    fieldnames = [
        'ip_address', 'query_timestamp',
        # IPQS Fields
        'ipqs_success', 'ipqs_message', 'ipqs_fraud_score',
        'ipqs_country_code', 'ipqs_region', 'ipqs_city', 'ipqs_isp', 'ipqs_org',
        'ipqs_asn', 'ipqs_mobile', 'ipqs_host', 'ipqs_proxy', 'ipqs_vpn', 'ipqs_tor',
        'ipqs_is_crawler', 'ipqs_connection_type', 'ipqs_latitude', 'ipqs_longitude',
        'ipqs_timezone',
        # InternetDB Fields
        'internetdb_error', # To capture 'Not found' or other errors
        'internetdb_cpes', 'internetdb_hostnames', 'internetdb_ip',
        'internetdb_ports', 'internetdb_tags', 'internetdb_vulns'
        # Add more InternetDB fields as needed based on API response
    ]
    # --- END FIELDNAMES ---

    if not data:
        logging.warning("No data provided to write_to_csv function.")
        return

    try:
        logging.info(f"Writing {len(data)} enriched records to CSV file: {filename}")
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            # Use extrasaction='ignore' to avoid errors if a field is missing in a row
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(data)
        logging.info(f"Enriched data successfully written to {filename}")
    except IOError as e:
        logging.error(f"Error writing to CSV file {filename}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error writing CSV {filename}: {e}", exc_info=True)

def main():
    """Main function to orchestrate the script's execution."""
    start_time = datetime.now()
    logging.info("Starting Cloudflare IP enrichment script (IPQS & InternetDB).")

    required_vars = ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID", "IPQS_API_KEY"]
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    if missing_vars:
        logging.critical(f"Error: Missing required environment variables: {', '.join(missing_vars)}. Please configure them.")
        return

    cloudflare_ips = fetch_cloudflare_allow_ips()

    if not cloudflare_ips:
        logging.warning("Exiting script because no 'Allow' IPs were retrieved from Cloudflare.")
        return

    # Filter out IP ranges *after* retrieval
    single_ips = [ip for ip in cloudflare_ips if '/' not in ip]
    ranges = [ip for ip in cloudflare_ips if '/' in ip]
    logging.info(f"Retrieved {len(cloudflare_ips)} allow rules: {len(single_ips)} single IPs and {len(ranges)} IP ranges.")
    if ranges:
        # Maybe log ranges to a separate file?
        logging.info(f"Skipped {len(ranges)} IP ranges for enrichment: {', '.join(ranges) if len(ranges) < 10 else str(len(ranges)) + ' ranges'}") # Avoid overly long logs

    if not single_ips:
        logging.warning("No single IPs found to enrich after filtering out ranges. Exiting.")
        return

    enriched_data = []
    total_ips = len(single_ips)
    ipqs_success_count = 0
    ipqs_failure_count = 0
    internetdb_success_count = 0
    internetdb_failure_count = 0
    internetdb_notfound_count = 0

    logging.info(f"Starting enrichment for {total_ips} unique single IPs...")

    for index, ip in enumerate(single_ips):
        if (index + 1) % 25 == 0 or index == total_ips - 1: # Log progress more often
            logging.info(f"Processing IP {index + 1}/{total_ips}: {ip}")

        query_ts = datetime.now().isoformat()
        row_data = {'ip_address': ip, 'query_timestamp': query_ts}

        # --- Query IPQS ---
        ipqs_result = query_ipqs(ip)
        if ipqs_result and ipqs_result.get('success'):
            ipqs_success_count += 1
            row_data.update({
                'ipqs_success': True, 'ipqs_message': ipqs_result.get('message'),
                'ipqs_fraud_score': ipqs_result.get('fraud_score'), 'ipqs_country_code': ipqs_result.get('country_code'),
                'ipqs_region': ipqs_result.get('region'), 'ipqs_city': ipqs_result.get('city'),
                'ipqs_isp': ipqs_result.get('ISP'), 'ipqs_org': ipqs_result.get('organization'),
                'ipqs_asn': ipqs_result.get('ASN'), 'ipqs_mobile': ipqs_result.get('mobile'),
                'ipqs_host': ipqs_result.get('host'), 'ipqs_proxy': ipqs_result.get('proxy'),
                'ipqs_vpn': ipqs_result.get('vpn'), 'ipqs_tor': ipqs_result.get('tor'),
                'ipqs_is_crawler': ipqs_result.get('is_crawler'), 'ipqs_connection_type': ipqs_result.get('connection_type'),
                'ipqs_latitude': ipqs_result.get('latitude'), 'ipqs_longitude': ipqs_result.get('longitude'),
                'ipqs_timezone': ipqs_result.get('timezone'),
            })
        elif ipqs_result and not ipqs_result.get('success'):
            ipqs_failure_count += 1
            logging.warning(f"IPQS query for {ip} failed: {ipqs_result.get('message')}")
            row_data.update({'ipqs_success': False, 'ipqs_message': ipqs_result.get('message', 'IPQS query unsuccessful')})
        else: # Handles None return from query_ipqs
            ipqs_failure_count += 1
            logging.error(f"Failed to retrieve any response from IPQS for {ip}.")
            row_data.update({'ipqs_success': False, 'ipqs_message': 'Failed to retrieve data from IPQS (request error)'})

        time.sleep(REQUEST_DELAY) # Pause between IPQS and InternetDB

        # --- Query InternetDB ---
        internetdb_result = query_internetdb(ip)
        if internetdb_result and "error" not in internetdb_result:
            internetdb_success_count += 1
            # Convert lists to strings for easier CSV handling (e.g., comma-separated)
            hostnames_str = ', '.join(internetdb_result.get('hostnames', []))
            ports_str = ', '.join(map(str, internetdb_result.get('ports', []))) # Ensure ports are strings
            tags_str = ', '.join(internetdb_result.get('tags', []))
            cpes_str = ', '.join(internetdb_result.get('cpes', []))
            vulns_str = ', '.join(internetdb_result.get('vulns', []))

            row_data.update({
                'internetdb_error': None,
                'internetdb_cpes': cpes_str,
                'internetdb_hostnames': hostnames_str,
                'internetdb_ip': internetdb_result.get('ip'), # Should match input IP
                'internetdb_ports': ports_str,
                'internetdb_tags': tags_str,
                'internetdb_vulns': vulns_str
            })
        elif internetdb_result and internetdb_result.get("error") == "Not found in InternetDB":
             internetdb_notfound_count += 1
             logging.info(f"IP {ip} marked as not found in InternetDB.")
             row_data.update({'internetdb_error': 'Not found in InternetDB'})
        else: # Handles None return from query_internetdb or other errors
            internetdb_failure_count += 1
            logging.error(f"Failed to retrieve valid data from InternetDB for {ip}.")
            row_data.update({'internetdb_error': 'Failed to retrieve data'})

        enriched_data.append(row_data)
        time.sleep(REQUEST_DELAY) # Pause between IPs

    logging.info(f"IPQS enrichment completed. Successful: {ipqs_success_count}, Failed: {ipqs_failure_count}")
    logging.info(f"InternetDB enrichment completed. Successful: {internetdb_success_count}, Not Found: {internetdb_notfound_count}, Failed: {internetdb_failure_count}")

    if enriched_data:
        # Define fieldnames again here or pass from main to ensure consistency
        # This ensures write_to_csv uses the most up-to-date field list
        csv_fieldnames = [
            'ip_address', 'query_timestamp', 'ipqs_success', 'ipqs_message', 'ipqs_fraud_score',
            'ipqs_country_code', 'ipqs_region', 'ipqs_city', 'ipqs_isp', 'ipqs_org',
            'ipqs_asn', 'ipqs_mobile', 'ipqs_host', 'ipqs_proxy', 'ipqs_vpn', 'ipqs_tor',
            'ipqs_is_crawler', 'ipqs_connection_type', 'ipqs_latitude', 'ipqs_longitude',
            'ipqs_timezone', 'internetdb_error', 'internetdb_cpes', 'internetdb_hostnames',
            'internetdb_ip', 'internetdb_ports', 'internetdb_tags', 'internetdb_vulns'
        ]
        write_to_csv(enriched_data, OUTPUT_CSV_FILENAME) # Pass fieldnames if defined in main
    else:
        logging.info("No data was enriched.")

    end_time = datetime.now()
    logging.info(f"Script finished execution. Total time: {end_time - start_time}")

if __name__ == "__main__":
    main()