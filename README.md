# cf-ip-enrichment
 Cloudflare IP Access Rules- Security Data Enrichment


## Overview and Purpose

The script looks to enrich each IP from a CF Zone's *IP Access Rules* with additional relevant security information in order to help you assess the risk of each "whitelisted" IP in your Zone.
Can be very useful when you inherit a Cloudflare setup which has not been properly documented or it has legacy rules present (due to lack of FW reviews).

The script has been used successfully multiple times in a real production environment.

## Prerequisites

- A Cloudflare Zone with IP Access Rules
- Cloudflare API Key with proper Read permissions for the Zone (Firewall Read/ WAF Read)
- IPQualityScore (IPQS) account with API key
- Python 3 instaled on your machine / environment
- Environment variables provided in a .env file in the script directory

### Environment Variables

    *CLOUDFLARE_API_TOKEN*= "Your Cloudflare API Token (not Key)"
    *CLOUDFLARE_ZONE_ID*= "Your Cloudflare Zone ID" - # Currently only supports 1 ID per script run
    *IPQS_API_KEY*= "Your IPQS API Key"

## How to Use

- 1. Download or clone git repo
- 2. Provide your env variables in a .env file (see Prerequisites)
- 3. Load / Install dependencies in your environment (or virtualenv)
- 4. Run Script
- 5. Review results csv

 *Optional*: Integrate in CI/CD pipeline for periodic Firewall reviews.

##  License

This project is under the MIT License- see LICENSE for details.