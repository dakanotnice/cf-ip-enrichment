# Cloudflare IP Enrichment CLI

## Overview

This command-line tool is designed for security engineers to gather intelligence on IP addresses from various sources. It enriches IPs with data from IPQualityScore (IPQS) and Shodan's InternetDB, providing valuable context for threat analysis and security posture assessment.

The tool can fetch IP addresses from Cloudflare Access Rules, Cloudflare Zone Lockdown rules, a local file, or a single IP provided as an argument. The enriched data can be saved in either CSV or JSON format.

## Features

-   **Multiple IP Sources**: Fetch IPs from Cloudflare Access Rules, Cloudflare Zone Lockdown, a local file, or a single IP address.
-   **Rich Data Enrichment**: Gathers information from IPQS and InternetDB.
-   **Flexible Output**: Save enriched data in either CSV or JSON format.
-   **Filtered Queries**: Option to retrieve only Cloudflare Access Rules that have no notes.
-   **Containerized**: Run the application within a Docker container for consistent and isolated execution.
-   **Secure Credential Management**: Load API keys from a `.env` file or provide them as command-line arguments.

## Prerequisites

-   Python 3.6+
-   Docker (for containerized execution)
-   API keys for:
    -   Cloudflare (if using Cloudflare as a source)
    -   IPQualityScore

---

## Installation and Usage

There are two ways to run this application: directly on your machine using a Python environment, or within a Docker container.

### 1. Running with Python (Local)

#### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/cf-ip-enrichment.git
    cd cf-ip-enrichment
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up your environment variables:**
    Create a `.env` file in the project directory and add your API keys. The script will load these automatically.
    ```
    CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"
    CLOUDFLARE_ZONE_ID="your_cloudflare_zone_id"
    IPQS_API_KEY="your_ipqs_api_key"
    ```

#### Usage

The script is run from the command line with various options to specify the IP source and output format.

**Command-Line Arguments**

*   **IP Sources (choose one):**
    *   `--cf-access-rules`: Fetch IPs from Cloudflare Access Rules.
    *   `--cf-access-rules-no-notes`: Fetch IPs from Cloudflare Access Rules **only** where the 'notes' field is empty.
    *   `--cf-zone-lockdown`: Fetch IPs from Cloudflare Zone Lockdown rules.
    *   `--file <path>`: Path to a local file with one IP per line.
    *   `--ip <address>`: A single IP address to enrich.

*   **API Credentials (optional if `.env` is not used):**
    *   `--cf-zone-id <ID>`: Your Cloudflare Zone ID.
    *   `--cf-api-token <token>`: Your Cloudflare API token.
    *   `--ipqs-api-key <key>`: Your IPQS API key.

*   **Output Options:**
    *   `--output <filename>`: The base name for the output file (e.g., `enriched_output`). The extension is added automatically.
    *   `--format <type>`: The output format, `csv` or `json` (default: `json`).

**Examples**

-   **Get all Cloudflare Access Rules and save as CSV:**
    ```bash
    python ip_enricher_cli.py --cf-access-rules --output cf_access_ips --format csv
    ```

-   **Get only Access Rules with no notes:**
    ```bash
    python ip_enricher_cli.py --cf-access-rules-no-notes --output no_note_ips --format csv
    ```

-   **Get IPs from a local file and save as JSON:**
    ```bash
    python ip_enricher_cli.py --file /path/to/your/ips.txt --output from_file --format json
    ```

---

### 2. Running with Docker

Using Docker allows you to run the application in a self-contained environment without managing Python dependencies directly.

#### Setup

1.  **Build the Docker image:**
    From the project's root directory, run the build command:
    ```bash
    docker build -t ip-enricher .
    ```

#### Usage

When running the container, you need to provide the command-line arguments for the script and your API keys. It's also important to mount a volume to get the output files back to your host machine.

**Running the Container**

-   The `docker run` command should be structured to:
    -   Pass your API keys as environment variables (`-e`).
    -   Mount the current directory's `output` folder to the container's `/app/output` folder to retrieve results (`-v`).
    -   Specify the command-line arguments for the script.

-   **First, create an output directory on your host machine:**
    ```bash
    mkdir output
    ```

**Examples**

-   **Get all Cloudflare Access Rules and save to `./output/cf_rules.csv`:**
    ```bash
    docker run --rm \
      -e CLOUDFLARE_API_TOKEN="your_token" \
      -e CLOUDFLARE_ZONE_ID="your_zone_id" \
      -e IPQS_API_KEY="your_ipqs_key" \
      -v "$(pwd)/output":/app/output \
      ip-enricher \
      --cf-access-rules --output output/cf_rules --format csv
    ```

-   **Get IPs from a local file (e.g., `ips.txt`) and save to `./output/enriched.json`:**
    *Note: The input file must also be mounted into the container.*
    ```bash
    docker run --rm \
      -e IPQS_API_KEY="your_ipqs_key" \
      -v "$(pwd)/ips.txt":/app/ips.txt \
      -v "$(pwd)/output":/app/output \
      ip-enricher \
      --file ips.txt --output output/enriched --format json
    ```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.