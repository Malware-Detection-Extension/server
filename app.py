# app.py

import os
import re
import base64
import requests
import json
import sys
import copy
from logging_config import get_logger
from urllib.parse import urlparse
from analysis_engine import AnalysisEngine

# setup logger and default configurations
logger = get_logger(__name__)
DEFAULT_HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
download_dir = os.getcwd()

# load a JSON report template from the given file path
def load_report_template(json_path: str) -> dict:
    if not os.path.exists(json_path):
        logger.error(f"[-] CRITICAL: Template file not found at {json_path}")
        return None
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# merge analysis results into a copy of the report template
def populate_report_data(template: dict, analysis_data: dict) -> dict:
    report_data = copy.deepcopy(template)
    def update_recursive(target, source):
        for key, value in source.items():
            if isinstance(value, dict) and key in target and isinstance(target[key], dict):
                update_recursive(target[key], value)
            else:
                target[key] = value
    update_recursive(report_data, analysis_data)
    return report_data

# main function to archestrate the file download and analysis process
def main():
    logger.info("[*] Analysis worker started.")
    report_template = load_report_template("report_template.json")
    if not report_template:
        sys.exit(1)

    live_analysis_data = {}
    try:
        # get the target URL from an environment variable
        target_url = os.getenv("TARGET_URL")
        if not target_url: raise ValueError("TARGET_URL environment variable not set.")

        logger.info(f"[*] Analyzing URL")

        # handle both base64 data URIs and standard web URLs
        if target_url.startswith("data:"):
            match = re.match(r'data:.*?;base64,(.*)', target_url)
            file_data = base64.b64decode(match.group(1))
        else:
            res = requests.get(target_url, headers=DEFAULT_HEADERS, timeout=30)
            res.raise_for_status()
            file_data = res.content

        # save the file locally for analysis
        parsed = urlparse(target_url)
        file_name = os.path.basename(parsed.path) or "downloaded.bin"
        download_path = os.path.join(download_dir, file_name)
        with open(download_path, "wb") as f:
            f.write(file_data)

        logger.info(f"[+] File saved to: {download_path} ({len(file_data)} bytes)")

        # initialize and run the analysis engine
        engine = AnalysisEngine(download_path, file_data, file_name)
        live_analysis_data = engine.run_all_analyses()

        # set a final message based on the analysis result
        if not live_analysis_data.get("is_malicious"):
            live_analysis_data["message"] = "The file appears to be safe."
        else:
            live_analysis_data["message"] = "Malicious file detected based on YARA rules and heuristics."

    except Exception as e:
        # handle any exceptions during the process, marking the fiel as malicious
        logger.exception(f"[!] An unexpected error occurred: {e}")
        live_analysis_data["is_malicious"] = True
        live_analysis_data["message"] = f"Analysis failed with an error: {e}"
        live_analysis_data["risk_score"] = 100
    finally:
        # ensure a final report is always generated and printed to stdout
        final_report = populate_report_data(report_template, live_analysis_data)

        print("<YARA scan result>\n" + json.dumps(final_report, ensure_ascii=False))
        sys.stdout.flush()
        sys.exit(0)

if __name__ == "__main__":
    main()
