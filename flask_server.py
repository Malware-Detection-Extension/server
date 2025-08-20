# flask_server.py

import os
import json
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime
from controller import launch_worker_container
from logging_config import get_logger
from pdf_report import generate_malicious_pdf_report
from urllib.parse import urlparse
from url_analyzer import UrlAnalyzer


# initialize Flask app and enable Cross-Origin Resource Sharing (CORS)
app = Flask(__name__)
CORS(app)

# define and create necessary directories for storing reports and logs
REPORTS_DIR = "reports"
LOGS_DIR = "logs"
PDF_REPORTS_DIR = os.path.join(REPORTS_DIR, "malicious_pdf")
DOCKER_DEBUG_MODE = os.getenv("DOCKER_DEBUG_MODE", "False").lower() in ('true', '1', 't')

for d in [REPORTS_DIR, LOGS_DIR, PDF_REPORTS_DIR]:
    os.makedirs(d, exist_ok=True)

logger = get_logger(__name__)

# pre-load the URL analysis ML model on server startup for faster response times
logger.info("Initializing URL Analyzer (loading ML model)...")
url_analyzer = UrlAnalyzer()
logger.info("URL Analyzer initialized.")


# a simple health check endpoint to confirm the server is running
@app.route("/")
def serve_index():
    return "Malware Detection Server is running."

# the main endpoint that receives a URL, analyzes it and the file it points to
@app.route("/analyze", methods=["POST"])
def analyze_download():
    try:
        data = request.get_json()
        url = data.get("url")
        if not url:
            return jsonify({"error": "URL is required"}), 400

        logger.info(f"\n[*] Request analysis")
        
        # analyze the URL itself using the pre-loaded ML model
        url_analysis_result = url_analyzer.check_url(url)
        logger.info(f"[+] URL analysis result: {url_analysis_result}")

        # launch a Docker container to download and analyze the file
        file_analysis_result = launch_worker_container(url, DOCKER_DEBUG_MODE)
        
        # merge the URL and file analysis results into a single report
        result = file_analysis_result
        result["url_analysis"] = url_analysis_result

        # recalculate the final verdict
        url_is_malicious = url_analysis_result.get("is_malicious", False)
        file_is_malicious = file_analysis_result.get("is_malicious", False)
        result["is_malicious"] = url_is_malicious and file_is_malicious

        # combine human-readable messages from both analysis stages
        messages = []
        if url_is_malicious:
            messages.append("Malicious URL detected by ML model.")
        if file_is_malicious:
            file_message = file_analysis_result.get("message", "Malicious file detected.")
            messages.append(file_message)

        if not messages:
            result["message"] = "URL and file appear to be safe."
        else:
            result["message"] = " | ".join(messages)
        
        logger.info(f"[+] Analysis done. Malicious: {result.get('is_malicious', 'N/A')}")

        # save the full JSON analysis report to a file
        report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}.json"
        report_path = os.path.join(REPORTS_DIR, report_filename)
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        logger.info(f"[+] Saved analysis report to: {report_path}")


        if result.get("is_malicious"):
            try:
                hashes = result.get("hashes", {})
                yara_rules = [match.get("rule") for match in result.get("yara_matches", [])]
                analysis_details = result.get("analysis_details", {})

                detailed_log = {
                    "timestamp": datetime.now().isoformat(),
                    "source_url": url,
                    "message": result.get("message"),
                    "risk_score": result.get("risk_score"),
                    "file_hashes": {
                        "md5": hashes.get("md5"),
                        "sha256": hashes.get("sha256")
                    },
                    "key_indicators": {
                        "yara_rules": yara_rules,
                        "packers": result.get("packers"),
                        "suspicious_urls": analysis_details.get("potential_urls"),
                        "suspicious_ips": analysis_details.get("potential_ips")
                    },
                    "full_report_path": report_path
                }

                # append the summarized log to a dedicated file for malicious events
                with open(os.path.join(LOGS_DIR, "malicious.log"), "a", encoding='utf-8') as f:
                    f.write(json.dumps(detailed_log) + "\n")
                logger.info(f"[!] Detailed malicious log saved.")

                # generate PDF report of the malicious findings
                pdf_report_path = generate_malicious_pdf_report(
                    analysis_result=result,
                    url=url,
                    original_filename=os.path.basename(urlparse(url).path) or "downloaded_file",
                    pdf_reports_dir=PDF_REPORTS_DIR
                )
                if pdf_report_path:
                    logger.info(f"[+] PDF report generated: {pdf_report_path}")
                    result["pdf_report_path"] = pdf_report_path
                else:
                    logger.warning(f"[!] Failed to generate PDF report for a malicious file.")

            except Exception as e:
                logger.warning(f"[!] Failed to save log or generate PDF: {e}")

        return jsonify(result), 200

    except Exception as e:
        # global error handler for the endpoint to prevent server crashes
        logger.exception("[!] Unexpected error in analyze_download")
        return jsonify({"error": str(e), "is_malicious": True}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

