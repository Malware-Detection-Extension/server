# flask_server.py

import os
import json
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime
from controller import launch_worker_container
from logging_config import get_logger


app = Flask(__name__)
CORS(app)

REPORTS_DIR = "reports"
LOGS_DIR = "logs"
DOCKER_DEBUG_MODE = os.getenv("DOCKER_DEBUG_MODE", "False").lower() in ('true', '1', 't')

for d in [REPORTS_DIR, LOGS_DIR]:
    os.makedirs(d, exist_ok=True)

logger = get_logger(__name__)


@app.route("/")
def serve_index():
    logger.info("[*] Serving index.html")
    return send_from_directory('.', 'index.html')

@app.route("/analyze", methods=["POST"])
def analyze_download():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            logger.error("[!] Missing 'url' in request payload.")
            return jsonify({"error": "URL is required"}), 400
        
        logger.info(f"[*] Request analysis: {url}")

        result = launch_worker_container(url, DOCKER_DEBUG_MODE)
        
        try:
            logger.info(f"[+] Analysis done. Malicious: {result.get('is_malicious', 'N/A')}")
        except Exception as e:
            logger.info(f"[!] Analysis failed. result is NoneType.")
            return jsonify({"error": str(e), "is_malicious": True}), 500

        report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}.json"
        report_path = os.path.join(REPORTS_DIR, report_filename)

        with open(report_path, 'w') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        logger.info(f"[+] Saved analysis report to: {report_path}")
        
        # 악성일 경우 격리로그 작성
        if result.get("is_malicious"):
            try:
                analyzed_log = {
                    "timestamp": datetime.now().isoformat(),
                    "url": url,
                    "result": result
                }
                with open(os.path.join(LOGS_DIR, "malicious.log"), "a", encoding='utf-8') as f:
                    f.write(json.dumps(analyzed_log) + "\n")
                logger.info(f"[!] Malicious log is saved.")
            except Exception as e:
                logger.warning(f"[!] Failed to save analyzed log: {e}")

        return jsonify(result), 200

    except Exception as e:
        logger.exception("[!] Unexpected error in analyze_download")
        return jsonify({"error": str(e), "is_malicious": True}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

