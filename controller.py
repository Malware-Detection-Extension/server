# controller.py

import docker
import uuid
import os
import json
import logging
import time
from logging_config import get_logger


logger = get_logger(__name__)
logger.setLevel(logging.INFO)

# attempt to connect to the Docker daemon on startup
try:
    client = docker.from_env()
    client.ping()
    logger.info("[*] Successfully connected to Docker demon.")
except Exception as e:
    logger.error(f"[!] Docker demon connection failed: {e}. Make sure Docker is running.")
    client = None

# configuration constants for the worker container
WORKER_IMAGE = "malware_worker"
YARA_RULES_PATH = os.path.abspath("./rules/")
REPORTS_DIR = os.path.abspath("./reports/")

# find and forcibly remove a Docker container by name if it exists
def remove_container_if_exists(container_name: str) -> bool:
    if not client:
        return False

    try:
        container = client.containers.get(container_name)
        container.remove(force=True)
        logger.info(f"[*] Container '{container_name}' removed.")
        return True
    except docker.errors.NotFound:
        return False
    except Exception as e:
        logger.error(f"[!] Error removing container '{container_name}': {e}")
        return False

# launch a Docker container to analyze a URL, wait for it to finish, and return the JSON result from the container's logs
def launch_worker_container(url: str, debug_mode: bool) -> dict:
    if not client:
        return {"error": "Docker daemon is not available.", "is_malicious": True, "message": "Docker not running."}
    
    container_id = uuid.uuid4().hex[:8]
    container_name = f"malware-worker-{container_id}"
    logger.info(f"[*] Starting new worker container '{container_name}' for URL analysis.")

    temp_file_path_in_container = f"/app/temp/downloaded_file_{container_id}"
    
    # set environment variables for the worker container
    env = {
        "TARGET_URL": url,
        "WORKER_ID": container_id,
        "DOWNLOAD_PATH": temp_file_path_in_container
    }

    # host-container volume binding (YARA rules, report)
    volumes = {
        YARA_RULES_PATH: {'bind': '/app/rules', 'mode': 'ro'},
        REPORTS_DIR: {'bind': '/app/reports', 'mode': 'rw'}
    }

    container = None
    try:
        # run the container in detached mode
        container = client.containers.run(
            image=WORKER_IMAGE,
            name=container_name,
            environment=env,
            volumes=volumes,
            detach=True,
            remove=False
        )
        logger.info(f"[*] Worker container '{container_name}' started. Waiting for completion...")

        # wait for the container to exit, with a timeout
        try:
            result_code = container.wait(timeout=300)["StatusCode"]
            logger.info(f"[*] Worker container '{container_name}' finished. Exit code: {result_code}")
        except Exception as e:
            logger.warning(f"[*] Container wait timed out or failed: {e}")
            if container:
                container.kill()
            raise


        # retrieve all logs from the container after it has finished
        logs = container.logs().decode("utf-8")
        logger.info(f"--- Logs from Worker Container '{container_name}' ---")
        logger.info(logs)
        logger.info(f"--- End Logs ---")

        # clean up containers
        if not debug_mode:
            remove_container_if_exists(container_name)
        else:
            logger.info(f"[*] Debug mode is enabled. Container '{container_name}' is kept for debugging.")

        # parse the JSON result from the worker's stdout
        try:
            raw_result_json = logs.split("<RESULT>\n")[-1].strip()
            result = json.loads(raw_result_json)
            logger.info(f"[+] Worker result parsed successfully: {result.get('is_malicious', 'N/A')}")
        except (json.JSONDecodeError, IndexError) as parse_error:
            logger.error(f"[!] Failed to parse JSON from worker logs: {parse_error}. Raw log:\n{logs}")
            result = {"error": "Invalid or missing JSON result from worker", "log": logs, "is_malicious": True, "message": "Failed to parse worker output."}
        
        return result

    except docker.errors.ImageNotFound:
        logger.critical(f"[!] Docker image '{WORKER_IMAGE}' not found. Please build it first.")
        if container and not debug_mode:
            remove_container_if_exists(container_name)
        return {"error": f"Docker image '{WORKER_IMAGE}' not found. Please build it.", "is_malicious": True}
    except Exception as e:
        logger.exception(f"[!] Unexpected error during worker container execution.")
        if container and not debug_mode:
            remove_container_if_exists(container_name)
        return {"error": str(e), "is_malicious": True, "message": "Unexpected error during worker execution."}

