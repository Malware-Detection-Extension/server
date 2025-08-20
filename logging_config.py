# logging_config.py

import logging
import sys

def get_logger(name):
    logger = logging.getLogger(name)
    if not logger.hasHandlers():
        formatter = logging.Formatter(
            '%(asctime)s - %(filename)s - %(levelname)s - %(message)s'
        )
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)

        logger.addHandler(stream_handler)
        logger.setLevel(logging.INFO)

    return logger

