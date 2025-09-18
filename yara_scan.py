# yara_scan.py

import yara
import os
import logging

# 로거 설정
logger = logging.getLogger("yara_scanner")

# class to scan files for malware using a set of YARA rules
class MalwareScanner:
    # initialize the scanner by loading and compiling YARA rules from a list of file paths
    def __init__(self, rule_filepaths=None):
        """
        Initializes the scanner with a list of YARA rule file paths.
        :param rule_filepaths: A list of strings, where each string is a path to a .yar file.
        """
        if rule_filepaths is None:
            rule_filepaths = []
        self.rule_filepaths = rule_filepaths
        self.rules = self._load_rules()

    # compile YARA rules from the specified file paths
    def _load_rules(self):
        """
        Compiles YARA rules from the provided list of file paths.
        Uses the filename (without extension) as the namespace for each rule file.
        """
        if not self.rule_filepaths:
            logger.warning("No YARA rule files provided for compilation.")
            return None

        try:
            # Create a dictionary for the filepaths argument of yara.compile
            # {'namespace1': 'path/to/rule1.yar', 'namespace2': 'path/to/rule2.yar'}
            filepaths_dict = {}
            for path in self.rule_filepaths:
                if os.path.exists(path):
                    # Use the filename as the namespace to avoid conflicts
                    namespace = os.path.splitext(os.path.basename(path))[0]
                    filepaths_dict[namespace] = path

            if not filepaths_dict:
                logger.warning("All provided YARA rule paths do not exist.")
                return None

            logger.info(f"Loading YARA rules from: {list(filepaths_dict.values())}")
            return yara.compile(filepaths=filepaths_dict)

        except yara.Error as e:
            logger.error(f"YARA rule compilation failed: {e}")
            return None

    # scan a single file against the loaded YARA rules
    def scan_file(self, file_path):
        if not self.rules or not os.path.exists(file_path):
            return {"yara_matches": [], "yara_base_score": 0}

        try:
            # match the compiled rules against the file
            matches = self.rules.match(file_path)

            # process the raw matchs into a more structured format
            yara_matches = []
            for match in matches:
                strings_data = []
                for string_match in match.strings:
                    strings_data.append({
                        "offset": string_match.offset if hasattr(string_match, 'offset') else string_match.instances[0].offset,
                        "identifier": string_match.identifier,
                        "data": string_match.instances[0].matched_data.decode('utf-8', 'ignore')
                    })

                yara_matches.append({
                    "rule": match.rule,
                    "meta": match.meta,
                    "strings": strings_data
                })

            # calculate a base score from the severity of the matched rules
            yara_base_score = self._calculate_yara_base_score(yara_matches)

            return {
                "yara_matches": yara_matches,
                "yara_base_score": yara_base_score,
            }
        except Exception as e:
            logger.error(f"YARA scan failed for file '{os.path.basename(file_path)}': {e}")
            return {"yara_matches": [], "yara_base_score": 0}

    # calculate a base risk score based on the severity defined in YARA rules metadata
    def _calculate_yara_base_score(self, yara_matches):
        score = 0
        for match in yara_matches:
            # the 'severity' meta tag in the YARA rule determines its contribution to the score
            severity = match.get('meta', {}).get('severity', 'low')
            if severity == 'critical': return 100
            elif severity == 'high': score = max(score, 80)
            elif severity == 'medium': score = max(score, 50)
            elif severity == 'low': score = max(score, 20)
        return score
