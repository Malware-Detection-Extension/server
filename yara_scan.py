# yara_scan.py

import yara
import os

# class to scan files for malware using a set of YARA rules
class MalwareScanner:
    # initialize the scanner by loading and compiling the YARA rules
    def __init__(self, rules_path="./rules/rules_combined.yar"):
        self.rules_path = rules_path
        self.rules = self._load_rules()

    # compile YARA rules from the specified file path
    def _load_rules(self):
        try:
            print(f"[*] Loading YARA rules from: {self.rules_path}")
            return yara.compile(filepath=self.rules_path)
        except Exception as e:
            print(f"[!] YARA rule load failed: {e}")
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
                        "offset": getattr(string_match, 'offset', 0),
                        "identifier": getattr(string_match, 'identifier', '$'),
                        "data": getattr(string_match, 'data', b'').decode('utf-8', 'ignore')
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
            print(f"[!] YARA scan failed for file '{os.path.basename(file_path)}': {e}")
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

