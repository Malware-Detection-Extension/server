# analysis_engine.py

import os
import re
import hashlib
import math
import zipfile
import tempfile
import shutil
from collections import Counter
from file_type import FileTypeAnalyzer
from yara_scan import MalwareScanner

try:
    import pefile
except ImportError:
    pefile = None

# Constants and Configuration

EXTENSION_RISKS = {
    ".exe": "high", ".dll": "high", ".sys": "high", ".scr": "high", ".pif": "high", ".com": "high",
    ".bat": "medium", ".cmd": "medium", ".vbs": "medium", ".js": "medium", ".ps1": "medium",
    ".jar": "medium", ".docm": "medium", ".xlsm": "medium", ".pptm": "medium",
}

TYPICAL_SIZES = {
    "pe executable": (10 * 1024, 10 * 1024 * 1024),
    "pdf document": (5 * 1024, 20 * 1024 * 1024),
}

IP_PATTERN = rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
URL_PATTERN = rb'https?://[^\s/$.?#].[^\s]*'

SUSPICIOUS_APIS = [
    b'createremotethread', b'virtualallocex', b'writeprocessmemory', b'shellexecute',
    b'getprocaddress', b'loadlibrary', b'isdebuggerpresent'
]

URL_FILTER_LIST = [
    "schemas.microsoft.com", "www.w3.org", "ns.adobe.com", "purl.org",
]

# Dynamic YARA Rule Mapping
BASE_RULES_PATH = os.path.join(os.path.dirname(__file__), 'rules')
RULE_CATEGORY_MAP = {
    'PE Executable': 'executables',
    'PDF Document': 'documents',
    'Microsoft Word': 'documents',
    'Microsoft Excel': 'spreadsheets',
    'Microsoft PowerPoint': 'documents',
    'Rich Text Format': 'documents',
    'Zip archive': 'archives',
    'RAR archive': 'archives',
    'HTML document': 'emails',
    'JPEG image': 'images',
    'PNG image': 'images',
    'MP3 audio': 'media',
}

# class to perform static analysis on a given file
class AnalysisEngine:
    # initialize
    def __init__(self, file_path, file_data, original_filename):
        self.file_path = file_path
        self.file_data = file_data
        self.original_filename = original_filename
        self.results = {}

    # run all analysis steps and return a result dictionary
    def run_all_analyses(self):
        self._analyze_basic_info()
        self._analyze_hashes()
        self.results['entropy'] = self._calculate_entropy()
        self._analyze_risk_factors()

        # branch analysis logic depending on whether the file is an archive
        mime_type = self.results.get("file_info", {}).get("mime_type", "")
        if "zip" in mime_type or self.original_filename.lower().endswith(".zip"):
            self._analyze_archive()
        else:
            self._analyze_single_file()

        return self.results

    # run the detailed analysis process for a single, non-archive file
    def _analyze_single_file(self):
        self._extract_indicators()
        file_type_str = self.results.get("file_info", {}).get("file_type", "").lower()
        if 'pe executable' in file_type_str:
            self._analyze_pe_details()
        self._run_yara_scan() # This will now run dynamically
        self._calculate_final_score_and_verdict()

    # extract files from an archive and recursively analyze each one
    def _analyze_archive(self):
        self.results["archived_files"] = []
        max_risk_score = 0
        malicious_files_count = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)

                for root, _, files in os.walk(temp_dir):
                    for filename in files:
                        archived_file_path = os.path.join(root, filename)
                        try:
                            with open(archived_file_path, 'rb') as f:
                                archived_file_data = f.read()

                            sub_engine = AnalysisEngine(archived_file_path, archived_file_data, filename)
                            sub_report = sub_engine.run_all_analyses()
                            self.results["archived_files"].append(sub_report)

                            if sub_report.get("is_malicious"):
                                malicious_files_count += 1
                            max_risk_score = max(max_risk_score, sub_report.get("risk_score", 0))
                        except Exception as e:
                            print(f"Error analyzing archived file {filename}: {e}")
            except zipfile.BadZipFile:
                self.results["message"] = "Error: Corrupted or invalid ZIP file."
                self.results["is_malicious"] = True
                self.results["risk_score"] = 70
                return

        # Consolidate results for the archive itself
        base_score = self.results.get("risk_score", 0)
        self.results["risk_score"] = max(max_risk_score, base_score)
        self.results["is_malicious"] = self.results["risk_score"] >= 60
        if malicious_files_count > 0:
            self.results["message"] = f"Archive contains {malicious_files_count} malicious file(s)."
        else:
            self.results["message"] = "Archive appears to be safe."

    # analyze basic file information like size and MIME type
    def _analyze_basic_info(self):
        analyzer = FileTypeAnalyzer()
        info = analyzer.analyze_file(self.file_path)
        self.results["file_info"] = { "size": info.get("size", 0), "mime_type": info.get("mime_type", "unknown"), "file_type": info.get("signature_type", "unknown") }

    # calculate MD5, SHA1, and SHA256 hashes of the file
    def _analyze_hashes(self):
        self.results["hashes"] = { "md5": hashlib.md5(self.file_data).hexdigest(), "sha1": hashlib.sha1(self.file_data).hexdigest(), "sha256": hashlib.sha256(self.file_data).hexdigest() }

    # calculate entropy to detect packed or encrypted data
    def _calculate_entropy(self):
        if not self.file_data: return 0.0
        entropy = 0; data_len = len(self.file_data)
        byte_counts = Counter(self.file_data)
        for count in byte_counts.values():
            p_x = count / data_len
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    # assess risk based on file extension and size anomalies
    def _analyze_risk_factors(self):
        ext = os.path.splitext(self.original_filename)[1].lower()
        self.results["extension_risk"] = { "risk": EXTENSION_RISKS.get(ext, "low"), "extension": ext }
        file_type = self.results.get("file_info", {}).get("file_type", "").lower()
        file_size = self.results.get("file_info", {}).get("size", 0)
        for type_key, (min_size, max_size) in TYPICAL_SIZES.items():
            if type_key in file_type:
                if not (min_size <= file_size <= max_size):
                    anomaly = "Large File Size" if file_size > max_size else "Small File Size"
                    self.results["size_anomaly"] = { "anomaly": anomaly, "description": f"Size ({file_size/1024:.1f}KB) is outside typical range." }
                break

    # extract potential IOCs like URL, IP, and suspicious API calls
    def _extract_indicators(self):
        raw_urls = [url.decode('utf-8', 'ignore') for url in re.findall(URL_PATTERN, self.file_data)]
        filtered_urls = [url for url in raw_urls if not any(filtered_domain in url for filtered_domain in URL_FILTER_LIST)]
        details = {
            "potential_urls": filtered_urls,
            "potential_ips": [ip.decode() for ip in re.findall(IP_PATTERN, self.file_data)],
        }
        found_apis = Counter()
        for api in SUSPICIOUS_APIS:
            if api.lower() in self.file_data.lower(): found_apis[api.decode()] += 1
        if found_apis: details["suspicious_api_calls"] = list(found_apis.keys())
        self.results["analysis_details"] = details

    # analyze PE file structure, check for packers, and extract header info
    def _analyze_pe_details(self):
        if not pefile: self.results["pe_info"] = {"error": "pefile library not installed."}; return
        try:
            pe = pefile.PE(self.file_path, fast_load=True)
            self.results["pe_info"] = { "type": "Executable" if pe.is_exe() else "DLL", "architecture": "x64" if pe.OPTIONAL_HEADER.Magic == 0x20b else "x86", "machine": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, 'Unknown'), "sections": len(pe.sections), "timestamp": pe.FILE_HEADER.TimeDateStamp }
            packers, obfuscation_log = [], []
            section_names = [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections]
            if "UPX0" in section_names: packers.append("UPX")
            if ".aspack" in section_names: packers.append("ASPack")
            self.results["packers"] = list(set(packers))
            if self.results["entropy"] > 7.5: self.results["obfuscation_detected"] = True; obfuscation_log.append(f"High entropy ({self.results['entropy']:.2f}) suggests packing/encryption.")
            if self.results["packers"]: self.results["obfuscation_detected"] = True; obfuscation_log.append(f"Known packer(s) detected: {', '.join(self.results['packers'])}")
            self.results["deobfuscation_result"] = {"log": obfuscation_log}
        except pefile.PEFormatError:
            self.results["pe_info"] = {"error": "Not a valid PE file."}

    # scan the file with YARA rules to detect known malware patterns
    def _run_yara_scan(self):
        signature_type = self.results.get("file_info", {}).get("file_type", "Unknown")

        # Find the appropriate rule category based on the file's signature
        rule_category = None
        for key, category in RULE_CATEGORY_MAP.items():
            if key in signature_type:
                rule_category = category
                break

        rule_files_to_apply = []
        if rule_category:
            target_rule_dir = os.path.join(BASE_RULES_PATH, rule_category)
            if os.path.isdir(target_rule_dir):
                rule_files_to_apply = [
                    os.path.join(target_rule_dir, f)
                    for f in os.listdir(target_rule_dir) if f.endswith(('.yar', '.yara'))
                ]

        if not rule_files_to_apply:
            print(f"No specific YARA rules found for type '{signature_type}'. Skipping YARA scan.")
            self.results.update({"yara_matches": [], "yara_base_score": 0})
            return

        # Initialize the scanner with the selected rule files and scan
        print(f"Applying YARA rules from '{rule_category}' category for file type '{signature_type}'.")
        scanner = MalwareScanner(rule_filepaths=rule_files_to_apply)
        scan_result = scanner.scan_file(self.file_path)
        self.results.update(scan_result)

    # calculate a final risk score and make a malicious/safe verdict
    def _calculate_final_score_and_verdict(self):
        final_score = self.results.get("yara_base_score", 0)

        # Add points to the score based on various risk factors
        if final_score < 100:
            if self.results.get("extension_risk", {}).get("risk") == "high":
                final_score = min(100, final_score + 25)
            if self.results.get("extension_risk", {}).get("risk") == "medium":
                final_score = min(100, final_score + 10)
            if self.results.get("obfuscation_detected"):
                final_score = min(100, final_score + 20) # Increased penalty for obfuscation
            if self.results.get("entropy", 0) > 7.9:
                final_score = min(100, final_score + 10)

        self.results["risk_score"] = int(final_score)
        self.results["is_malicious"] = self.results["risk_score"] >= 60

        if self.results["is_malicious"]:
            self.results["message"] = "Malicious file detected based on multiple indicators."
        else:
            self.results["message"] = "The file appears to be safe."
