# file_type.py

import magic
import logging
import os
import math
import struct
import hashlib

logger = logging.getLogger("file_type_analyzer")
logger.setLevel(logging.INFO)

class FileTypeAnalyzer:
    def __init__(self):
        try:
            # MIME 타입 감지용 인스턴스
            self.magic_mime_analyzer = magic.Magic(mime=True)
            # 상세 타입 감지용 인스턴스
            self.magic_full_analyzer = magic.Magic()
        except Exception as e:
            logger.error(f"Error initializing python-magic: {e}")
            self.magic_mime_analyzer = None
            self.magic_full_analyzer = None

        self.magic_signatures = {
            b'MZ': 'PE Executable',
            b'\x7fELF': 'ELF Executable',
            b'\xfe\xed\xfa\xce': 'Mach-O Executable (32-bit)',
            b'\xfe\xed\xfa\xcf': 'Mach-O Executable (64-bit)',
            b'PK\x03\x04': 'ZIP Archive',
            b'Rar!\x1a\x07\x00': 'RAR Archive',
            b'7z\xbc\xaf\x27\x1c': '7-Zip Archive',
            b'#!/bin/bash': 'Bash Script',
            b'#!/bin/sh': 'Shell Script',
            b'@echo off': 'Batch Script',
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'Microsoft Office Document',
            b'%PDF': 'PDF Document',
            b'\xff\xd8\xff': 'JPEG Image',
            b'\x89PNG\r\n\x1a\n': 'PNG Image',
            b'GIF87a': 'GIF Image',
            b'GIF89a': 'GIF Image',
        }

    def get_file_signature(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)
            for signature, file_type in self.magic_signatures.items():
                if header.startswith(signature):
                    return file_type
        except Exception as e:
            logger.error(f"[!] 파일 시그니처 확인 실패: {e}")
        return "Unknown"

    def analyze_pe_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                    return None
                pe_offset_bytes = dos_header[60:64]
                if len(pe_offset_bytes) < 4:
                    return None
                pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
                f.seek(pe_offset)
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    return None
                coff_header = f.read(20)
                if len(coff_header) < 20:
                    return None
                machine = struct.unpack('<H', coff_header[0:2])[0]
                number_of_sections = struct.unpack('<H', coff_header[2:4])[0]
                time_date_stamp = struct.unpack('<I', coff_header[4:8])[0]
                optional_header_size = struct.unpack('<H', coff_header[16:18])[0]
                pe_type = "PE32"
                if optional_header_size > 0:
                    optional_header = f.read(optional_header_size)
                    if len(optional_header) >= 2:
                        magic_val = struct.unpack('<H', optional_header[0:2])[0]
                        pe_type = "PE32+" if magic_val == 0x20b else "PE32"
                return {
                    "type": pe_type,
                    "machine": hex(machine),
                    "sections": number_of_sections,
                    "timestamp": time_date_stamp,
                    "architecture": "x64" if machine == 0x8664 else "x86" if machine == 0x14c else "Unknown"
                }
        except Exception as e:
            logger.error(f"[!] PE 파일 분석 실패: {e}")
        return None

    def check_file_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if not data:
                return 0.0
            frequency = [0] * 256
            for byte in data:
                frequency[byte] += 1
            entropy = 0.0
            data_len = len(data)
            for count in frequency:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            return entropy
        except Exception as e:
            logger.error(f"[!] 엔트로피 계산 실패: {e}")
            return 0.0

    def detect_packer(self, file_path):
        packers = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            packer_signatures = {
                b'UPX!': 'UPX', b'UPX0': 'UPX', b'UPX1': 'UPX', b'FSG!': 'FSG',
                b'MPRESS': 'MPRESS', b'aPLib': 'aPLib', b'NsPack': 'NsPack'
            }
            for signature, packer_name in packer_signatures.items():
                if signature in data:
                    packers.append(packer_name)
            entropy = self.check_file_entropy(file_path)
            if entropy > 7.5:
                packers.append("High Entropy (Possibly Packed)")
        except Exception as e:
            logger.error(f"[!] 패커 탐지 실패: {e}")
        return packers

    def analyze_file(self, file_path):
        result = {
            "filename": os.path.basename(file_path),
            "size": 0,
            "signature_type": "Unknown",
            "mime_type": "Unknown",
            "magic_type": "Unknown",
            "pe_info": None,
            "entropy": 0.0,
            "packers": [],
            "is_executable": False,
            "is_archive": False,
            "is_document": False,
            "risk_indicators": []
        }
        if not os.path.exists(file_path):
            result["error"] = "파일이 존재하지 않습니다"
            logger.error(f"[!] File not found for analysis: {file_path}")
            return result
        try:
            result["size"] = os.path.getsize(file_path)
            result["signature_type"] = self.get_file_signature(file_path)

            if self.magic_mime_analyzer and self.magic_full_analyzer:
                try:
                    result["magic_type"] = self.magic_full_analyzer.from_file(file_path)
                    result["mime_type"] = self.magic_mime_analyzer.from_file(file_path) # <--- mime=True 인자 제거
                except Exception as e:
                    logger.warning(f"[!] python-magic analysis failed for {file_path}: {e}")
            else:
                logger.warning("[!] python-magic analyzer not initialized, skipping magic type detection.")

            if result["signature_type"] == "PE Executable" or (result["magic_type"] and "PE executable" in result["magic_type"]):
                result["pe_info"] = self.analyze_pe_file(file_path)
                result["is_executable"] = True
            result["entropy"] = self.check_file_entropy(file_path)
            result["packers"] = self.detect_packer(file_path)

            if "executable" in result["mime_type"] or "application/x-executable" in result["mime_type"] or "application/x-ms-dos-executable" in result["mime_type"]:
                result["is_executable"] = True
            elif "archive" in result["mime_type"] or "application/zip" in result["mime_type"] or "application/x-rar" in result["mime_type"]:
                result["is_archive"] = True
            elif "document" in result["mime_type"] or "application/pdf" in result["mime_type"] or "application/msword" in result["mime_type"]:
                result["is_document"] = True

            risk_indicators = []
            if result["entropy"] > 7.5:
                risk_indicators.append("High entropy (possibly packed or encrypted)")
            if result["packers"]:
                risk_indicators.append(f"Packed with: {', '.join(result['packers'])}")
            filename_lower = result["filename"].lower()
            if result["is_executable"] and (filename_lower.endswith(('.txt', '.doc', '.pdf', '.jpg', '.png')) or "text" in result["mime_type"] or "image" in result["mime_type"] or "document" in result["mime_type"]):
                risk_indicators.append("File extension/MIME type mismatch (executable disguised)")
            if result["is_executable"] and result["size"] > 0 and result["size"] < 1024:
                risk_indicators.append("Unusually small executable file")
            result["risk_indicators"] = risk_indicators
        except Exception as e:
            result["error"] = f"분석 중 오류 발생: {str(e)}"
            logger.exception(f"[!] Unexpected error during file analysis: {file_path}")
        return result

