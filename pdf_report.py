# pdf_report.py

import os
import json
import hashlib
import magic
from datetime import datetime, timezone
from pathlib import Path
from fpdf import FPDF
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger("pdf_report")
logger.setLevel(logging.INFO)

class MaliciousPDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.add_page()
        self.set_font('Arial', '', 12)

    def header(self):
        self.set_font('Arial', 'B', 16)
        self.set_text_color(220, 50, 50)
        self.cell(0, 10, 'MALWARE ANALYSIS REPORT', 0, 1, 'C')
        self.set_text_color(0, 0, 0)
        self.ln(5)
        self.set_draw_color(200, 200, 200)
        self.line(10, 25, 200, 25)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Page {self.page_no()}', 0, 0, 'C')

    def add_section_header(self, title: str):
        self.ln(5)
        self.set_font('Arial', 'B', 14)
        self.set_text_color(70, 70, 70)
        self.cell(0, 8, title, 0, 1)
        self.set_text_color(0, 0, 0)
        self.set_draw_color(150, 150, 150)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def add_key_value(self, key: str, value: str, indent: int = 0):
        self.set_font('Arial', 'B', 10)
        self.cell(50 + indent, 6, f'{key}:', 0, 0)
        self.set_font('Arial', '', 10)
        max_width = 140 - indent
        if len(value) > 80:
            self.ln()
            self.set_x(60 + indent)
            words = value.split()
            line = ""
            for word in words:
                if len(line + word) > 100:
                    self.cell(max_width, 6, line.strip(), 0, 1)
                    self.set_x(60 + indent)
                    line = word + " "
                else:
                    line += word + " "
            if line.strip():
                self.cell(max_width, 6, line.strip(), 0, 1)
        else:
            self.cell(max_width, 6, value, 0, 1)

    def add_risk_indicator(self, score: int):
        self.set_font('Arial', 'B', 12)
        if score >= 80:
            self.set_text_color(255, 0, 0)
            risk_level = "CRITICAL"
        elif score >= 60:
            self.set_text_color(255, 165, 0)
            risk_level = "HIGH"
        elif score >= 40:
            self.set_text_color(255, 255, 0)
            risk_level = "MEDIUM"
        else:
            self.set_text_color(0, 255, 0)
            risk_level = "LOW"
        self.cell(0, 10, f'RISK LEVEL: {risk_level} ({score}/100)', 0, 1, 'C')
        self.set_text_color(0, 0, 0)

    def add_yara_matches(self, matches: List[Dict]):
        if not matches:
            self.add_key_value("YARA Matches", "No matches found")
            return
        self.add_key_value("YARA Matches", f"{len(matches)} rule(s) triggered")
        self.ln(2)
        for i, match in enumerate(matches, 1):
            rule_name = match.get('rule', 'Unknown')
            meta = match.get('meta', {})
            severity = meta.get('severity', 'unknown')
            self.set_font('Arial', 'B', 9)
            self.cell(15, 5, f'{i}.', 0, 0)
            self.set_font('Arial', '', 9)
            self.cell(0, 5, f'Rule: {rule_name} | Severity: {severity.upper()}', 0, 1)
            strings = match.get('strings', [])
            if strings:
                for string_match in strings[:3]:
                    identifier = string_match.get('identifier', '')
                    offset = string_match.get('offset', 0)
                    data = string_match.get('data', '')[:50]
                    self.set_x(25)
                    self.set_font('Arial', '', 8)
                    self.cell(0, 4, f'   {identifier} at 0x{offset:X}: {data}...', 0, 1)
                if len(strings) > 3:
                    self.set_x(25)
                    self.cell(0, 4, f'   ... and {len(strings) - 3} more matches', 0, 1)
            self.ln(1)

    def add_obfuscation_analysis(self, analysis_data: Dict):
        obfuscation_detected = analysis_data.get('obfuscation_detected', False)
        deob_result = analysis_data.get('deobfuscation_result')
        self.add_key_value("Obfuscation Detected", "Yes" if obfuscation_detected else "No")
        if obfuscation_detected and deob_result:
            success = deob_result.get('success', False)
            obf_types = deob_result.get('obfuscation_types', [])
            self.add_key_value("Deobfuscation Attempted", "Yes", 10)
            self.add_key_value("Deobfuscation Success", "Yes" if success else "No", 10)
            if obf_types:
                self.add_key_value("Obfuscation Types", ", ".join(obf_types), 10)
            logs = deob_result.get('log', [])
            if logs:
                self.add_key_value("Deobfuscation Log", "", 10)
                for log_entry in logs[:5]:
                    self.set_x(30)
                    self.set_font('Arial', '', 9)
                    self.cell(0, 4, f"- {log_entry}", 0, 1)


    def add_static_analysis_details(self, analysis_data: Dict):
        file_info = analysis_data.get('file_info', {})
        hashes = analysis_data.get('hashes', {})
        self.add_key_value("File Size", f"{file_info.get('size', 0):,} bytes")
        self.add_key_value("MIME Type", file_info.get('mime_type', 'Unknown'))
        self.add_key_value("File Type", file_info.get('file_type', 'Unknown'))
        if hashes:
            self.ln(2)
            self.set_font('Arial', 'B', 11)
            self.cell(0, 6, 'File Hashes:', 0, 1)
            for hash_type, hash_value in hashes.items():
                if hash_value:
                    self.add_key_value(f"{hash_type.upper()}", hash_value, 10)
        entropy = analysis_data.get('entropy', 0)
        if entropy > 0:
            entropy_risk = "High (Possibly Packed)" if entropy > 7.0 else "Normal"
            self.add_key_value("Entropy", f"{entropy:.2f} ({entropy_risk})")
        packers = analysis_data.get('packers', [])
        if packers:
            self.add_key_value("Detected Packers", ", ".join(packers))
        pe_info = analysis_data.get('pe_info')
        if pe_info:
            self.ln(2)
            self.set_font('Arial', 'B', 11)
            self.cell(0, 6, 'PE File Details:', 0, 1)
            self.add_key_value("PE Type", pe_info.get('type', 'Unknown'), 10)
            self.add_key_value("Architecture", pe_info.get('architecture', 'Unknown'), 10)
            self.add_key_value("Machine", pe_info.get('machine', 'Unknown'), 10)
            self.add_key_value("Sections", str(pe_info.get('sections', 0)), 10)
            timestamp = pe_info.get('timestamp', 0)
            if timestamp:
                compile_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                self.add_key_value("Compile Time", compile_time, 10)


    def add_risk_assessment(self, analysis_data: Dict):
        extension_risk = analysis_data.get('extension_risk', {})
        size_anomaly = analysis_data.get('size_anomaly')
        yara_matches = analysis_data.get('yara_matches', [])
        ext_risk_level = extension_risk.get('risk', 'unknown')
        ext = extension_risk.get('extension', 'unknown')
        self.add_key_value("Extension Risk", f"{ext_risk_level.upper()} ({ext})")
        if size_anomaly:
            anomaly_type = size_anomaly.get('anomaly', '')
            description = size_anomaly.get('description', '')
            self.add_key_value("Size Anomaly", f"{anomaly_type}: {description}")
        else:
            self.add_key_value("Size Anomaly", "None detected")
        if yara_matches:
            severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for match in yara_matches:
                severity = match.get('meta', {}).get('severity', 'low')
                severity_count[severity] = severity_count.get(severity, 0) + 1
            severity_text = ", ".join([f"{k.capitalize()}: {v}" for k, v in severity_count.items() if v > 0])
            self.add_key_value("Rule Severity Distribution", severity_text)


class PDFReportGenerator:
    def __init__(self, pdf_reports_dir: str = "./reports/malicious_pdf"):
        self.pdf_dir = Path(pdf_reports_dir)
        self.pdf_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_malicious_report(self, analysis_result: Dict[str, Any],
                                 url: str,
                                 original_filename: Optional[str] = None) -> Optional[str]:
        if not analysis_result.get('is_malicious', False):
            logger.info("Non-malicious file - PDF report not generated")
            return None
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_url = self._sanitize_filename(url)
            pdf_filename = f"malicious_report_{timestamp}_{safe_url[:30]}.pdf"
            pdf_path = self.pdf_dir / pdf_filename
            
            pdf = MaliciousPDFReport()
            
            # 1. 요약 정보
            pdf.add_section_header("EXECUTIVE SUMMARY")
            pdf.add_risk_indicator(analysis_result.get('risk_score', 0))
            pdf.ln(5)
            
            # 2. 기본 정보
            pdf.add_section_header("BASIC INFORMATION")
            pdf.add_key_value("Analysis Date", datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'))
            pdf.add_key_value("Source URL", url)
            if original_filename:
                pdf.add_key_value("Original Filename", original_filename)
            pdf.add_key_value("Malicious", "YES" if analysis_result.get('is_malicious') else "NO")
            pdf.add_key_value("Risk Score", f"{analysis_result.get('risk_score', 0)}/100")
            pdf.add_key_value("Detection Message", analysis_result.get('message', 'No message'))
            
            # 3. 파일 분석 정보
            pdf.add_section_header("FILE ANALYSIS")
            pdf.add_static_analysis_details(analysis_result) 
            
            # 4. 난독화 분석
            pdf.add_section_header("OBFUSCATION ANALYSIS")
            # app.py에서 obfuscation 분석이 없음.
            # 이 섹션이 작동하지 않으므로, 더미 데이터로 대체하거나 app.py에 해당 로직을 추가해야 함.
            pdf.add_obfuscation_analysis(analysis_result)
            
            # 5. YARA 탐지 결과
            pdf.add_section_header("YARA DETECTION RESULTS")
            yara_matches = analysis_result.get('yara_matches', [])
            pdf.add_yara_matches(yara_matches)
            
            # 6. 위험도 평가 상세
            pdf.add_section_header("RISK ASSESSMENT DETAILS")
            pdf.add_risk_assessment(analysis_result)
            
            # 7. 권장 사항
            pdf.add_section_header("RECOMMENDATIONS")
            pdf.set_font('Arial', '', 10)
            recommendations = self._generate_recommendations(analysis_result)
            for i, rec in enumerate(recommendations, 1):
                pdf.cell(10, 6, f'{i}.', 0, 0)
                pdf.cell(0, 6, rec, 0, 1)
            
            # 8. 기술적 세부사항
            if analysis_result.get('analysis_details'):
                pdf.add_section_header("TECHNICAL DETAILS")
                details = analysis_result.get('analysis_details', {})
                for key, value in details.items():
                    if isinstance(value, (str, int, float)):
                        pdf.add_key_value(key.replace('_', ' ').title(), str(value))
            
            pdf.output(str(pdf_path))
            logger.info(f"Malicious PDF report generated: {pdf_path}")
            return str(pdf_path)
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return None
            
    def _sanitize_filename(self, text: str) -> str:
        if "://" in text:
            text = text.split("://")[-1]
        import re
        safe_text = re.sub(r'[^\w\-_.]', '_', text)
        return safe_text[:50]
        
    def _generate_recommendations(self, analysis_result: Dict) -> List[str]:
        recommendations = [
            "Immediately quarantine or delete the malicious file",
            "Run a full system antivirus scan",
            "Check system for signs of compromise"
        ]
        
        risk_score = analysis_result.get('risk_score', 0)
        yara_matches = analysis_result.get('yara_matches', [])
        obfuscation = analysis_result.get('obfuscation_detected', False)
        
        if risk_score >= 80:
            recommendations.append("Consider reimaging the affected system")
            recommendations.append("Monitor network traffic for suspicious activity")
            
        if obfuscation:
            recommendations.append("Analyze deobfuscated code for additional IOCs")
            
        if any('trojan' in match.get('rule', '').lower() for match in yara_matches):
            recommendations.append("Check for unauthorized network connections")
            recommendations.append("Scan for additional malware variants")
            
        if any('ransomware' in match.get('rule', '').lower() for match in yara_matches):
            recommendations.append("Backup critical data immediately")
            recommendations.append("Disconnect from network to prevent spread")
            
        return recommendations


# 최종적으로 호출되는 래퍼 함수
def generate_malicious_pdf_report(analysis_result: Dict[str, Any],
                                 url: str,
                                 original_filename: Optional[str] = None,
                                 pdf_reports_dir: str = "./reports/malicious_pdf") -> Optional[str]:
    generator = PDFReportGenerator(pdf_reports_dir)
    return generator.generate_malicious_report(analysis_result, url, original_filename)