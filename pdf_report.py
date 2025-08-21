# pdf_report.py

import os
import re
import logging
from datetime import datetime
from pathlib import Path
from fpdf import FPDF
from typing import Dict, Any, Optional, List

logger = logging.getLogger("pdf_report")
logger.setLevel(logging.INFO)

# a custom PDF class using FPDF to generatea formatted malware analysis report
class MaliciousPDFReport(FPDF):
    # initialize
    def __init__(self):
        super().__init__()
        self.font_family = 'Arial'
        self.set_auto_page_break(auto=True, margin=15)
        self.add_page()
        self.set_font(self.font_family, '', 12)

    # define the header content for each page of the PDF
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.set_text_color(220, 50, 50)
        self.cell(0, 10, 'Malware Analysis Report', 0, 1, 'C')
        self.set_text_color(0, 0, 0)
        self.ln(5)

    # definethe footer content, including the page number
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    # create a styled, full-width title for a new section
    def section_title(self, title):
        if self.get_y() > 240:
            self.add_page()
        self.set_font(self.font_family, 'B', 14)
        self.set_fill_color(230, 230, 230)
        self.cell(0, 10, title, 0, 1, 'L', fill=True)
        self.ln(4)

    # create a two-column row for displaying a key and its value, handling multi-line text
    def key_value_row(self, key, value):
        line_height = 8

        # calculate the number of lines required for key and value
        self.set_font(self.font_family, 'B', 10)
        key_lines = self.multi_cell(w=50, h=line_height, text=key, split_only=True)

        self.set_font(self.font_family, '', 10)
        value_lines = self.multi_cell(w=140, h=line_height, text=str(value), split_only=True)

        # determine the total height of the row
        row_height = max(len(key_lines), len(value_lines)) * line_height

        # check if there is enough space on the page, if not, add a new page
        if self.get_y() + row_height > self.page_break_trigger:
            self.add_page()

        start_y = self.get_y()
        start_x = self.get_x()

        # draw the borders for the entire row
        self.rect(start_x, start_y, 190, row_height)
        self.line(start_x + 50, start_y, start_x + 50, start_y + row_height)

        # draw the key text
        self.set_font(self.font_family, 'B', 10)
        self.multi_cell(50, line_height, key, border=0, align='L')

        # move to the second column and draw the value text
        self.set_xy(start_x + 50, start_y)
        self.set_font(self.font_family, '', 10)
        self.multi_cell(140, line_height, str(value), border=0, align='L')

        # set the Y position for the next element
        self.set_y(start_y + row_height)

    # add the executive summary section with a color-coded risk level
    def risk_summary(self, score, message):
        self.section_title('Executive Summary')
        if score >= 80: risk_level, color = "CRITICAL", (255, 0, 0)
        elif score >= 60: risk_level, color = "HIGH", (255, 165, 0)
        else: risk_level, color = "LOW", (0, 176, 80)

        self.set_font(self.font_family, 'B', 12)
        self.set_text_color(*color)
        self.cell(50, 10, 'Risk Level', border=1)
        self.cell(140, 10, f'{risk_level} ({score}/100)', border=1, ln=1)
        self.set_text_color(0,0,0)
        self.key_value_row('Summary', message)
        self.ln(10)

    # add a section with metadata about the analysis session
    def analysis_metadata(self, url, filename):
        self.section_title('Analysis Metadata')
        self.key_value_row('Source URL', url)
        if filename: self.key_value_row('Original Filename', filename)
        self.key_value_row('Analysis Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.ln(10)

    # add a summary table of files dound within an archive, highlighting malicious ones
    def archived_files_summary(self, archived_files):
        if not archived_files:
            return

        self.section_title('Archived File Analysis Summary')

        # table header
        self.set_font(self.font_family, 'B', 10)
        self.cell(80, 8, 'Filename', 1)
        self.cell(30, 8, 'Risk Score', 1)
        self.cell(80, 8, 'File Type', 1, ln=1)

        # table rows (display up to 10 files)
        for report in archived_files[:10]:
            self.set_font(self.font_family, '', 9)
            filename = report.get("file_info", {}).get("filename", "N/A")
            risk_score = report.get("risk_score", 0)
            file_type = report.get("file_info", {}).get("file_type", "N/A")

            # set a light red background for high-risk files
            if risk_score >= 60:
                # light red
                self.set_fill_color(255, 220, 220)
            else:
                # white
                self.set_fill_color(255, 255, 255)

            # truncate long file name to prevent overflow
            self.cell(80, 8, filename[:45], 1, 0, 'L', fill=True)
            self.cell(30, 8, str(risk_score), 1, 0, 'C', fill=True)
            self.cell(80, 8, file_type[:45], 1, 1, 'L', fill=True)

        if len(archived_files) > 10:
            self.cell(0, 8, f"... and {len(archived_files) - 10} more files.", 1, 1, 'C')

        self.ln(10)

    # add a section for static properties like size, type, and hashes of the container file
    def static_properties(self, analysis_data):
        file_info = analysis_data.get('file_info')
        if not file_info: return

        self.section_title('Static Properties (Archive Container)')
        hashes = analysis_data.get('hashes', {})
        self.key_value_row('File Size', f"{file_info.get('size', 0):,} bytes")
        self.key_value_row('File Type', file_info.get('file_type', 'Unknown'))
        self.key_value_row('MIME Type', file_info.get('mime_type', 'Unknown'))
        self.ln(4)
        self.set_font(self.font_family, 'B', 11)
        self.cell(0, 8, 'File Hashes', 0, 1, 'L')
        for h_type, h_value in hashes.items(): self.key_value_row(h_type.upper(), h_value)
        self.ln(10)

    # add a section for risk factors
    def risk_factors(self, analysis_data):
        self.section_title('Heuristic Risk Factors')
        ext_risk = analysis_data.get('extension_risk', {})
        size_anomaly = analysis_data.get('size_anomaly')
        packers = analysis_data.get('packers', [])
        obfuscation = analysis_data.get('obfuscation_detected', False)
        self.key_value_row('Extension Risk', f"{ext_risk.get('risk', 'N/A').upper()} ({ext_risk.get('extension', 'N/A')})")
        if size_anomaly: self.key_value_row('Size Anomaly', f"{size_anomaly.get('anomaly')}: {size_anomaly.get('description')}")
        else: self.key_value_row('Size Anomaly', 'None detected.')
        self.key_value_row('Packers Detected', ', '.join(packers) if packers else 'None detected.')
        self.key_value_row('Obfuscation Detected', 'Yes' if obfuscation else 'No')
        self.ln(10)

    # add a section for pe_detail
    def pe_details(self, pe_info):
        if not pe_info or "error" in pe_info: return
        self.section_title('PE File Details')
        self.key_value_row('PE Type', pe_info.get('type', 'Unknown'))
        self.key_value_row('Architecture', pe_info.get('architecture', 'Unknown'))
        self.key_value_row('Machine', pe_info.get('machine', 'Unknown'))
        self.key_value_row('Sections', str(pe_info.get('sections', 0)))
        timestamp = pe_info.get('timestamp', 0)
        if timestamp:
            compile_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
            self.key_value_row('Compile Time', compile_time)
        self.ln(10)

    # add a section for indicators of compromise
    def indicators_of_compromise(self, analysis_details):
        if not analysis_details: return
        self.section_title('Indicators of Compromise (IOCs)')
        urls = analysis_details.get('potential_urls', [])
        ips = analysis_details.get('potential_ips', [])
        self.key_value_row('Potential URLs', '\n'.join(urls) if urls else 'None found.')
        self.key_value_row('Potential IPs', '\n'.join(ips) if ips else 'None found.')
        self.key_value_row('Suspicious API Calls', analysis_details.get('suspicious_api_calls', "") or 'None found.')
        self.ln(10)

    # add a section with YARA scan results about the analysis session
    def yara_results(self, matches):
        self.section_title('YARA Detection Results')
        if not matches:
            self.cell(0, 10, 'No YARA rules matched.', border=1, ln=1)
            self.ln(10)
            return

        self.set_font(self.font_family, 'B', 10)
        self.cell(95, 8, 'Rule Name', 1); self.cell(30, 8, 'Severity', 1); self.cell(65, 8, 'Matched String (first)', 1, ln=1)

        for match in matches:
            self.set_font(self.font_family, '', 9)
            severity = match.get('meta', {}).get('severity', 'low').upper()
            first_string = match.get('strings', [{}])[0]
            str_data = f"{first_string.get('identifier', '')}: {first_string.get('data', '')[:25]}"
            start_y = self.get_y()
            self.multi_cell(95, 8, match.get('rule', 'N/A'), border=0)
            y1 = self.get_y()
            self.set_xy(self.l_margin + 95, start_y)
            self.multi_cell(30, 8, severity, border=0)
            y2 = self.get_y()
            self.set_xy(self.l_margin + 125, start_y)
            self.multi_cell(65, 8, str_data, border=0)
            y3 = self.get_y()
            final_y = max(y1, y2, y3)
            row_height = final_y - start_y
            self.rect(self.l_margin, start_y, 190, row_height)
            self.line(self.l_margin + 95, start_y, self.l_margin + 95, final_y)
            self.line(self.l_margin + 125, start_y, self.l_margin + 125, final_y)
            self.set_y(final_y)
            self.ln(0)
        self.ln(10)

# generate a PDF report if the analysis result is malicious
def generate_malicious_pdf_report(analysis_result: Dict[str, Any],
                                 url: str,
                                 original_filename: Optional[str] = None,
                                 pdf_reports_dir: str = "./reports/malicious_pdf") -> Optional[str]:

    if not analysis_result.get('is_malicious', False):
        return None

    try:
        pdf_dir = Path(pdf_reports_dir)
        pdf_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')

        # sanitize the file name to make it safe for the file system
        safe_filename = re.sub(r'[^\w\-_.]', '_', original_filename or "download")
        pdf_filename = f"malicious_report_{timestamp}_{safe_filename[:30]}.pdf"
        pdf_path = pdf_dir / pdf_filename

        # create a PDF instance and populate it with data
        pdf = MaliciousPDFReport()
        pdf.risk_summary(analysis_result.get('risk_score', 0), analysis_result.get('message', ''))
        pdf.analysis_metadata(url, original_filename)
        pdf.archived_files_summary(analysis_result.get('archived_files'))
        pdf.static_properties(analysis_result)
        pdf.risk_factors(analysis_result)
        pdf.pe_details(analysis_result.get('pe_info'))
        pdf.indicators_of_compromise(analysis_result.get('analysis_details'))
        pdf.yara_results(analysis_result.get('yara_matches', []))

        # output the final PDF to the specified path
        pdf.output(str(pdf_path))
        logger.info(f"Malicious PDF report generated: {pdf_path}")

        return str(pdf_path)

    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}")
        return None
        
