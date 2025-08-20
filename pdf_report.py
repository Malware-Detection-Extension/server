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
        start_y = self.get_y()

        # draw the key in the first column
        self.set_font(self.font_family, 'B', 10)
        self.multi_cell(50, 8, key, border=0, align='L')
        key_end_y = self.get_y()

        # move to the second column and draw the value
        self.set_xy(self.l_margin + 50, start_y)
        self.set_font(self.font_family, '', 10)
        self.multi_cell(140, 8, str(value), border=0, align='L')
        value_end_y = self.get_y()

        # determine the final Y position after drawing both cells
        final_y = max(key_end_y, value_end_y)
        row_height = final_y - start_y

        # redraw the cells with a border to ensure it fits the content
        self.rect(self.l_margin, start_y, 190, row_height)
        self.line(self.l_margin + 50, start_y, self.l_margin + 50, final_y)
        self.set_xy(self.l_margin, start_y)
        self.set_font(self.font_family, 'B', 10)
        self.multi_cell(50, 8, key, border=0, align='L')
        self.set_xy(self.l_margin + 50, start_y)
        self.set_font(self.font_family, '', 10)
        self.multi_cell(140, 8, str(value), border=0, align='L')
        self.set_y(final_y)

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
        
        # Table Header
        self.set_font(self.font_family, 'B', 10)
        self.cell(80, 8, 'Filename', 1)
        self.cell(30, 8, 'Risk Score', 1)
        self.cell(80, 8, 'File Type', 1, ln=1)

        # Table Rows (display up to 10 files)
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
        
        # if the file was an archive, add the summary of its contents
        pdf.archived_files_summary(analysis_result.get('archived_files'))
        
        # add static properties of the main container file
        pdf.static_properties(analysis_result)
        
        # output the final PDF to the specified path
        pdf.output(str(pdf_path))
        logger.info(f"Malicious PDF report generated: {pdf_path}")

        return str(pdf_path)

    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}")
        return None

