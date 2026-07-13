from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from datetime import datetime
from typing import Dict, List, Any
import os


class PDFReportGenerator:
    def __init__(self, output_path: str = "reports"):
        self.output_path = output_path
        self._create_report_directory()

    def _create_report_directory(self):
        if not os.path.exists(self.output_path):
            os.makedirs(self.output_path)

    def generate_report(self, scan_results: Dict[str, Any], company_name: str = "Security Audit") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{self.output_path}/vulnerability_report_{timestamp}.pdf"
        doc = SimpleDocTemplate(filename, pagesize=A4)
        elements = []
        elements.extend(self._create_title_page(scan_results, company_name))
        elements.append(PageBreak())
        elements.extend(self._create_executive_summary(scan_results))
        elements.append(PageBreak())
        elements.extend(self._create_vulnerability_details(scan_results))
        doc.build(elements)
        return filename

    def _create_title_page(self, scan_results: Dict, company_name: str) -> List:
        elements = []
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle', parent=styles['Heading1'], fontSize=24,
            textColor=colors.HexColor('#1f4788'), spaceAfter=30,
            alignment=TA_CENTER, fontName='Helvetica-Bold'
        )
        subtitle_style = ParagraphStyle(
            'Subtitle', parent=styles['Normal'], fontSize=14,
            textColor=colors.HexColor('#333333'), spaceAfter=12, alignment=TA_CENTER
        )
        elements.append(Paragraph("PENETRATION TEST REPORT", title_style))
        elements.append(Paragraph("Web Application Vulnerability Assessment", subtitle_style))
        elements.append(Spacer(1, 0.3 * inch))

        metadata = [
            ['Target URL:', scan_results.get('target', 'N/A')],
            ['Scan Date:', scan_results.get('timestamp', 'N/A')],
            ['Organization:', company_name],
            ['Report Status:', scan_results.get('scan_status', 'N/A')],
        ]
        metadata_table = Table(metadata, colWidths=[2 * inch, 4 * inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8e8e8')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(metadata_table)
        return elements

    def _create_executive_summary(self, scan_results: Dict) -> List:
        elements = []
        styles = getSampleStyleSheet()
        heading_style = ParagraphStyle(
            'CustomHeading', parent=styles['Heading2'], fontSize=14,
            textColor=colors.HexColor('#1f4788'), spaceAfter=12, fontName='Helvetica-Bold'
        )
        elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        elements.append(Spacer(1, 0.2 * inch))

        summary = scan_results.get('summary', {})
        summary_text = f"""
        This penetration test identified security vulnerabilities in the target web application.
        <br/><br/>
        <b>Total Vulnerabilities:</b> {summary.get('total_vulnerabilities', 0)}<br/>
        <b>Critical Issues:</b> {summary.get('critical_count', 0)}<br/>
        <b>High Severity Issues:</b> {summary.get('high_count', 0)}<br/>
        <b>Command Injection Found:</b> {summary.get('command_injection_found', 0)}<br/>
        <b>File Inclusion Found:</b> {summary.get('file_inclusion_found', 0)}<br/>
        """
        elements.append(Paragraph(summary_text, styles['Normal']))
        return elements

    def _create_vulnerability_details(self, scan_results: Dict) -> List:
        elements = []
        styles = getSampleStyleSheet()
        heading_style = ParagraphStyle(
            'CustomHeading', parent=styles['Heading2'], fontSize=14,
            textColor=colors.HexColor('#1f4788'), spaceAfter=12, fontName='Helvetica-Bold'
        )
        elements.append(Paragraph("VULNERABILITY DETAILS", heading_style))
        elements.append(Spacer(1, 0.2 * inch))

        vulnerabilities = scan_results.get('vulnerabilities', [])
        if not vulnerabilities:
            elements.append(Paragraph("No vulnerabilities found.", styles['Normal']))
            return elements

        table_data = [['Type', 'Severity', 'Parameter', 'Payload']]
        for vuln in vulnerabilities:
            if vuln.get('vulnerable'):
                table_data.append([
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'N/A'),
                    vuln.get('parameter', 'N/A'),
                    vuln.get('payload', 'N/A')[:25],
                ])

        if len(table_data) > 1:
            vuln_table = Table(table_data, colWidths=[1.8 * inch, 1.2 * inch, 1.2 * inch, 1.8 * inch])
            style_commands = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4788')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]
            for idx in range(1, len(table_data)):
                style_commands.append(('BACKGROUND', (0, idx), (-1, idx), colors.HexColor('#ff6b6b')))
            vuln_table.setStyle(TableStyle(style_commands))
            elements.append(vuln_table)
        return elements
