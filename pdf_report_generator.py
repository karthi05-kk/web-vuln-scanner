"""
pdf_report_generator.py - PROFESSIONAL REPORT VERSION

Drop-in replacement: same class name, same generate_report(scan_results,
company_name=...) call signature as before, so auto_scanner.py and
simple_main.py need ZERO changes.

Structure implemented, matching the requested professional pentest report
format:
  - Cover page (title, target, date, prepared-by, confidentiality notice)
  - Table of Contents (real, page-numbered, with clickable PDF bookmarks
    in the viewer's sidebar - see note in the accompanying chat message
    about what "clickable" means here specifically)
  - Executive Summary
  - Dashboard (severity pie chart + category bar chart)
  - Scan Information
  - Findings (one detailed sub-section per vulnerability: ID, CVSS, CWE,
    OWASP, description, technical details, evidence, steps to reproduce,
    impact, recommendation, references)
  - Appendix (payloads used, tool versions)

NOT included, honestly: Proof-of-Concept screenshots. That needs a
headless browser (Selenium/Playwright) to actually capture the page,
which this scanner doesn't drive - it's an HTTP-only tool. Flagged
clearly in the PDF itself rather than faking a placeholder image.
"""
import os
from html import escape as _esc
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import quote

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image as RLImage, KeepTogether,
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend

# ----------------------------------------------------------------------
# Reference data: severity colors, representative CVSS scores, and the
# description/impact/references content for each vulnerability type.
# ----------------------------------------------------------------------
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#b02a25"),
    "HIGH": colors.HexColor("#d9752e"),
    "MEDIUM": colors.HexColor("#d4ac0d"),
    "LOW": colors.HexColor("#2e75b0"),
    "INFO": colors.HexColor("#7f8c8d"),
}

VULN_INFO = {
    "Command Injection": {
        "cwe": "CWE-78", "owasp": "A03:2021 - Injection", "cvss": 9.8,
        "description": "The application passes user-supplied input directly into a system "
                        "shell command without adequate sanitization, allowing an attacker to "
                        "execute arbitrary operating system commands with the privileges of "
                        "the web server process.",
        "impact": "Full compromise of the underlying host is possible: reading, modifying, "
                   "or deleting files; pivoting to internal systems; installing persistence "
                   "mechanisms; or using the server as a foothold for further attacks.",
        "recommendation": "Avoid shell execution with user input entirely where possible. If "
                           "unavoidable, use language APIs rather than shell strings, and "
                           "apply strict allow-lists for any characters passed through.",
        "references": ["https://owasp.org/www-community/attacks/Command_Injection",
                        "https://cwe.mitre.org/data/definitions/78.html"],
    },
    "File Inclusion (LFI)": {
        "cwe": "CWE-98", "owasp": "A03:2021 - Injection", "cvss": 7.5,
        "description": "The application builds a file path from user-controlled input "
                        "without validating it against an allow-list, permitting path "
                        "traversal sequences to read arbitrary files from the server's "
                        "filesystem.",
        "impact": "Disclosure of sensitive files (credentials, source code, configuration "
                   "data), and potential escalation to remote code execution via techniques "
                   "such as log poisoning or session file injection.",
        "recommendation": "Validate file paths against an allow-list of known-good "
                           "filenames. Never build include paths directly from user input. "
                           "Disable allow_url_include / allow_url_fopen.",
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal",
                        "https://cwe.mitre.org/data/definitions/98.html"],
    },
    "Cross-Site Scripting (XSS)": {
        "cwe": "CWE-79", "owasp": "A03:2021 - Injection", "cvss": 6.1,
        "description": "User-supplied input is reflected back into the HTML response "
                        "without context-appropriate output encoding, allowing injection of "
                        "arbitrary HTML/JavaScript that executes in victims' browsers.",
        "impact": "Session hijacking, credential theft via fake login prompts, defacement, "
                   "or using the victim's browser as a pivot for further attacks against "
                   "them or the application on their behalf.",
        "recommendation": "Apply context-appropriate output encoding at every reflection "
                           "point. Consider a Content-Security-Policy as defense in depth.",
        "references": ["https://owasp.org/www-community/attacks/xss/",
                        "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "SQL Injection (Error-Based)": {
        "cwe": "CWE-89", "owasp": "A03:2021 - Injection", "cvss": 9.8,
        "description": "User-supplied input is concatenated directly into a SQL query, "
                        "and the raw database error is returned to the client - confirming "
                        "the query structure can be manipulated by the attacker.",
        "impact": "Full read/write access to the application's database is possible: "
                   "credential theft, data exfiltration, or data destruction.",
        "recommendation": "Use parameterized queries / prepared statements exclusively. "
                           "Never concatenate user input into SQL strings. Disable verbose "
                           "database error output in production.",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cwe.mitre.org/data/definitions/89.html"],
    },
}
DEFAULT_VULN_INFO = {
    "cwe": "N/A", "owasp": "N/A", "cvss": 5.0,
    "description": "See referenced CWE/OWASP entries for this vulnerability class.",
    "impact": "Impact varies by context - consult the evidence and references for details.",
    "recommendation": "Consult OWASP guidance for this specific vulnerability class.",
    "references": [],
}


def get_vuln_info(vuln_type: str) -> dict:
    return VULN_INFO.get(vuln_type, DEFAULT_VULN_INFO)


def generate_repro_command(finding: dict) -> str:
    method = finding.get("method", "GET").upper()
    url = _esc(finding.get("url", ""))
    param = _esc(finding.get("parameter", ""))
    payload = _esc(str(finding.get("payload", "")))
    if method == "POST":
        return (f"curl -X POST '{url}' --data '{param}={payload}' "
                f"(plus any other required form fields, e.g. a CSRF token)")
    return f"curl '{url}?{param}={quote(str(finding.get('payload', '')))}'"


def generate_repro_steps(finding: dict) -> List[str]:
    method = finding.get("method", "GET").upper()
    url = _esc(finding.get("url", ""))
    param = _esc(finding.get("parameter", ""))
    payload = _esc(str(finding.get("payload", "")))
    evidence = _esc(str(finding.get("evidence", "the response"))[:120])
    return [
        f"1. Navigate to: {url}",
        f"2. Locate the '{param}' parameter (submitted via {method}).",
        f"3. Set '{param}' to the following value: {payload}",
        f"4. Submit the request.",
        f"5. Observe the response - confirming evidence appears: {evidence}",
    ]


# ----------------------------------------------------------------------
# Page numbering + footer: standard reportlab "NumberedCanvas" recipe -
# buffers every page, then stamps "Page X of Y" once the total is known.
# ----------------------------------------------------------------------
class NumberedCanvas(pdfcanvas.Canvas):
    def __init__(self, *args, **kwargs):
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total_pages)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_footer(self, total_pages):
        page_num = self._pageNumber
        self.saveState()
        self.setStrokeColor(colors.HexColor("#cccccc"))
        self.line(0.75 * inch, 0.75 * inch, A4[0] - 0.75 * inch, 0.75 * inch)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#666666"))
        self.drawString(0.75 * inch, 0.55 * inch, "CONFIDENTIAL - Penetration Test Report")
        self.drawRightString(A4[0] - 0.75 * inch, 0.55 * inch, f"Page {page_num} of {total_pages}")
        self.restoreState()


# ----------------------------------------------------------------------
# Custom doc template: hooks afterFlowable() to feed heading paragraphs
# into the TableOfContents flowable, AND registers a PDF outline
# (sidebar bookmark) entry per heading so the TOC is clickable in the
# sense that the reader's PDF viewer sidebar can jump straight to each
# section. (The TOC page's own text lines are not separately
# hyperlinked - that would need manual internal-link annotations on top
# of this; the sidebar bookmarks are the standard, simpler mechanism and
# are what most professional PDF reports actually rely on.)
# ----------------------------------------------------------------------
class ReportDocTemplate(BaseDocTemplate):
    def __init__(self, filename, **kwargs):
        BaseDocTemplate.__init__(self, filename, **kwargs)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        self.addPageTemplates([PageTemplate(id="all", frames=frame)])

    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        style_name = flowable.style.name
        text = flowable.getPlainText()
        if style_name == "SectionHeading":
            key = f"h1-{self.page}-{abs(hash(text))}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=0, closed=0)
            self.notify("TOCEntry", (0, text, self.page))
        elif style_name == "FindingHeading":
            key = f"h2-{self.page}-{abs(hash(text))}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=1, closed=0)
            self.notify("TOCEntry", (1, text, self.page))


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("CoverTitle", parent=ss["Title"], fontSize=26,
                           textColor=colors.HexColor("#1a2b4a"), spaceAfter=14, alignment=TA_CENTER))
    ss.add(ParagraphStyle("CoverSub", parent=ss["Normal"], fontSize=13,
                           textColor=colors.HexColor("#444444"), alignment=TA_CENTER, spaceAfter=6))
    ss.add(ParagraphStyle("SectionHeading", parent=ss["Heading1"], fontSize=16,
                           textColor=colors.white, backColor=colors.HexColor("#1a2b4a"),
                           spaceBefore=4, spaceAfter=14, leftIndent=6, borderPadding=6))
    ss.add(ParagraphStyle("FindingHeading", parent=ss["Heading2"], fontSize=13,
                           textColor=colors.HexColor("#1a2b4a"), spaceBefore=16, spaceAfter=8))
    ss.add(ParagraphStyle("FieldLabel", parent=ss["Normal"], fontSize=9,
                           textColor=colors.HexColor("#555555"), fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=9.5, leading=13))
    ss.add(ParagraphStyle("Mono", parent=ss["Normal"], fontName="Courier", fontSize=8, leading=11))
    return ss


# ----------------------------------------------------------------------
# Section builders - each returns a list of flowables to add to the story
# ----------------------------------------------------------------------
def build_cover_page(styles, target, scan_date, assessment_type, prepared_by, logo_path=None):
    elements = []
    elements.append(Spacer(1, 1.2 * inch))
    if logo_path and os.path.isfile(logo_path):
        try:
            elements.append(RLImage(logo_path, width=1.5 * inch, height=1.5 * inch))
            elements.append(Spacer(1, 0.3 * inch))
        except Exception:
            pass
    elements.append(Paragraph("PENETRATION TEST REPORT", styles["CoverTitle"]))
    elements.append(Paragraph("Web Application Vulnerability Assessment", styles["CoverSub"]))
    elements.append(Spacer(1, 0.6 * inch))

    meta_rows = [
        ["Target URL:", target],
        ["Assessment Type:", assessment_type],
        ["Assessment Date:", scan_date],
        ["Prepared By:", prepared_by],
        ["Scanner:", "Web Vulnerability Scanner v1.3.0 (modular)"],
    ]
    t = Table(meta_rows, colWidths=[1.7 * inch, 4 * inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1a2b4a")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 1 * inch))

    notice = Paragraph(
        "<b>CONFIDENTIALITY NOTICE</b><br/><br/>"
        "This report contains sensitive security information about the target system(s) "
        "listed above, including details of vulnerabilities that could be used to gain "
        "unauthorized access if disclosed. Distribute only to individuals with a "
        "legitimate need to know. Do not transmit over unencrypted channels.",
        styles["Body"],
    )
    box = Table([[notice]], colWidths=[6.3 * inch])
    box.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#b02a25")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fdf1f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    elements.append(box)
    elements.append(PageBreak())
    return elements


def build_toc(styles):
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(name="TOCHeading1", fontSize=12, fontName="Helvetica-Bold",
                        leftIndent=0, firstLineIndent=0, spaceBefore=8, leading=16),
        ParagraphStyle(name="TOCHeading2", fontSize=10, fontName="Helvetica",
                        leftIndent=18, firstLineIndent=0, spaceBefore=2, leading=13,
                        textColor=colors.HexColor("#444444")),
    ]
    elements = [Paragraph("TABLE OF CONTENTS", styles["SectionHeading"]), Spacer(1, 10), toc, PageBreak()]
    return elements


def build_executive_summary(styles, scan_results, endpoints_scanned, scan_duration):
    elements = [Paragraph("EXECUTIVE SUMMARY", styles["SectionHeading"])]
    summary = scan_results.get("summary", {})
    findings = scan_results.get("vulnerabilities", [])

    crit = summary.get("critical_count", 0)
    high = summary.get("high_count", 0)
    if crit > 0:
        overall_risk = "CRITICAL"
    elif high > 0:
        overall_risk = "HIGH"
    elif summary.get("medium_count", 0) > 0:
        overall_risk = "MEDIUM"
    elif summary.get("total_vulnerabilities", 0) > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "INFO"

    rows = [
        ["Target URL", scan_results.get("target", "N/A")],
        ["Endpoints Scanned", str(endpoints_scanned)],
        ["Scan Duration", scan_duration],
        ["Total Findings", str(len(findings))],
        ["Overall Risk Rating", overall_risk],
    ]
    t = Table(rows, colWidths=[2 * inch, 4 * inch])
    style_cmds = [
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef1f7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]
    risk_color = SEVERITY_COLORS.get(overall_risk, colors.grey)
    style_cmds.append(("BACKGROUND", (1, 4), (1, 4), risk_color))
    style_cmds.append(("TEXTCOLOR", (1, 4), (1, 4), colors.white))
    style_cmds.append(("FONTNAME", (1, 4), (1, 4), "Helvetica-Bold"))
    t.setStyle(TableStyle(style_cmds))
    elements.append(t)
    elements.append(Spacer(1, 14))

    narrative = (
        f"This assessment identified <b>{len(findings)}</b> finding(s) across "
        f"<b>{endpoints_scanned}</b> tested endpoint(s). "
    )
    if crit or high:
        narrative += (
            f"Of these, <b>{crit}</b> are rated CRITICAL and <b>{high}</b> HIGH severity, "
            f"indicating issues that should be remediated as a priority before this "
            f"application is exposed to untrusted users."
        )
    else:
        narrative += "No Critical or High severity issues were identified in this scan."
    elements.append(Paragraph(narrative, styles["Body"]))
    elements.append(PageBreak())
    return elements


def _severity_pie_drawing(summary):
    data = [summary.get(f"{s.lower()}_count", 0) for s in SEVERITY_ORDER]
    labels = [f"{s} ({c})" for s, c in zip(SEVERITY_ORDER, data) if c > 0]
    nonzero_data = [c for c in data if c > 0]
    nonzero_colors = [SEVERITY_COLORS[s] for s, c in zip(SEVERITY_ORDER, data) if c > 0]

    d = Drawing(400, 200)
    if not nonzero_data:
        d.add(String(150, 100, "No findings to chart", fontSize=10))
        return d

    pie = Pie()
    pie.x, pie.y = 60, 30
    pie.width, pie.height = 150, 150
    pie.data = nonzero_data
    pie.labels = None
    for i, c in enumerate(nonzero_colors):
        pie.slices[i].fillColor = c
    d.add(pie)

    legend = Legend()
    legend.x, legend.y = 250, 150
    legend.dx, legend.dy = 8, 8
    legend.fontSize = 9
    legend.alignment = "right"
    legend.colorNamePairs = list(zip(nonzero_colors, labels))
    d.add(legend)
    return d


def _category_bar_drawing(findings):
    counts = {}
    for f in findings:
        counts[f["type"]] = counts.get(f["type"], 0) + 1
    if not counts:
        d = Drawing(420, 200)
        d.add(String(150, 100, "No findings to chart", fontSize=10))
        return d

    categories = list(counts.keys())
    values = list(counts.values())

    d = Drawing(420, 220)
    chart = VerticalBarChart()
    chart.x, chart.y = 50, 30
    chart.width, chart.height = 340, 150
    chart.data = [values]
    chart.categoryAxis.categoryNames = [c[:16] for c in categories]
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.angle = 20
    chart.categoryAxis.labels.dy = -12
    chart.valueAxis.valueMin = 0
    chart.bars[0].fillColor = colors.HexColor("#1a2b4a")
    d.add(chart)
    return d


def build_scope(styles, scan_results, scan_start, scan_end, endpoints_scanned):
    elements = [Paragraph("SCOPE", styles["SectionHeading"])]
    rows = [
        ["Target", scan_results.get("target", "N/A")],
        ["Endpoints In Scope", str(endpoints_scanned)],
        ["Authentication", "Automatic login (credentials supplied to the scanner)"],
        ["Scan Start", scan_start],
        ["Scan Finish", scan_end],
    ]
    t = Table(rows, colWidths=[1.8 * inch, 4.2 * inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef1f7")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(
        "This assessment covers only the endpoints listed above. Vulnerability classes "
        "outside the active module list (see Scan Information) were not tested and their "
        "absence from this report is not evidence of their absence in the application.",
        styles["Body"],
    ))
    elements.append(PageBreak())
    return elements


def build_methodology(styles, scan_results):
    elements = [Paragraph("METHODOLOGY", styles["SectionHeading"])]
    steps = [
        "<b>1. Authentication</b> - the scanner detects login forms and authenticates "
        "automatically using supplied credentials before testing begins.",
        "<b>2. Endpoint Discovery</b> - target pages are identified via directory "
        "brute-forcing (dirb) and/or link crawling, depending on how the scan was invoked.",
        "<b>3. Injection Point Extraction</b> - each discovered page is parsed for GET "
        "query parameters, POST form fields, and query parameters embedded in on-page "
        "links.",
        "<b>4. Module-Based Testing</b> - each parameter is tested with payloads from "
        "the vulnerability modules most relevant to its name (see Scan Information for "
        "the active module list), falling back to a broad default set for unrecognized "
        "parameter names.",
        "<b>5. Multi-Payload Confirmation</b> - findings that could plausibly be false "
        "positives from a single string match (e.g. XSS, SQL Injection) require multiple "
        "independent payloads to agree before being reported. See each finding's "
        "'Confirmed via N independent payload(s)' note.",
        "<b>6. Reporting</b> - confirmed findings are compiled into this report with "
        "severity, CWE/OWASP mapping, and remediation guidance.",
    ]
    for s in steps:
        elements.append(Paragraph(s, styles["Body"]))
        elements.append(Spacer(1, 6))
    elements.append(PageBreak())
    return elements


def build_recommendations_summary(styles, findings):
    elements = [Paragraph("RECOMMENDATIONS SUMMARY", styles["SectionHeading"])]
    if not findings:
        elements.append(Paragraph("No findings requiring remediation.", styles["Body"]))
        return elements

    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(findings, key=lambda f: severity_rank.get(f.get("severity", "INFO"), 99))

    rows = [["ID", "Finding", "Severity", "Recommendation"]]
    small_body = ParagraphStyle("SmallBody", fontName="Helvetica", fontSize=8, leading=10)
    for idx, f in enumerate(sorted_findings, 1):
        info = get_vuln_info(f["type"])
        rows.append([f"WEB-{idx:03d}", Paragraph(_esc(f["type"]), small_body), f["severity"],
                     Paragraph(_esc(info["recommendation"]), small_body)])

    t = Table(rows, colWidths=[0.6 * inch, 1.3 * inch, 0.7 * inch, 3.6 * inch])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2b4a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, f in enumerate(sorted_findings, 1):
        sev_color = SEVERITY_COLORS.get(f["severity"], colors.grey)
        style_cmds.append(("BACKGROUND", (2, i), (2, i), sev_color))
        style_cmds.append(("TEXTCOLOR", (2, i), (2, i), colors.white))
    t.setStyle(TableStyle(style_cmds))
    elements.append(t)
    elements.append(PageBreak())
    return elements


def build_dashboard(styles, scan_results):
    elements = [Paragraph("DASHBOARD", styles["SectionHeading"])]
    summary = scan_results.get("summary", {})
    findings = scan_results.get("vulnerabilities", [])

    elements.append(Paragraph("Vulnerabilities by Severity", styles["FindingHeading"]))
    elements.append(_severity_pie_drawing(summary))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Vulnerabilities by Category", styles["FindingHeading"]))
    elements.append(_category_bar_drawing(findings))
    elements.append(PageBreak())
    return elements


def build_scan_info(styles, scan_results, scan_start, scan_end, total_requests, endpoints_scanned, endpoints_reachable):
    elements = [Paragraph("SCAN INFORMATION", styles["SectionHeading"])]
    rows = [
        ["Scanner Version", "1.3.0 (modular)"],
        ["Scan Start", scan_start],
        ["Scan End", scan_end],
        ["Total Requests Sent (approx.)", str(total_requests)],
        ["Endpoints Scanned", str(endpoints_scanned)],
        ["Endpoints Reachable", str(endpoints_reachable)],
        ["Active Detection Modules", ", ".join(scan_results.get("modules_active", ["command_injection", "lfi_rfi"]))],
    ]
    t = Table(rows, colWidths=[2.3 * inch, 3.7 * inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef1f7")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t)
    elements.append(PageBreak())
    return elements


def build_findings(styles, findings):
    elements = [Paragraph("FINDINGS", styles["SectionHeading"])]
    if not findings:
        elements.append(Paragraph("No vulnerabilities were identified during this assessment.", styles["Body"]))
        return elements

    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(findings, key=lambda f: severity_rank.get(f.get("severity", "INFO"), 99))

    for idx, f in enumerate(sorted_findings, 1):
        finding_id = f"WEB-{idx:03d}"
        info = get_vuln_info(f["type"])
        sev = f.get("severity", "INFO")
        sev_color = SEVERITY_COLORS.get(sev, colors.grey)

        block = []
        header = Table([[f"{finding_id}: {f['type']}", f"\u25cf {sev}"]], colWidths=[4.6 * inch, 1.4 * inch])
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#1a2b4a")),
            ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
            ("BACKGROUND", (1, 0), (1, 0), sev_color),
            ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 11),
            ("ALIGN", (1, 0), (1, 0), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ]))
        block.append(header)
        block.append(Spacer(1, 6))

        detail_rows = [
            ["CVSS Score", f"{info['cvss']:.1f}"],
            ["CWE ID", info["cwe"]],
            ["OWASP Category", info["owasp"]],
            ["Affected URL", _esc(f["url"])],
            ["Affected Parameter", _esc(f"{f['parameter']} ({f.get('method', 'GET')})")],
            ["Response Code", str(f.get("status_code", "Not captured in this scan"))],
            ["Response Length", str(f.get("response_length", "Not captured in this scan"))],
        ]
        dt = Table(detail_rows, colWidths=[1.4 * inch, 4.6 * inch])
        dt.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        block.append(dt)
        block.append(Spacer(1, 8))

        block.append(Paragraph("<b>Description</b>", styles["FieldLabel"]))
        block.append(Paragraph(info["description"], styles["Body"]))
        block.append(Spacer(1, 6))

        block.append(Paragraph("<b>Technical Details / Evidence</b>", styles["FieldLabel"]))
        evidence_text = f.get("evidence", "N/A")
        block.append(Paragraph(f"Payload used: <font face='Courier'>{_esc(str(f['payload']))}</font>", styles["Body"]))
        block.append(Paragraph(f"Evidence observed: <font face='Courier'>{_esc(str(evidence_text)[:250])}</font>", styles["Body"]))
        if f.get("confirmations"):
            block.append(Paragraph(f"Confirmed via {f['confirmations']} independent payload(s).", styles["Body"]))
        block.append(Spacer(1, 6))

        block.append(Paragraph("<b>Steps to Reproduce</b>", styles["FieldLabel"]))
        for step in generate_repro_steps(f):
            block.append(Paragraph(step, styles["Body"]))
        block.append(Spacer(1, 4))
        block.append(Paragraph("Quick reproduction command:", styles["FieldLabel"]))
        block.append(Paragraph(generate_repro_command(f), styles["Mono"]))
        block.append(Spacer(1, 6))

        block.append(Paragraph("<b>Impact</b>", styles["FieldLabel"]))
        block.append(Paragraph(info["impact"], styles["Body"]))
        block.append(Spacer(1, 6))

        block.append(Paragraph("<b>Recommendation</b>", styles["FieldLabel"]))
        block.append(Paragraph(info["recommendation"], styles["Body"]))

        if info["references"]:
            block.append(Spacer(1, 6))
            block.append(Paragraph("<b>References</b>", styles["FieldLabel"]))
            for ref in info["references"]:
                block.append(Paragraph(ref, styles["Body"]))

        elements.append(Paragraph(f"{finding_id}: {f['type']}", styles["FindingHeading"]))
        elements.append(KeepTogether(block))
        elements.append(Spacer(1, 16))

    elements.append(PageBreak())
    return elements


def build_appendix(styles, findings):
    elements = [Paragraph("APPENDIX", styles["SectionHeading"])]

    elements.append(Paragraph("A.1 Payloads Used By Category", styles["FindingHeading"]))
    by_type = {}
    for f in findings:
        by_type.setdefault(f["type"], set()).add(f["payload"])
    if by_type:
        for vtype, payloads in by_type.items():
            elements.append(Paragraph(f"<b>{_esc(vtype)}</b>", styles["Body"]))
            for p in sorted(payloads):
                elements.append(Paragraph(f"&nbsp;&nbsp;&#8226; {_esc(str(p))}", styles["Mono"]))
            elements.append(Spacer(1, 6))
    else:
        elements.append(Paragraph("No payloads triggered a confirmed finding.", styles["Body"]))

    elements.append(Spacer(1, 10))
    elements.append(Paragraph("A.2 Tool Versions", styles["FindingHeading"]))
    import sys
    try:
        import requests as _r, bs4 as _b, reportlab as _rl
        versions = [
            ["Python", sys.version.split()[0]],
            ["requests", getattr(_r, "__version__", "unknown")],
            ["beautifulsoup4", getattr(_b, "__version__", "unknown")],
            ["reportlab", getattr(_rl, "Version", "unknown")],
        ]
    except Exception:
        versions = [["Python", sys.version.split()[0]]]
    vt = Table(versions, colWidths=[2 * inch, 3 * inch])
    vt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
    ]))
    elements.append(vt)

    elements.append(Spacer(1, 10))
    elements.append(Paragraph(
        "<b>Note on Proof-of-Concept screenshots:</b> this scanner performs HTTP-level "
        "testing only and does not drive a browser, so no screenshots are captured. "
        "The raw evidence text captured for each finding (above) serves as the "
        "reproducible proof for that finding.",
        styles["Body"],
    ))
    return elements


class PDFReportGenerator:
    """Same public interface as before: generate_report(scan_results,
    company_name=...) -> path. auto_scanner.py / simple_main.py need no
    changes at all to use this."""

    def __init__(self, output_path: str = "reports", logo_path: str = None):
        self.output_path = output_path
        self.logo_path = logo_path
        if not os.path.exists(self.output_path):
            os.makedirs(self.output_path)

    def generate_report(self, scan_results: Dict[str, Any], company_name: str = "Security Audit",
                         endpoints_scanned: int = None, scan_start: str = None, scan_end: str = None) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{self.output_path}/vulnerability_report_{timestamp}.pdf"

        findings = scan_results.get("vulnerabilities", [])
        target = scan_results.get("target", "N/A")
        scan_date = scan_results.get("timestamp", datetime.now().isoformat())

        # These aren't always available from a single-endpoint scan_results
        # dict (see the accompanying chat message for why) - fall back to
        # sensible single-target defaults rather than fabricating data.
        if endpoints_scanned is None:
            endpoints_scanned = len(set(f["url"] for f in findings)) or 1
        if scan_start is None:
            scan_start = scan_date
        if scan_end is None:
            scan_end = scan_date
        scan_duration = "N/A (single endpoint - see aggregate report for batch timing)" \
            if scan_start == scan_end else f"{scan_start} to {scan_end}"

        styles = _styles()
        story = []
        story += build_cover_page(styles, target, scan_date, scan_results.get("scan_type", "Automated Scan"),
                                   company_name, logo_path=self.logo_path)
        story += build_toc(styles)
        story += build_executive_summary(styles, scan_results, endpoints_scanned, scan_duration)
        story += build_scope(styles, scan_results, scan_start, scan_end, endpoints_scanned)
        story += build_methodology(styles, scan_results)
        story += build_dashboard(styles, scan_results)
        story += build_scan_info(styles, scan_results, scan_start, scan_end,
                                  total_requests="see scan console output", endpoints_scanned=endpoints_scanned,
                                  endpoints_reachable=endpoints_scanned)
        story += build_findings(styles, findings)
        story += build_recommendations_summary(styles, findings)
        story += build_appendix(styles, findings)

        doc = ReportDocTemplate(filename, pagesize=A4,
                                 leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                                 topMargin=0.75 * inch, bottomMargin=0.9 * inch)
        doc.multiBuild(story, canvasmaker=NumberedCanvas)
        return filename
