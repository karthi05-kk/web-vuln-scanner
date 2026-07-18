#!/usr/bin/env python3
"""
pdf_report_generator.py
========================
Generates a professional, multi-page penetration test report PDF from a list
of finding dictionaries.

Sections produced:
    1. Cover page
    2. Table of Contents (auto page numbers)
    3. Executive Summary
    4. Risk Dashboard (severity pie chart + per-finding CVSS bar chart)
    5. Scope & Methodology
    6. Detailed Findings (one sub-section per finding: CVSS/CWE/OWASP badges,
       description, technical details, evidence, steps to reproduce, impact,
       recommendation, references)
    7. Consolidated Recommendations
    8. Appendix

Drop this file into your scanner project and call generate_report(). The
__main__ block at the bottom shows a worked example using two real DVWA
findings (Command Injection + LFI) so you can run this file directly and see
sample output.

Dependencies: reportlab  (pip install reportlab)
"""

from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, NextPageTemplate,
    Paragraph, Spacer, PageBreak, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend

# ---------------------------------------------------------------------------
# Brand palette / severity colors -- tweak these to match your own branding
# ---------------------------------------------------------------------------
NAVY = colors.HexColor("#0f172a")
SLATE = colors.HexColor("#334155")
LIGHT_SLATE = colors.HexColor("#64748b")
ACCENT = colors.HexColor("#0ea5e9")
PALE_BG = colors.HexColor("#f1f5f9")
BORDER = colors.HexColor("#cbd5e1")
WHITE = colors.white

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#dc2626"),
    "High": colors.HexColor("#ea580c"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#16a34a"),
    "Info": colors.HexColor("#2563eb"),
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

PAGE_W, PAGE_H = letter
MARGIN = 0.75 * inch
CONTENT_W = PAGE_W - 2 * MARGIN


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
def build_styles():
    ss = getSampleStyleSheet()

    ss.add(ParagraphStyle("CoverTitle", fontName="Helvetica-Bold", fontSize=28,
                           leading=34, textColor=WHITE, alignment=TA_CENTER))
    ss.add(ParagraphStyle("CoverSub", fontName="Helvetica", fontSize=13,
                           leading=18, textColor=colors.HexColor("#94a3b8"),
                           alignment=TA_CENTER, spaceBefore=6))
    ss.add(ParagraphStyle("CoverMeta", fontName="Helvetica", fontSize=10.5,
                           leading=16, textColor=WHITE, alignment=TA_LEFT))
    ss.add(ParagraphStyle("CoverMetaLabel", fontName="Helvetica-Bold", fontSize=9,
                           leading=14, textColor=colors.HexColor("#7dd3fc"),
                           alignment=TA_LEFT))

    ss.add(ParagraphStyle("H1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                           fontSize=17, textColor=NAVY, spaceBefore=4, spaceAfter=12,
                           borderPadding=0))
    ss.add(ParagraphStyle("H2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                           fontSize=13, textColor=NAVY, spaceBefore=14, spaceAfter=8))
    ss.add(ParagraphStyle("H3", parent=ss["Heading3"], fontName="Helvetica-Bold",
                           fontSize=10.5, textColor=SLATE, spaceBefore=10, spaceAfter=4))

    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontName="Helvetica",
                           fontSize=9.5, leading=14, textColor=colors.HexColor("#1e293b")))
    ss.add(ParagraphStyle("BodyBullet", parent=ss["Body"], leftIndent=14,
                           bulletIndent=2, spaceAfter=3))
    ss.add(ParagraphStyle("Mono", fontName="Courier", fontSize=9, leading=13,
                           textColor=colors.HexColor("#e2e8f0")))
    ss.add(ParagraphStyle("Small", parent=ss["Body"], fontSize=8, leading=11,
                           textColor=LIGHT_SLATE))
    ss.add(ParagraphStyle("BadgeText", fontName="Helvetica-Bold", fontSize=9.5,
                           textColor=WHITE, alignment=TA_CENTER))
    ss.add(ParagraphStyle("TOCHeading", parent=ss["Body"], fontSize=11,
                           fontName="Helvetica-Bold", textColor=NAVY, leftIndent=0))
    ss.add(ParagraphStyle("KPINum", fontName="Helvetica-Bold", fontSize=22,
                           textColor=NAVY, alignment=TA_CENTER))
    ss.add(ParagraphStyle("KPILabel", fontName="Helvetica", fontSize=8.5,
                           textColor=LIGHT_SLATE, alignment=TA_CENTER))
    return ss


STYLES = build_styles()


# ---------------------------------------------------------------------------
# Small reusable widgets
# ---------------------------------------------------------------------------
def severity_badge(severity, width=1.15 * inch, height=0.26 * inch):
    color = SEVERITY_COLORS.get(severity, LIGHT_SLATE)
    t = Table([[Paragraph(severity.upper(), STYLES["BadgeText"])]],
               colWidths=[width], rowHeights=[height])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 0, color),
    ]))
    return t


def label_badge(text, bg=SLATE, width=1.6 * inch, height=0.26 * inch):
    t = Table([[Paragraph(text, STYLES["BadgeText"])]],
               colWidths=[width], rowHeights=[height])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return t


def kpi_box(number, label, width=1.55 * inch, accent=NAVY):
    inner = Table(
        [[Paragraph(str(number), ParagraphStyle("kn", parent=STYLES["KPINum"], textColor=accent))],
         [Paragraph(label.upper(), STYLES["KPILabel"])]],
        colWidths=[width],
    )
    inner.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), PALE_BG),
    ]))
    return inner


def section_divider():
    t = Table([[""]], colWidths=[CONTENT_W], rowHeights=[1])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.75, BORDER)]))
    return t


def bullet_list(items):
    return [Paragraph(f"&bull;&nbsp;&nbsp;{i}", STYLES["BodyBullet"]) for i in items]


def numbered_list(items):
    out = []
    for idx, i in enumerate(items, 1):
        out.append(Paragraph(f"<b>{idx}.</b>&nbsp;&nbsp;{i}", STYLES["BodyBullet"]))
    return out


def evidence_box(text):
    t = Table([[Paragraph(text.replace("\n", "<br/>"), STYLES["Mono"])]],
               colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def kv_table(rows, col0_w=1.6 * inch):
    data = [[Paragraph(f"<b>{k}</b>", STYLES["Small"]), Paragraph(str(v), STYLES["Body"])]
            for k, v in rows]
    t = Table(data, colWidths=[col0_w, CONTENT_W - col0_w])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PALE_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
def severity_pie_chart(counts):
    present = [(s, counts.get(s, 0)) for s in SEVERITY_ORDER if counts.get(s, 0) > 0]
    if not present:
        present = [("Info", 1)]

    d = Drawing(260, 170)
    pie = Pie()
    pie.x, pie.y = 15, 15
    pie.width, pie.height = 140, 140
    pie.data = [n for _, n in present]
    pie.labels = [f"{s} ({n})" for s, n in present]
    pie.slices.strokeWidth = 1
    pie.slices.strokeColor = WHITE
    for i, (sev, _) in enumerate(present):
        pie.slices[i].fillColor = SEVERITY_COLORS[sev]
    pie.sideLabels = 0
    pie.simpleLabels = 0
    d.add(pie)

    legend = Legend()
    legend.x = 170
    legend.y = 130
    legend.dx = 8
    legend.dy = 8
    legend.fontName = "Helvetica"
    legend.fontSize = 8
    legend.deltay = 12
    legend.colorNamePairs = [(SEVERITY_COLORS[s], f"{s} ({n})") for s, n in present]
    d.add(legend)
    return d


def cvss_bar_chart(findings):
    d = Drawing(CONTENT_W, 190)
    chart = VerticalBarChart()
    chart.x, chart.y = 45, 30
    chart.width = CONTENT_W - 70
    chart.height = 130
    chart.data = [[f["cvss_score"] for f in findings]]
    chart.categoryAxis.categoryNames = [f["id"] for f in findings]
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.angle = 0
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = 10
    chart.valueAxis.valueStep = 2
    chart.valueAxis.labels.fontSize = 7
    chart.barWidth = 14
    chart.groupSpacing = 12
    chart.bars[0].fillColor = ACCENT
    for i, f in enumerate(findings):
        chart.bars[(0, i)].fillColor = SEVERITY_COLORS.get(f["severity"], ACCENT)
    d.add(chart)
    return d


# ---------------------------------------------------------------------------
# Doc template with cover + TOC support
# ---------------------------------------------------------------------------
class ReportDocTemplate(BaseDocTemplate):
    """Adds afterFlowable hooks so H1/H2 paragraphs auto-populate the TOC
    with correct page numbers (two-pass build via multiBuild)."""

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            style = flowable.style.name
            text = flowable.getPlainText()
            if style == "H1":
                self.notify("TOCEntry", (0, text, self.page))
            elif style == "H2":
                self.notify("TOCEntry", (1, text, self.page))


def _cover_background(canvas_obj, doc):
    canvas_obj.saveState()
    canvas_obj.setFillColor(NAVY)
    canvas_obj.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
    canvas_obj.setFillColor(ACCENT)
    canvas_obj.rect(0, PAGE_H - 0.12 * inch, PAGE_W, 0.12 * inch, stroke=0, fill=1)
    canvas_obj.setFillColor(ACCENT)
    canvas_obj.rect(0, 0, PAGE_W, 0.12 * inch, stroke=0, fill=1)
    canvas_obj.restoreState()


def _content_page(canvas_obj, doc, target_url, org):
    canvas_obj.saveState()
    canvas_obj.setStrokeColor(BORDER)
    canvas_obj.setLineWidth(0.6)
    canvas_obj.line(MARGIN, PAGE_H - 0.55 * inch, PAGE_W - MARGIN, PAGE_H - 0.55 * inch)
    canvas_obj.setFont("Helvetica-Bold", 8)
    canvas_obj.setFillColor(SLATE)
    canvas_obj.drawString(MARGIN, PAGE_H - 0.45 * inch, org.upper())
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(LIGHT_SLATE)
    canvas_obj.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.45 * inch, target_url)

    canvas_obj.setStrokeColor(BORDER)
    canvas_obj.line(MARGIN, 0.55 * inch, PAGE_W - MARGIN, 0.55 * inch)
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(LIGHT_SLATE)
    canvas_obj.drawString(MARGIN, 0.38 * inch, "CONFIDENTIAL \u2014 Penetration Test Report")
    canvas_obj.drawRightString(PAGE_W - MARGIN, 0.38 * inch, f"Page {doc.page - 1}")
    canvas_obj.restoreState()


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------
def generate_report(target_url, findings, output_path="pentest_report.pdf",
                     organization="Security Audit", prepared_by="Security Team",
                     scanner_name="Web Vulnerability Scanner v2.0",
                     scan_start=None, scan_end=None, assessment_type=
                     "Authorized Web Application Security Assessment"):
    """
    findings: list of dicts, each with the following keys
        id, title, severity (Critical/High/Medium/Low/Info), cvss_score,
        cvss_vector, cwe, owasp, affected_url, parameter, http_method,
        payload, description, technical_details (list[str]), evidence,
        steps (list[str]), impact (list[str]), recommendations (list[str]),
        references (list[str])
    """
    scan_start = scan_start or datetime.now()
    scan_end = scan_end or scan_start
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f["severity"]))

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    overall_risk = next((s for s in SEVERITY_ORDER if counts[s] > 0), "Info")

    doc = ReportDocTemplate(output_path, pagesize=letter,
                             leftMargin=MARGIN, rightMargin=MARGIN,
                             topMargin=0.9 * inch, bottomMargin=0.8 * inch,
                             title=f"Penetration Test Report - {target_url}")

    cover_frame = Frame(0, 0, PAGE_W, PAGE_H, id="cover", leftPadding=0.9 * inch,
                         rightPadding=0.9 * inch, topPadding=1.6 * inch,
                         bottomPadding=1 * inch)
    content_frame = Frame(MARGIN, 0.8 * inch, CONTENT_W, PAGE_H - 1.7 * inch, id="content")

    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame], onPage=_cover_background),
        PageTemplate(id="Normal", frames=[content_frame],
                      onPage=lambda c, d: _content_page(c, d, target_url, organization)),
    ])

    story = []

    # ---------------- Cover page ----------------
    story.append(Spacer(1, 0.6 * inch))
    story.append(Paragraph("WEB APPLICATION", STYLES["CoverSub"]))
    story.append(Paragraph("PENETRATION TEST REPORT", STYLES["CoverTitle"]))
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(assessment_type, STYLES["CoverSub"]))
    story.append(Spacer(1, 1.6 * inch))

    meta_rows = [
        ["TARGET", target_url],
        ["PREPARED BY", prepared_by],
        ["SCANNER", scanner_name],
        ["ASSESSMENT DATE", scan_start.strftime("%B %d, %Y")],
        ["CLASSIFICATION", "Confidential \u2014 Internal Use Only"],
    ]
    meta_data = []
    for label, val in meta_rows:
        meta_data.append([Paragraph(label, STYLES["CoverMetaLabel"]),
                           Paragraph(val, STYLES["CoverMeta"])])
    meta_t = Table(meta_data, colWidths=[1.7 * inch, 3.8 * inch])
    meta_t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#334155")),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(meta_t)
    story.append(NextPageTemplate("Normal"))
    story.append(PageBreak())

    # ---------------- Table of contents ----------------
    story.append(Paragraph("Table of Contents", STYLES["H1"]))
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(name="TOC0", fontName="Helvetica-Bold", fontSize=10.5,
                        leading=16, textColor=NAVY, leftIndent=0),
        ParagraphStyle(name="TOC1", fontName="Helvetica", fontSize=9.5,
                        leading=14, textColor=SLATE, leftIndent=14),
    ]
    story.append(toc)
    story.append(PageBreak())

    # ---------------- Executive summary ----------------
    story.append(Paragraph("1. Executive Summary", STYLES["H1"]))
    crit = counts["Critical"]
    high = counts["High"]
    story.append(Paragraph(
        f"This engagement was conducted against <b>{target_url}</b> as an "
        f"{assessment_type.lower()}. Testing identified <b>{len(findings)}</b> "
        f"confirmed security finding(s), including <b>{crit}</b> classified as "
        f"Critical and <b>{high}</b> classified as High severity. The overall "
        f"risk posture of the application is assessed as "
        f"<b>{overall_risk.upper()}</b>. "
        f"Immediate remediation of Critical and High findings is recommended before "
        f"the application is exposed to production or untrusted networks.",
        STYLES["Body"]))
    story.append(Spacer(1, 12))

    kpi_row = [kpi_box(len(findings), "Total Findings"),
               kpi_box(crit, "Critical", accent=SEVERITY_COLORS["Critical"]),
               kpi_box(high, "High", accent=SEVERITY_COLORS["High"]),
               kpi_box(counts["Medium"] + counts["Low"], "Medium/Low")]
    kpi_table = Table([kpi_row], colWidths=[1.55 * inch] * 4)
    kpi_table.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story.append(kpi_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Key Findings", STYLES["H3"]))
    story.extend(bullet_list([f"<b>{f['id']}</b> \u2014 {f['title']} ({f['severity']}, "
                               f"CVSS {f['cvss_score']})" for f in findings]))
    story.append(PageBreak())

    # ---------------- Risk dashboard ----------------
    story.append(Paragraph("2. Risk Dashboard", STYLES["H1"]))
    dash_left = [Paragraph("Severity Distribution", STYLES["H3"]), severity_pie_chart(counts)]
    dash_left_t = Table([[c] for c in dash_left], colWidths=[CONTENT_W * 0.48])
    dash_right = [Paragraph("Overall Risk Rating", STYLES["H3"]),
                  Spacer(1, 4), severity_badge(overall_risk, width=1.8 * inch, height=0.4 * inch)]
    dash_right_t = Table([[c] for c in dash_right], colWidths=[CONTENT_W * 0.48])
    two_col = Table([[dash_left_t, dash_right_t]], colWidths=[CONTENT_W * 0.5, CONTENT_W * 0.5])
    two_col.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(two_col)
    story.append(Spacer(1, 10))
    story.append(Paragraph("CVSS Score by Finding", STYLES["H3"]))
    story.append(cvss_bar_chart(findings))
    story.append(PageBreak())

    # ---------------- Scope & methodology ----------------
    story.append(Paragraph("3. Scope & Methodology", STYLES["H1"]))
    story.append(Paragraph("Scope", STYLES["H3"]))
    story.append(kv_table([
        ("Target", target_url),
        ("Assessment Type", assessment_type),
        ("Scan Start", scan_start.strftime("%Y-%m-%d %H:%M:%S")),
        ("Scan End", scan_end.strftime("%Y-%m-%d %H:%M:%S")),
        ("Tooling", scanner_name),
    ]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Methodology", STYLES["H3"]))
    story.extend(bullet_list([
        "Reconnaissance \u2014 enumerate endpoints, parameters, and application surface.",
        "Automated scanning \u2014 fuzz identified parameters for injection classes.",
        "Manual verification \u2014 confirm and safely exploit each candidate finding.",
        "Impact analysis \u2014 assess exploitability, blast radius, and business impact.",
        "Reporting \u2014 document findings, evidence, and remediation guidance.",
    ]))
    story.append(PageBreak())

    # ---------------- Detailed findings ----------------
    story.append(Paragraph("4. Detailed Findings", STYLES["H1"]))
    for f in findings:
        story.append(Paragraph(f"{f['id']} \u2014 {f['title']}", STYLES["H2"]))

        badge_row = [severity_badge(f["severity"]),
                     label_badge(f"CVSS {f['cvss_score']}", bg=SLATE),
                     label_badge(f["cwe"], bg=SLATE),
                     label_badge(f["owasp"], bg=SLATE, width=2.1 * inch)]
        bt = Table([badge_row], colWidths=[1.15 * inch, 1.2 * inch, 1.3 * inch, 2.1 * inch])
        bt.setStyle(TableStyle([("LEFTPADDING", (1, 0), (-1, 0), 6)]))
        story.append(bt)
        story.append(Spacer(1, 8))

        story.append(Paragraph("Description", STYLES["H3"]))
        story.append(Paragraph(f["description"], STYLES["Body"]))

        story.append(Paragraph("Technical Details", STYLES["H3"]))
        story.append(kv_table([
            ("Affected URL", f["affected_url"]),
            ("Parameter", f["parameter"]),
            ("HTTP Method", f["http_method"]),
            ("Payload", f"<font face='Courier'>{f['payload']}</font>"),
        ]))

        if f.get("evidence"):
            story.append(Paragraph("Evidence", STYLES["H3"]))
            story.append(evidence_box(f["evidence"]))

        if f.get("steps"):
            story.append(Paragraph("Steps to Reproduce", STYLES["H3"]))
            story.extend(numbered_list(f["steps"]))

        if f.get("impact"):
            story.append(Paragraph("Impact", STYLES["H3"]))
            story.extend(bullet_list(f["impact"]))

        if f.get("recommendations"):
            story.append(Paragraph("Recommendation", STYLES["H3"]))
            story.extend(bullet_list(f["recommendations"]))

        if f.get("references"):
            story.append(Paragraph("References", STYLES["H3"]))
            story.extend([Paragraph(r, STYLES["Small"]) for r in f["references"]])

        story.append(Spacer(1, 10))
        story.append(section_divider())
        story.append(Spacer(1, 6))

    story.append(PageBreak())

    # ---------------- Consolidated recommendations ----------------
    story.append(Paragraph("5. Consolidated Recommendations", STYLES["H1"]))
    story.append(Paragraph(
        "Findings are prioritized below by severity. Critical and High items "
        "should be remediated before the next release; Medium/Low items should "
        "be tracked in the standard backlog.", STYLES["Body"]))
    story.append(Spacer(1, 8))
    cell_style = ParagraphStyle("RecCell", parent=STYLES["Body"], fontSize=8.5, leading=11)
    header_style = ParagraphStyle("RecHeader", parent=cell_style, textColor=WHITE,
                                   fontName="Helvetica-Bold")
    rows = [[Paragraph(h, header_style) for h in
             ["ID", "Finding", "Severity", "Recommended Action"]]]
    for f in findings:
        first_rec = f.get("recommendations", ["See detailed finding."])[0]
        rows.append([
            Paragraph(f["id"], cell_style),
            Paragraph(f["title"], cell_style),
            Paragraph(f["severity"], ParagraphStyle("sev", parent=cell_style,
                      textColor=SEVERITY_COLORS[f["severity"]], fontName="Helvetica-Bold")),
            Paragraph(first_rec, cell_style),
        ])
    rec_table = Table(rows, colWidths=[0.7 * inch, 1.3 * inch, 0.7 * inch, 3.6 * inch])
    rec_style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    rec_table.setStyle(TableStyle(rec_style))
    story.append(rec_table)
    story.append(PageBreak())

    # ---------------- Appendix ----------------
    story.append(Paragraph("6. Appendix", STYLES["H1"]))
    story.append(Paragraph("CVSS Methodology", STYLES["H3"]))
    story.append(Paragraph(
        "Severity ratings use CVSS v3.1 base scores: Critical 9.0\u201310.0, "
        "High 7.0\u20138.9, Medium 4.0\u20136.9, Low 0.1\u20133.9, Info 0.0.",
        STYLES["Body"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Scan Configuration", STYLES["H3"]))
    story.append(kv_table([
        ("Scanner", scanner_name),
        ("Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Disclaimer", STYLES["H3"]))
    story.append(Paragraph(
        "This report reflects the state of the target application at the time "
        "of testing. It is not exhaustive and does not guarantee the absence of "
        "additional vulnerabilities. Findings were identified within an "
        "authorized lab/test environment.", STYLES["Body"]))

    doc.multiBuild(story)
    return output_path


# ---------------------------------------------------------------------------
# Example usage \u2014 replace with your scanner's real findings
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    target = "http://172.17.0.1:8080/vulnerabilities/exec/"

    findings = [
        {
            "id": "WEB-001",
            "title": "OS Command Injection",
            "severity": "Critical",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-78",
            "owasp": "A03:2021-Injection",
            "affected_url": target,
            "parameter": "ip",
            "http_method": "POST",
            "payload": "; id",
            "description": (
                "The 'ip' parameter is passed into a server-side shell command "
                "(likely a ping/traceroute wrapper) without sanitization. Shell "
                "metacharacters in the input are interpreted by the underlying "
                "OS shell, allowing arbitrary command execution in the context "
                "of the web server process."
            ),
            "evidence": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            "steps": [
                "Browse to the vulnerable page and locate the IP address input field.",
                "Submit a normal value (e.g. 127.0.0.1) and observe the expected ping output.",
                "Submit the payload <font face='Courier'>127.0.0.1; id</font> in the same field.",
                "Observe that the response includes the output of the injected 'id' command, "
                "confirming command execution.",
            ],
            "impact": [
                "Remote Code Execution in the context of the web server user.",
                "Potential pivot point for lateral movement or privilege escalation.",
                "Full compromise of confidentiality, integrity, and availability of the host.",
            ],
            "recommendations": [
                "Never pass user input directly to a shell; use language-native "
                "APIs (e.g. a ping library) instead of shelling out.",
                "If shelling out is unavoidable, use parameterized execution "
                "(e.g. subprocess with a list of args, shell=False) rather than string concatenation.",
                "Validate the input against a strict allowlist (e.g. IPv4/IPv6 regex).",
                "Run the web application with least-privilege OS permissions.",
            ],
            "references": [
                "OWASP: owasp.org/www-community/attacks/Command_Injection",
                "CWE-78: cwe.mitre.org/data/definitions/78.html",
            ],
        },
        {
            "id": "WEB-002",
            "title": "Local File Inclusion (LFI)",
            "severity": "High",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": "CWE-98",
            "owasp": "A03:2021-Injection",
            "affected_url": target.replace("exec", "fi"),
            "parameter": "page",
            "http_method": "GET",
            "payload": "/etc/passwd",
            "description": (
                "The 'page' parameter is used to build a server-side file "
                "include path without validating or restricting the requested "
                "file. An attacker can supply an absolute path to read arbitrary "
                "files readable by the web server process."
            ),
            "evidence": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "steps": [
                "Identify the file-inclusion parameter (e.g. 'page') via the application's navigation.",
                "Replace the expected value with an absolute path: "
                "<font face='Courier'>/etc/passwd</font>.",
                "Observe that the contents of /etc/passwd are reflected in the response.",
            ],
            "impact": [
                "Disclosure of sensitive local files (configuration, credentials, source code).",
                "Potential escalation to Remote Code Execution via log/session poisoning.",
            ],
            "recommendations": [
                "Map page identifiers to an allowlist of known-safe files rather than "
                "including a raw, user-controlled path.",
                "Reject path traversal sequences and absolute paths.",
                "Run the application under a low-privilege account with restricted "
                "filesystem read access.",
            ],
            "references": [
                "OWASP: owasp.org/www-community/attacks/Path_Traversal",
                "CWE-98: cwe.mitre.org/data/definitions/98.html",
            ],
        },
    ]

    out = generate_report(
        target_url=target,
        findings=findings,
        output_path="pentest_report.pdf",
        organization="Security Audit",
        prepared_by="Karthick K",
        scanner_name="Web Vulnerability Scanner v2.0",
    )
    print(f"Report written to {out}")
