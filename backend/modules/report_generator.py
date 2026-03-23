import json
import csv
import os
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_report(scan_id: str, data: dict, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return generate_json(scan_id, data)
    elif fmt == "csv":
        return generate_csv(scan_id, data)
    elif fmt == "pdf":
        return generate_pdf(scan_id, data)
    else:
        return generate_json(scan_id, data)

def generate_json(scan_id: str, data: dict) -> str:
    path = os.path.join(REPORTS_DIR, f"webguard_{scan_id[:8]}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path

def generate_csv(scan_id: str, data: dict) -> str:
    path = os.path.join(REPORTS_DIR, f"webguard_{scan_id[:8]}.csv")
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow(["WebGuard Scan Report"])
        writer.writerow(["Domain", data.get("domain", "")])
        writer.writerow(["Timestamp", data.get("timestamp", "")])
        writer.writerow(["Risk Score", f"{data.get('risk_score', 0)}/100"])
        writer.writerow(["Risk Level", data.get("risk_level", "")])
        writer.writerow([])

        writer.writerow(["=== SUBDOMAINS ==="])
        writer.writerow(["Subdomain", "IP", "Status"])
        for s in data.get("subdomains", []):
            writer.writerow([s.get("subdomain"), s.get("ip"), s.get("status")])
        writer.writerow([])

        writer.writerow(["=== GOOGLE DORK FINDINGS ==="])
        writer.writerow(["Type", "URL", "Severity"])
        for d in data.get("google_dorks", []):
            writer.writerow([d.get("dork_type"), d.get("url"), d.get("severity")])
        writer.writerow([])

        writer.writerow(["=== OPEN PORTS (Shodan) ==="])
        for svc in data.get("shodan", {}).get("services", []):
            writer.writerow([svc.get("port"), svc.get("service"), svc.get("version")])
        writer.writerow([])

        writer.writerow(["=== S3 BUCKET EXPOSURE ==="])
        writer.writerow(["Bucket", "URL", "Status", "Severity"])
        for b in data.get("s3_buckets", []):
            writer.writerow([b.get("bucket_name"), b.get("url"), b.get("status"), b.get("severity")])
        writer.writerow([])

        writer.writerow(["=== HIDDEN PATHS FOUND ==="])
        writer.writerow(["Path", "Status Code", "Severity"])
        for p in data.get("hidden_paths", []):
            writer.writerow([p.get("url"), p.get("status_code"), p.get("severity")])
        writer.writerow([])

        writer.writerow(["=== CVE VULNERABILITIES ==="])
        writer.writerow(["CVE ID", "CVSS Score", "Severity", "Description"])
        for c in data.get("cves", []):
            writer.writerow([c.get("cve_id"), c.get("cvss_score"), c.get("severity"), c.get("description", "")[:150]])
        writer.writerow([])

        writer.writerow(["=== RECOMMENDATIONS ==="])
        for rec in data.get("risk_breakdown", {}).get("recommendations", []):
            writer.writerow([rec])

    return path

def generate_pdf(scan_id: str, data: dict) -> str:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        path = os.path.join(REPORTS_DIR, f"webguard_{scan_id[:8]}.pdf")
        doc = SimpleDocTemplate(path, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        story = []
        styles = getSampleStyleSheet()

        # Define colors
        dark_bg = colors.HexColor("#0d1117")
        accent = colors.HexColor("#00ff88")
        danger = colors.HexColor("#ff4444")
        warning = colors.HexColor("#ffaa00")
        info = colors.HexColor("#4488ff")

        # Header
        title_style = ParagraphStyle("title", fontSize=22, textColor=accent,
                                     spaceAfter=4, fontName="Helvetica-Bold", alignment=TA_CENTER)
        sub_style = ParagraphStyle("sub", fontSize=10, textColor=colors.grey,
                                   spaceAfter=2, alignment=TA_CENTER)
        section_style = ParagraphStyle("section", fontSize=13, textColor=accent,
                                       spaceBefore=12, spaceAfter=6, fontName="Helvetica-Bold")
        normal_style = ParagraphStyle("norm", fontSize=9, textColor=colors.black, spaceAfter=3)

        story.append(Paragraph("🛡 WebGuard Security Report", title_style))
        story.append(Paragraph(f"Domain: {data.get('domain', '')}", sub_style))
        story.append(Paragraph(f"Generated: {data.get('timestamp', '')}", sub_style))
        story.append(HRFlowable(width="100%", thickness=1, color=accent, spaceAfter=10))

        # Risk Score Summary
        risk_score = data.get("risk_score", 0)
        risk_level = data.get("risk_level", "")
        risk_color = danger if risk_level in ("CRITICAL", "HIGH") else (warning if risk_level == "MEDIUM" else info)

        summary_data = [
            ["Risk Score", "Risk Level", "Subdomains", "CVEs Found", "Open Ports", "Exposed Paths"],
            [
                f"{risk_score}/100",
                risk_level,
                str(len(data.get("subdomains", []))),
                str(len(data.get("cves", []))),
                str(len(data.get("shodan", {}).get("open_ports", []))),
                str(len(data.get("hidden_paths", [])))
            ]
        ]
        t = Table(summary_data, colWidths=[2.8*cm]*6)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
            ("TEXTCOLOR", (0, 0), (-1, 0), accent),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f0f4f8"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWHEIGHT", (0, 0), (-1, -1), 20),
            ("TEXTCOLOR", (0, 1), (0, 1), risk_color),
            ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

        def add_section(title, rows, headers):
            story.append(Paragraph(title, section_style))
            if not rows:
                story.append(Paragraph("No findings.", normal_style))
                return
            table_data = [headers] + rows
            col_count = len(headers)
            col_w = 17 / col_count * cm
            tbl = Table(table_data, colWidths=[col_w]*col_count, repeatRows=1)
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                ("TEXTCOLOR", (0, 0), (-1, 0), accent),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("ROWHEIGHT", (0, 0), (-1, -1), 18),
                ("WORDWRAP", (0, 0), (-1, -1), True),
            ]))
            story.append(tbl)
            story.append(Spacer(1, 8))

        # Subdomains
        sub_rows = [[s.get("subdomain", ""), s.get("ip", "N/A"), s.get("status", "")]
                    for s in data.get("subdomains", [])]
        add_section("Subdomain Enumeration", sub_rows, ["Subdomain", "IP Address", "Status"])

        # Google Dorks
        dork_rows = [[d.get("dork_type", ""), d.get("url", "")[:60], d.get("severity", "")]
                     for d in data.get("google_dorks", [])]
        add_section("Google Dorking Findings", dork_rows, ["Type", "URL", "Severity"])

        # Open Ports
        svc_rows = [[str(s.get("port", "")), s.get("service", ""), s.get("version", "")]
                    for s in data.get("shodan", {}).get("services", [])]
        add_section("Open Ports & Services (Shodan)", svc_rows, ["Port", "Service", "Version"])

        # S3 Buckets
        bucket_rows = [[b.get("bucket_name", ""), b.get("status", ""), b.get("severity", "")]
                       for b in data.get("s3_buckets", [])]
        add_section("Cloud Bucket Exposure (S3)", bucket_rows, ["Bucket Name", "Status", "Severity"])

        # Hidden Paths
        path_rows = [[p.get("path", ""), str(p.get("status_code", "")), p.get("severity", "")]
                     for p in data.get("hidden_paths", [])]
        add_section("Hidden Paths Discovered", path_rows, ["Path", "Status Code", "Severity"])

        # CVEs
        cve_rows = [[c.get("cve_id", ""), str(c.get("cvss_score", "")), c.get("severity", ""),
                     c.get("description", "")[:80]]
                    for c in data.get("cves", [])]
        add_section("CVE Vulnerability Mapping", cve_rows, ["CVE ID", "CVSS", "Severity", "Description"])

        # Recommendations
        recs = data.get("risk_breakdown", {}).get("recommendations", [])
        if recs:
            story.append(Paragraph("Security Recommendations", section_style))
            for i, rec in enumerate(recs, 1):
                story.append(Paragraph(f"{i}. {rec}", normal_style))

        doc.build(story)
        return path

    except ImportError:
        # Fallback to JSON if reportlab not installed
        return generate_json(scan_id, data)
