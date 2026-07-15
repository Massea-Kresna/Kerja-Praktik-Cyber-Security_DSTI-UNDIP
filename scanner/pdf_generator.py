import os
from datetime import datetime
from fpdf import FPDF

class DSTIReportPDF(FPDF):
    def __init__(self, domain_name, ip_address, scan_date, risk_level, risk_score):
        super().__init__()
        self.domain_name = domain_name
        self.ip_address = ip_address or "-"
        self.scan_date = scan_date or "-"
        self.risk_level = (risk_level or "SAFE").upper()
        self.risk_score = risk_score or 0.0
        self.alias_nb_pages()
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("helvetica", "B", 8)
        self.set_text_color(100, 110, 120)
        self.cell(0, 8, f"Security Assessment Report: {self.domain_name}", border="B", align="L", new_x="LMARGIN", new_y="NEXT")
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Confidential - DSTI UNDIP Security Scanner", align="R")

    def get_severity_colors(self, severity):
        sev = severity.upper()
        if sev == "CRITICAL":
            return (153, 27, 27), (254, 226, 226) # dark red text, light red bg
        elif sev == "HIGH":
            return (239, 68, 68), (254, 242, 242) # red
        elif sev == "MEDIUM":
            return (249, 115, 22), (255, 247, 237) # orange
        elif sev == "LOW":
            return (59, 130, 246), (239, 246, 255) # blue
        else:
            return (34, 197, 94), (240, 253, 250) # green / safe

    def draw_badge(self, text, severity):
        txt_color, bg_color = self.get_severity_colors(severity)
        
        # Save positions
        x = self.get_x()
        y = self.get_y()
        
        # Draw background rect
        self.set_fill_color(*bg_color)
        self.set_text_color(*txt_color)
        self.set_font("helvetica", "B", 9)
        
        # Measure text width
        w = self.get_string_width(text) + 6
        self.rect(x, y + 1, w, 6, "F")
        
        self.set_xy(x + 3, y)
        self.cell(w, 8, text, align="C")
        self.set_xy(x + w, y)

def generate_pdf_report(domain_name, ip_address, scan_date, risk_level, risk_score, open_ports, technologies, vulnerabilities, output_path):
    pdf = DSTIReportPDF(domain_name, ip_address, scan_date, risk_level, risk_score)
    
    # ----------------------------------------------------
    # COVER PAGE
    # ----------------------------------------------------
    pdf.add_page()
    
    # Decorative header strip
    pdf.set_fill_color(11, 31, 58) # #0b1f3a
    pdf.rect(0, 0, 210, 40, "F")
    
    # Title
    pdf.ln(10)
    pdf.set_font("helvetica", "B", 18)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "DSTI UNDIP SECURITY PORTAL", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 10)
    pdf.cell(0, 6, "Automated Security Assessment & Pentest Report", align="C", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(35)
    
    # Report Main Header
    pdf.set_text_color(30, 41, 59) # #1e293b
    pdf.set_font("helvetica", "B", 24)
    pdf.cell(0, 12, "Vulnerability Assessment", align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 12, f"Report: {domain_name}", align="L", new_x="LMARGIN", new_y="NEXT")
    
    # Horizontal line
    pdf.set_draw_color(226, 232, 240) # #e2e8f0
    pdf.line(10, pdf.get_y() + 5, 200, pdf.get_y() + 5)
    pdf.ln(15)
    
    # Meta info table
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(45, 8, "Target Domain:")
    pdf.set_font("helvetica", "", 11)
    pdf.cell(0, 8, domain_name, new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(45, 8, "IP Address:")
    pdf.set_font("helvetica", "", 11)
    pdf.cell(0, 8, ip_address or "-", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(45, 8, "Scan Date:")
    pdf.set_font("helvetica", "", 11)
    pdf.cell(0, 8, scan_date or "-", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(45, 8, "Assessment Risk:")
    pdf.draw_badge(risk_level, risk_level)
    pdf.ln(8)
    
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(45, 8, "Risk Score:")
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(0, 8, f"{risk_score:.1f} / 10.0", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(35)
    
    # Disclaimer / Footer info on Cover
    pdf.set_font("helvetica", "I", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(0, 5, "This report contains confidential information regarding the security posture of the target system. Authorized personnel only. The findings listed in this report are based on automated scanner executions at the time of the scan. Remediations should be tested in a staging environment before being deployed to production.", align="L")
    
    # ----------------------------------------------------
    # DETAILS PAGE
    # ----------------------------------------------------
    pdf.add_page()
    
    # Section 1: Executive Summary
    pdf.set_text_color(11, 31, 58) # #0b1f3a
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "1. Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 41, 59)
    pdf.set_font("helvetica", "", 10)
    
    vuln_count = len(vulnerabilities)
    crit_count = sum(1 for v in vulnerabilities if v.get("severity", "").upper() == "CRITICAL")
    high_count = sum(1 for v in vulnerabilities if v.get("severity", "").upper() == "HIGH")
    med_count = sum(1 for v in vulnerabilities if v.get("severity", "").upper() == "MEDIUM")
    low_count = sum(1 for v in vulnerabilities if v.get("severity", "").upper() == "LOW")
    info_count = sum(1 for v in vulnerabilities if v.get("severity", "").upper() in ["INFO", "SAFE"])
    
    summary_text = (
        f"A security assessment of {domain_name} was performed on {scan_date}. "
        f"The scanner identified a total of {vuln_count} vulnerabilities/anomalies. "
        f"The overall security assessment indicates a {risk_level} risk level, with a calculated score of {risk_score:.1f}/10.0. "
        f"Vulnerability count details: {crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low, and {info_count} Info/Safe items."
    )
    pdf.multi_cell(0, 5, summary_text)
    pdf.ln(8)
    
    # Section 2: Host & Technology Information
    pdf.set_text_color(11, 31, 58)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "2. System Information", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 41, 59)
    
    # Tech Info
    web_server = technologies.get("web_server", "Unknown") if technologies else "Unknown"
    cms = technologies.get("cms", "Unknown") if technologies else "Unknown"
    
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(40, 6, "Web Server:")
    pdf.set_font("helvetica", "", 10)
    pdf.cell(0, 6, web_server, new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(40, 6, "CMS / Platform:")
    pdf.set_font("helvetica", "", 10)
    pdf.cell(0, 6, cms, new_x="LMARGIN", new_y="NEXT")
    
    # Open Ports
    pdf.ln(2)
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(40, 6, "Open Ports:")
    if open_ports:
        ports_str = ", ".join([f"{p.get('port_number') or p.get('port')}/{p.get('service_name') or p.get('service') or 'unknown'}" for p in open_ports])
        pdf.set_font("helvetica", "", 10)
        pdf.multi_cell(0, 6, ports_str)
    else:
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 6, "No open ports detected in common ranges.", new_x="LMARGIN", new_y="NEXT")
        
    pdf.ln(8)
    
    # Section 3: Vulnerabilities Overview Table
    pdf.set_text_color(11, 31, 58)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "3. Vulnerabilities List", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 41, 59)
    
    if vulnerabilities:
        # Table Headers
        pdf.set_fill_color(241, 245, 249)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_font("helvetica", "B", 9)
        pdf.cell(25, 8, "Severity", border=1, align="C", fill=True)
        pdf.cell(115, 8, "Vulnerability / Finding Title", border=1, fill=True)
        pdf.cell(50, 8, "Category / Tool", border=1, align="C", fill=True, new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("helvetica", "", 9)
        # Sort vulnerabilities by severity order
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "SAFE": 5}
        sorted_vulns = sorted(vulnerabilities, key=lambda x: sev_rank.get((x.get("severity") or "").upper(), 99))
        
        for v in sorted_vulns:
            sev = (v.get("severity") or "LOW").upper()
            title = v.get("title") or "Unnamed Finding"
            category = v.get("check_type") or v.get("check") or "Web Scanner"
            
            # Print Severity Badge
            txt_color, bg_color = pdf.get_severity_colors(sev)
            pdf.set_fill_color(*bg_color)
            pdf.set_text_color(*txt_color)
            pdf.set_font("helvetica", "B", 8)
            pdf.cell(25, 8, sev, border=1, align="C", fill=True)
            
            # Print title and category
            pdf.set_text_color(30, 41, 59)
            pdf.set_font("helvetica", "", 9)
            
            # Shorten title if too long to prevent overflow
            if len(title) > 60:
                title = title[:57] + "..."
                
            pdf.cell(115, 8, title, border=1)
            pdf.cell(50, 8, category, border=1, align="C", new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_font("helvetica", "I", 10)
        pdf.cell(0, 8, "No vulnerabilities detected by the automated scanners.", new_x="LMARGIN", new_y="NEXT")
        
    # Section 4: Vulnerability Details
    if vulnerabilities:
        pdf.add_page()
        pdf.set_text_color(11, 31, 58)
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(0, 10, "4. Detailed Finding Logs", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
        
        # Sort again by severity
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "SAFE": 5}
        sorted_vulns = sorted(vulnerabilities, key=lambda x: sev_rank.get((x.get("severity") or "").upper(), 99))
        
        idx = 1
        for v in sorted_vulns:
            sev = (v.get("severity") or "LOW").upper()
            title = v.get("title") or "Unnamed Finding"
            category = v.get("check_type") or v.get("check") or "Web Scanner"
            desc = v.get("description") or v.get("detail") or "No description available."
            recom = v.get("recommendation") or v.get("remediation") or "No recommendation provided."
            
            # Heading for the finding
            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(15, 23, 42) # #0f172a
            pdf.cell(15, 7, f"4.{idx}", align="L")
            pdf.multi_cell(0, 7, title)
            
            # Meta box
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(30, 6, "Severity:")
            pdf.draw_badge(sev, sev)
            pdf.ln(6)
            
            pdf.set_text_color(100, 116, 139)
            pdf.cell(30, 6, "Category:")
            pdf.set_font("helvetica", "", 9)
            pdf.set_text_color(30, 41, 59)
            pdf.cell(0, 6, category, new_x="LMARGIN", new_y="NEXT")
            
            # Description
            pdf.ln(2)
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 5, "Description:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 9.5)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(0, 5, desc)
            pdf.ln(2)
            
            # Recommendation
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 5, "Remediation / Recommendation:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 9.5)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(0, 5, recom)
            
            # Divider line
            pdf.ln(5)
            pdf.set_draw_color(226, 232, 240)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)
            
            idx += 1
            
    # Save the output PDF
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    return True
