from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import sqlite3

DB_PATH = 'data/threat_intel.db'

class PDFReportGenerator:
    
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.cursor = self.conn.cursor()
    
    def close(self):
        if self.conn:
            self.conn.close()
    
    def generate_report(self, output_path):
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        title = Paragraph("Threat Intelligence Analysis Report", title_style)
        story.append(title)
        
        timestamp = Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
        story.append(timestamp)
        story.append(Spacer(1, 0.3*inch))
        
        self.cursor.execute("SELECT COUNT(*) FROM risk_scores")
        total = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE risk_level='High'")
        high = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE risk_level='Medium'")
        medium = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM log_correlations")
        correlations = self.cursor.fetchone()[0]
        
        summary_heading = Paragraph("Executive Summary", heading_style)
        story.append(summary_heading)
        
        summary_data = [
            ['Metric', 'Count'],
            ['Total Indicators', str(total)],
            ['High Risk Indicators', str(high)],
            ['Medium Risk Indicators', str(medium)],
            ['Log Correlations', str(correlations)]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        high_risk_heading = Paragraph("High-Risk Indicators", heading_style)
        story.append(high_risk_heading)
        
        self.cursor.execute("""
            SELECT indicator, type, risk_score, threat_category, country
            FROM risk_scores
            WHERE risk_level='High'
            ORDER BY risk_score DESC
            LIMIT 20
        """)
        
        high_risk_data = [['Indicator', 'Type', 'Score', 'Category', 'Country']]
        for row in self.cursor.fetchall():
            high_risk_data.append([str(row[0])[:40], row[1], str(row[2]), row[3], row[4]])
        
        if len(high_risk_data) > 1:
            high_risk_table = Table(high_risk_data, colWidths=[2*inch, 0.8*inch, 0.7*inch, 1.5*inch, 0.8*inch])
            high_risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fee2e2')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(high_risk_table)
        else:
            story.append(Paragraph("No high-risk indicators found", styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        category_heading = Paragraph("Threat Category Distribution", heading_style)
        story.append(category_heading)
        
        self.cursor.execute("""
            SELECT threat_category, COUNT(*) as count
            FROM risk_scores
            GROUP BY threat_category
            ORDER BY count DESC
            LIMIT 10
        """)
        
        category_data = [['Category', 'Count', 'Percentage']]
        total_count = max(total, 1)
        for row in self.cursor.fetchall():
            percentage = (row[1] / total_count) * 100
            category_data.append([row[0], str(row[1]), f"{percentage:.1f}%"])
        
        if len(category_data) > 1:
            category_table = Table(category_data, colWidths=[3*inch, 1*inch, 1*inch])
            category_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(category_table)
        
        story.append(Spacer(1, 0.3*inch))
        
        mitre_heading = Paragraph("MITRE ATT&CK Techniques", heading_style)
        story.append(mitre_heading)
        
        self.cursor.execute("""
            SELECT mitre_technique, mitre_tactic, COUNT(*) as count
            FROM mitre_mapping
            GROUP BY mitre_technique, mitre_tactic
            ORDER BY count DESC
            LIMIT 15
        """)
        
        mitre_data = [['Technique', 'Tactic', 'Count']]
        for row in self.cursor.fetchall():
            mitre_data.append([row[0], row[1], str(row[2])])
        
        if len(mitre_data) > 1:
            mitre_table = Table(mitre_data, colWidths=[3*inch, 2*inch, 1*inch])
            mitre_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(mitre_table)
        
        story.append(Spacer(1, 0.3*inch))
        
        recommendations_heading = Paragraph("Security Recommendations", heading_style)
        story.append(recommendations_heading)
        
        recommendations = [
            "1. Block all high-risk IP addresses at perimeter firewalls",
            "2. Enable DNS filtering for malicious domains",
            "3. Update endpoint protection signatures",
            "4. Review logs for indicators of compromise",
            "5. Conduct threat hunting for identified MITRE ATT&CK techniques",
            "6. Monitor for command and control communication patterns",
            "7. Implement network segmentation",
            "8. Review and update incident response procedures"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        doc.build(story)
        return output_path

if __name__ == '__main__':
    gen = PDFReportGenerator()
    gen.generate_report('data/threat_report.pdf')
    gen.close()
    print("PDF report generated successfully")
