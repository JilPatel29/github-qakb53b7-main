import sqlite3
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER
import os

DB_PATH = 'data/threat_intel.db'

class DailyReportGenerator:

    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.cursor = self.conn.cursor()
        self.report_date = datetime.now()

    def close(self):
        if self.conn:
            self.conn.close()

    def get_daily_statistics(self):
        stats = {}

        self.cursor.execute('''
            SELECT COUNT(*) FROM risk_scores
            WHERE DATE(created_at) = DATE('now')
        ''')
        stats['new_indicators_today'] = self.cursor.fetchone()[0]

        self.cursor.execute('''
            SELECT COUNT(*) FROM risk_scores
            WHERE risk_level = 'High'
            AND DATE(created_at) = DATE('now')
        ''')
        stats['high_risk_today'] = self.cursor.fetchone()[0]

        self.cursor.execute('''
            SELECT COUNT(*) FROM log_correlations
            WHERE DATE(created_at) = DATE('now')
        ''')
        stats['log_matches_today'] = self.cursor.fetchone()[0]

        self.cursor.execute('''
            SELECT COUNT(*) FROM alerts
            WHERE DATE(created_at) = DATE('now')
        ''')
        stats['alerts_today'] = self.cursor.fetchone()[0]

        self.cursor.execute('''
            SELECT COUNT(*) FROM scan_logs
            WHERE DATE(scan_timestamp) = DATE('now')
        ''')
        stats['scans_today'] = self.cursor.fetchone()[0]

        self.cursor.execute('''
            SELECT COUNT(*) FROM risk_scores
        ''')
        stats['total_indicators'] = self.cursor.fetchone()[0]

        self.cursor.execute('''
            SELECT COUNT(*) FROM risk_scores
            WHERE risk_level = 'High'
        ''')
        stats['total_high_risk'] = self.cursor.fetchone()[0]

        return stats

    def get_top_threats_today(self, limit=10):
        self.cursor.execute('''
            SELECT indicator, type, risk_score, risk_level, threat_category, country
            FROM risk_scores
            WHERE DATE(created_at) = DATE('now')
            ORDER BY risk_score DESC
            LIMIT ?
        ''', (limit,))

        return self.cursor.fetchall()

    def get_alerts_today(self):
        self.cursor.execute('''
            SELECT severity, title, description, created_at, acknowledged
            FROM alerts
            WHERE DATE(created_at) = DATE('now')
            ORDER BY created_at DESC
        ''')

        return self.cursor.fetchall()

    def get_scan_summary(self):
        self.cursor.execute('''
            SELECT scan_timestamp, ips_found, domains_found,
                   urls_found, hashes_found, total_iocs
            FROM scan_logs
            WHERE DATE(scan_timestamp) = DATE('now')
            ORDER BY scan_timestamp DESC
        ''')

        return self.cursor.fetchall()

    def get_mitre_summary(self):
        self.cursor.execute('''
            SELECT mitre_technique, mitre_tactic, COUNT(*) as count
            FROM mitre_mapping
            WHERE DATE(created_at) = DATE('now')
            GROUP BY mitre_technique, mitre_tactic
            ORDER BY count DESC
            LIMIT 10
        ''')

        return self.cursor.fetchall()

    def generate_console_report(self):
        print("="*80)
        print(f"DAILY THREAT INTELLIGENCE REPORT - {self.report_date.strftime('%Y-%m-%d')}")
        print("="*80)

        stats = self.get_daily_statistics()

        print("\n📊 DAILY SUMMARY")
        print("-"*80)
        print(f"New Indicators Today:        {stats['new_indicators_today']}")
        print(f"High-Risk Indicators:        {stats['high_risk_today']}")
        print(f"Log Correlations:            {stats['log_matches_today']}")
        print(f"Security Alerts:             {stats['alerts_today']}")
        print(f"DVWA Scans Performed:        {stats['scans_today']}")
        print(f"\nTotal Indicators in DB:      {stats['total_indicators']}")
        print(f"Total High-Risk:             {stats['total_high_risk']}")

        print("\n🎯 TOP THREATS TODAY")
        print("-"*80)
        threats = self.get_top_threats_today(5)
        if threats:
            for i, threat in enumerate(threats, 1):
                print(f"{i}. {threat[0][:50]} | {threat[1]} | Score: {threat[2]:.1f} | {threat[4]}")
        else:
            print("No new threats detected today")

        print("\n🚨 SECURITY ALERTS TODAY")
        print("-"*80)
        alerts = self.get_alerts_today()
        if alerts:
            for alert in alerts[:5]:
                status = "✓ ACK" if alert[4] else "⚠ NEW"
                print(f"[{alert[0]}] {status} - {alert[1]}")
                print(f"    Time: {alert[3]}")
        else:
            print("No security alerts today")

        print("\n🔍 DVWA SCAN SUMMARY")
        print("-"*80)
        scans = self.get_scan_summary()
        if scans:
            for scan in scans:
                print(f"Scan Time: {scan[0]}")
                print(f"  IPs: {scan[1]} | Domains: {scan[2]} | URLs: {scan[3]} | Hashes: {scan[4]}")
                print(f"  Total IOCs: {scan[5]}")
        else:
            print("No DVWA scans performed today")

        print("\n⚔️ MITRE ATT&CK DETECTIONS")
        print("-"*80)
        mitre = self.get_mitre_summary()
        if mitre:
            for technique in mitre[:5]:
                print(f"{technique[0]} ({technique[1]}): {technique[2]} detections")
        else:
            print("No MITRE ATT&CK techniques detected today")

        print("\n✅ RECOMMENDATIONS")
        print("-"*80)
        if stats['high_risk_today'] > 0:
            print("• Review and block high-risk indicators immediately")
        if stats['alerts_today'] > 5:
            print("• Multiple alerts detected - investigate common patterns")
        if stats['log_matches_today'] > 0:
            print("• Log correlations found - review network activity")
        print("• Continue automated DVWA scans")
        print("• Update threat intelligence feeds")
        print("• Review incident response procedures")

        print("\n" + "="*80)
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)

    def generate_pdf_report(self, output_path=None):
        if output_path is None:
            os.makedirs('reports', exist_ok=True)
            output_path = f"reports/daily_report_{self.report_date.strftime('%Y%m%d')}.pdf"

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=20,
            alignment=TA_CENTER
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=10,
            spaceBefore=10
        )

        title = Paragraph(f"Daily Threat Intelligence Report", title_style)
        story.append(title)

        date_para = Paragraph(f"Report Date: {self.report_date.strftime('%Y-%m-%d')}", styles['Normal'])
        story.append(date_para)
        story.append(Spacer(1, 0.3*inch))

        stats = self.get_daily_statistics()

        summary_heading = Paragraph("Executive Summary", heading_style)
        story.append(summary_heading)

        summary_data = [
            ['Metric', 'Today', 'Total'],
            ['New Indicators', str(stats['new_indicators_today']), str(stats['total_indicators'])],
            ['High-Risk Indicators', str(stats['high_risk_today']), str(stats['total_high_risk'])],
            ['Log Correlations', str(stats['log_matches_today']), '-'],
            ['Security Alerts', str(stats['alerts_today']), '-'],
            ['DVWA Scans', str(stats['scans_today']), '-']
        ]

        summary_table = Table(summary_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))

        threats_heading = Paragraph("Top Threats Detected Today", heading_style)
        story.append(threats_heading)

        threats = self.get_top_threats_today(10)
        threats_data = [['Indicator', 'Type', 'Score', 'Category', 'Country']]

        for threat in threats:
            threats_data.append([
                str(threat[0])[:35],
                threat[1],
                f"{threat[2]:.0f}",
                threat[4],
                threat[5]
            ])

        if len(threats_data) > 1:
            threats_table = Table(threats_data, colWidths=[2*inch, 0.7*inch, 0.6*inch, 1.5*inch, 0.8*inch])
            threats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fee2e2')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(threats_table)
        else:
            story.append(Paragraph("No new threats detected today", styles['Normal']))

        story.append(Spacer(1, 0.3*inch))

        alerts_heading = Paragraph("Security Alerts", heading_style)
        story.append(alerts_heading)

        alerts = self.get_alerts_today()
        if alerts:
            alerts_data = [['Severity', 'Title', 'Status']]
            for alert in alerts[:10]:
                status = "Acknowledged" if alert[4] else "New"
                alerts_data.append([alert[0], alert[1][:50], status])

            alerts_table = Table(alerts_data, colWidths=[1*inch, 3.5*inch, 1.2*inch])
            alerts_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(alerts_table)
        else:
            story.append(Paragraph("No security alerts generated today", styles['Normal']))

        doc.build(story)
        print(f"\n[PDF] Report saved to: {output_path}")

        return output_path

def generate_daily_report():
    print("="*70)
    print("DAILY REPORT GENERATOR")
    print("="*70)

    generator = DailyReportGenerator()

    generator.generate_console_report()

    pdf_path = generator.generate_pdf_report()

    generator.close()

    print(f"\n[COMPLETE] Daily report generation completed")
    print("="*70)

    return pdf_path

if __name__ == '__main__':
    generate_daily_report()
