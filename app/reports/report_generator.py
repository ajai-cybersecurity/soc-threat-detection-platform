"""
SOC Report Generator – PDF (ReportLab) and CSV (Pandas) reports.
"""
import os
import csv
import json
import uuid
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# SOC Color Palette
SOC_DARK    = colors.HexColor('#0d1117')
SOC_BLUE    = colors.HexColor('#1f6feb')
SOC_RED     = colors.HexColor('#f85149')
SOC_ORANGE  = colors.HexColor('#d29922')
SOC_GREEN   = colors.HexColor('#3fb950')
SOC_GRAY    = colors.HexColor('#8b949e')
SOC_LIGHT   = colors.HexColor('#c9d1d9')
SOC_SURFACE = colors.HexColor('#161b22')


def _build_styles():
    styles = getSampleStyleSheet()
    custom = {
        'Title': ParagraphStyle('SOCTitle', fontSize=22, fontName='Helvetica-Bold',
                                 textColor=SOC_BLUE, alignment=TA_CENTER, spaceAfter=6),
        'Subtitle': ParagraphStyle('SOCSubtitle', fontSize=12, fontName='Helvetica',
                                    textColor=SOC_GRAY, alignment=TA_CENTER, spaceAfter=20),
        'H1': ParagraphStyle('SOCH1', fontSize=14, fontName='Helvetica-Bold',
                               textColor=SOC_BLUE, spaceBefore=16, spaceAfter=8),
        'H2': ParagraphStyle('SOCH2', fontSize=11, fontName='Helvetica-Bold',
                               textColor=SOC_LIGHT, spaceBefore=10, spaceAfter=6),
        'Body': ParagraphStyle('SOCBody', fontSize=9, fontName='Helvetica',
                                textColor=colors.black, spaceAfter=4, leading=14),
        'Critical': ParagraphStyle('Critical', fontSize=9, fontName='Helvetica-Bold',
                                    textColor=SOC_RED),
        'High':     ParagraphStyle('High', fontSize=9, fontName='Helvetica-Bold',
                                    textColor=SOC_ORANGE),
        'Medium':   ParagraphStyle('Medium', fontSize=9, fontName='Helvetica-Bold',
                                    textColor=colors.HexColor('#e3b341')),
        'Low':      ParagraphStyle('Low', fontSize=9, fontName='Helvetica',
                                    textColor=SOC_GREEN),
    }
    return custom


def generate_pdf_report(data: dict, output_path: str) -> str:
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = _build_styles()
    story  = []

    # ── Cover ──────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph('SOC SECURITY REPORT', styles['Title']))
    story.append(Paragraph('Automated Log Analyzer & Threat Detection Platform', styles['Subtitle']))
    story.append(HRFlowable(width='100%', thickness=2, color=SOC_BLUE))
    story.append(Spacer(1, 0.3*cm))

    meta_data = [
        ['Report Generated:', datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')],
        ['Report Period:',    f"{data.get('date_from', 'N/A')} – {data.get('date_to', 'N/A')}"],
        ['Organization:',     data.get('organization', 'Default Organization')],
        ['Classification:',   'CONFIDENTIAL – SOC INTERNAL'],
    ]
    meta_table = Table(meta_data, colWidths=[5*cm, 10*cm])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('TEXTCOLOR', (0,0), (0,-1), SOC_GRAY),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width='100%', thickness=1, color=SOC_GRAY))

    # ── Executive Summary ──────────────────────────────────────
    story.append(Paragraph('1. EXECUTIVE SUMMARY', styles['H1']))
    stats = data.get('stats', {})
    summary_text = (
        f"During the analysis period, the SOC platform processed <b>{stats.get('total_logs', 0):,}</b> "
        f"log entries across <b>{stats.get('log_sources', 0)}</b> log sources. "
        f"The detection engine identified <b>{stats.get('total_alerts', 0)}</b> security alerts, "
        f"of which <b>{stats.get('critical_alerts', 0)}</b> were classified as CRITICAL and "
        f"<b>{stats.get('high_alerts', 0)}</b> as HIGH severity. "
        f"A total of <b>{stats.get('total_incidents', 0)}</b> security incidents were created "
        f"for investigation. {stats.get('unique_ips', 0)} unique source IP addresses were observed."
    )
    story.append(Paragraph(summary_text, styles['Body']))

    # ── Threat Statistics ──────────────────────────────────────
    story.append(Paragraph('2. THREAT OVERVIEW', styles['H1']))
    sev_data = [
        ['Severity', 'Count', 'Percentage'],
        ['CRITICAL', str(stats.get('critical_alerts', 0)), _pct(stats.get('critical_alerts', 0), stats.get('total_alerts', 1))],
        ['HIGH',     str(stats.get('high_alerts', 0)),     _pct(stats.get('high_alerts', 0), stats.get('total_alerts', 1))],
        ['MEDIUM',   str(stats.get('medium_alerts', 0)),   _pct(stats.get('medium_alerts', 0), stats.get('total_alerts', 1))],
        ['LOW',      str(stats.get('low_alerts', 0)),      _pct(stats.get('low_alerts', 0), stats.get('total_alerts', 1))],
    ]
    sev_table = Table(sev_data, colWidths=[5*cm, 4*cm, 4*cm])
    sev_table.setStyle(_severity_table_style())
    story.append(sev_table)
    story.append(Spacer(1, 0.4*cm))

    # ── Top Threats ────────────────────────────────────────────
    story.append(Paragraph('3. TOP THREAT TYPES', styles['H1']))
    top_threats = data.get('top_threats', [])
    if top_threats:
        threat_rows = [['Threat Type', 'Count', 'Severity']]
        for t in top_threats[:10]:
            threat_rows.append([t.get('threat_type', ''), str(t.get('count', 0)), t.get('severity', '')])
        threat_table = Table(threat_rows, colWidths=[8*cm, 3*cm, 4*cm])
        threat_table.setStyle(_base_table_style())
        story.append(threat_table)

    # ── Top Attack Sources ─────────────────────────────────────
    story.append(Paragraph('4. TOP ATTACK SOURCES', styles['H1']))
    top_ips = data.get('top_ips', [])
    if top_ips:
        ip_rows = [['Source IP', 'Alert Count', 'Threat Types']]
        for ip in top_ips[:10]:
            ip_rows.append([ip.get('source_ip', ''), str(ip.get('count', 0)), ip.get('types', '')])
        ip_table = Table(ip_rows, colWidths=[5*cm, 3*cm, 7*cm])
        ip_table.setStyle(_base_table_style())
        story.append(ip_table)

    # ── Incidents ──────────────────────────────────────────────
    story.append(Paragraph('5. ACTIVE INCIDENTS', styles['H1']))
    incidents = data.get('incidents', [])
    if incidents:
        inc_rows = [['Incident ID', 'Title', 'Severity', 'Status', 'Created']]
        for inc in incidents[:20]:
            inc_rows.append([
                inc.get('incident_id', ''), inc.get('title', '')[:40],
                inc.get('severity', ''), inc.get('status', ''),
                str(inc.get('created_at', ''))[:16]
            ])
        inc_table = Table(inc_rows, colWidths=[3*cm, 6*cm, 2.5*cm, 2.5*cm, 3.5*cm])
        inc_table.setStyle(_base_table_style())
        story.append(inc_table)

    # ── Recommendations ────────────────────────────────────────
    story.append(Paragraph('6. RECOMMENDATIONS', styles['H1']))
    recommendations = data.get('recommendations', _default_recommendations(stats))
    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f'{i}. {rec}', styles['Body']))

    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width='100%', thickness=1, color=SOC_GRAY))
    story.append(Paragraph(
        'This report was generated automatically by SOC Platform. CONFIDENTIAL.',
        ParagraphStyle('Footer', fontSize=7, textColor=SOC_GRAY, alignment=TA_CENTER)
    ))

    doc.build(story)
    return output_path


def generate_csv_report(alerts: list, output_path: str) -> str:
    if not alerts:
        return None
    fieldnames = ['alert_id', 'timestamp', 'title', 'threat_type', 'severity',
                  'source_ip', 'username', 'hostname', 'mitre_tactic', 'mitre_technique',
                  'description', 'status']
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for a in alerts:
            writer.writerow({k: a.get(k, '') for k in fieldnames})
    return output_path


def _pct(val, total):
    return f'{(val / max(total, 1)) * 100:.1f}%'


def _default_recommendations(stats):
    recs = []
    if stats.get('critical_alerts', 0) > 0:
        recs.append('IMMEDIATE: Investigate all CRITICAL alerts within 1 hour. Escalate to Incident Response team.')
    if stats.get('brute_force_count', 0) > 0:
        recs.append('Implement account lockout policies and MFA for all privileged accounts.')
    recs.append('Review firewall rules and block identified malicious source IPs.')
    recs.append('Enable enhanced logging on critical systems including Windows Event Forwarding.')
    recs.append('Conduct threat hunting exercises based on identified MITRE ATT&CK techniques.')
    recs.append('Patch management: Ensure all systems are up-to-date to reduce attack surface.')
    return recs


def _base_table_style():
    return TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  SOC_BLUE),
        ('TEXTCOLOR',     (0,0), (-1,0),  colors.white),
        ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [colors.white, colors.HexColor('#f6f8fa')]),
        ('GRID',          (0,0), (-1,-1), 0.5, SOC_GRAY),
        ('PADDING',       (0,0), (-1,-1), 4),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ])


def _severity_table_style():
    style = _base_table_style()
    style.add('TEXTCOLOR', (0,1), (0,1), SOC_RED)     # CRITICAL
    style.add('TEXTCOLOR', (0,2), (0,2), SOC_ORANGE)  # HIGH
    style.add('FONTNAME',  (0,1), (0,2), 'Helvetica-Bold')
    return style
