"""
Threat Intelligence – VirusTotal, AbuseIPDB, AlienVault OTX integrations.
"""
import json
import requests
from datetime import datetime, timedelta
from flask import current_app


class ThreatIntelClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SOC-Platform/1.0'})

    # ─────────────── VIRUSTOTAL ─────────────────────────────
    def check_virustotal(self, indicator: str, itype: str = 'ip') -> dict:
        api_key = current_app.config.get('VIRUSTOTAL_API_KEY', '')
        if not api_key or api_key == 'your_virustotal_api_key_here':
            return {'error': 'VirusTotal API key not configured', 'source': 'virustotal'}
        try:
            endpoints = {
                'ip':     f'https://www.virustotal.com/api/v3/ip_addresses/{indicator}',
                'domain': f'https://www.virustotal.com/api/v3/domains/{indicator}',
                'hash':   f'https://www.virustotal.com/api/v3/files/{indicator}',
                'url':    f'https://www.virustotal.com/api/v3/urls/{indicator}',
            }
            url = endpoints.get(itype, endpoints['ip'])
            resp = self.session.get(url, headers={'x-apikey': api_key}, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                malicious  = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total      = sum(stats.values()) or 1
                score = round((malicious + suspicious * 0.5) / total * 100, 1)
                return {
                    'source':          'virustotal',
                    'indicator':       indicator,
                    'is_malicious':    malicious > 0,
                    'reputation_score': score,
                    'malicious_votes': malicious,
                    'total_engines':   total,
                    'country':         data.get('country', ''),
                    'asn':             data.get('asn', ''),
                    'tags':            ', '.join(data.get('tags', [])),
                    'raw_response':    json.dumps(stats),
                }
            return {'error': f'HTTP {resp.status_code}', 'source': 'virustotal'}
        except Exception as e:
            return {'error': str(e), 'source': 'virustotal'}

    # ─────────────── ABUSEIPDB ──────────────────────────────
    def check_abuseipdb(self, ip: str) -> dict:
        api_key = current_app.config.get('ABUSEIPDB_API_KEY', '')
        if not api_key or api_key == 'your_abuseipdb_api_key_here':
            return {'error': 'AbuseIPDB API key not configured', 'source': 'abuseipdb'}
        try:
            resp = self.session.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': api_key, 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True},
                timeout=10
            )
            if resp.status_code == 200:
                d = resp.json().get('data', {})
                score = d.get('abuseConfidenceScore', 0)
                return {
                    'source':           'abuseipdb',
                    'indicator':        ip,
                    'is_malicious':     score >= 50,
                    'reputation_score': score,
                    'country':          d.get('countryCode', ''),
                    'isp':              d.get('isp', ''),
                    'domain':           d.get('domain', ''),
                    'total_reports':    d.get('totalReports', 0),
                    'last_reported':    str(d.get('lastReportedAt', '')),
                    'tags':             '',
                    'raw_response':     json.dumps({'score': score, 'reports': d.get('totalReports')}),
                }
            return {'error': f'HTTP {resp.status_code}', 'source': 'abuseipdb'}
        except Exception as e:
            return {'error': str(e), 'source': 'abuseipdb'}

    # ─────────────── ALIENVAULT OTX ─────────────────────────
    def check_otx(self, indicator: str, itype: str = 'ip') -> dict:
        api_key = current_app.config.get('OTX_API_KEY', '')
        if not api_key or api_key == 'your_otx_api_key_here':
            return {'error': 'OTX API key not configured', 'source': 'otx'}
        try:
            section_map = {'ip': 'IPv4', 'domain': 'domain', 'hash': 'file', 'url': 'url'}
            section     = section_map.get(itype, 'IPv4')
            url = f'https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general'
            resp = self.session.get(url, headers={'X-OTX-API-KEY': api_key}, timeout=10)
            if resp.status_code == 200:
                data        = resp.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                tags_list   = []
                for p in data.get('pulse_info', {}).get('pulses', [])[:5]:
                    tags_list.extend(p.get('tags', []))
                return {
                    'source':          'otx',
                    'indicator':       indicator,
                    'is_malicious':    pulse_count > 0,
                    'reputation_score': min(pulse_count * 10, 100),
                    'pulse_count':     pulse_count,
                    'country':         data.get('country_name', ''),
                    'asn':             str(data.get('asn', '')),
                    'tags':            ', '.join(set(tags_list[:10])),
                    'raw_response':    json.dumps({'pulses': pulse_count}),
                }
            return {'error': f'HTTP {resp.status_code}', 'source': 'otx'}
        except Exception as e:
            return {'error': str(e), 'source': 'otx'}

    def check_all(self, indicator: str, itype: str = 'ip') -> list:
        results = []
        if itype == 'ip':
            results.append(self.check_abuseipdb(indicator))
        results.append(self.check_virustotal(indicator, itype))
        results.append(self.check_otx(indicator, itype))
        return [r for r in results if 'error' not in r]


intel_client = ThreatIntelClient()
