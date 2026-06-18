"""
Attack Correlation Engine – builds attack chains and maps to MITRE ATT&CK.
"""
import json
from datetime import datetime
from collections import defaultdict


ATTACK_CHAINS = [
    {
        'name': 'Full Compromise Chain', 'severity': 'critical',
        'sequence': ['brute_force', 'logon_success', 'privilege_escalation', 'persistence'],
        'mitre': 'TA0006 -> TA0004 -> TA0003',
        'description': 'Attacker brute-forced credentials, gained access, escalated privileges, and established persistence.',
    },
    {
        'name': 'Lateral Movement Chain', 'severity': 'critical',
        'sequence': ['logon_success', 'lateral_movement', 'credential_access'],
        'mitre': 'TA0008 -> TA0006',
        'description': 'Attacker moved laterally across systems and attempted credential harvesting.',
    },
    {
        'name': 'Recon-to-Exploit Chain', 'severity': 'high',
        'sequence': ['reconnaissance', 'web_attack'],
        'mitre': 'TA0043 -> TA0009',
        'description': 'Reconnaissance followed by web application exploitation attempt.',
    },
    {
        'name': 'Defense Evasion Chain', 'severity': 'critical',
        'sequence': ['defense_evasion', 'persistence'],
        'mitre': 'TA0005 -> TA0003',
        'description': 'Event logs cleared followed by persistence mechanism installation.',
    },
]


class CorrelationEngine:
    def correlate(self, alerts: list) -> list:
        incidents = []
        by_ip = defaultdict(list)

        for a in alerts:
            if a.get('source_ip'):
                by_ip[a['source_ip']].append(a)

        for ip, ip_alerts in by_ip.items():
            types = [a['threat_type'] for a in ip_alerts]
            matched = False
            for chain in ATTACK_CHAINS:
                if self._chain_matches(chain['sequence'], types):
                    incidents.append(self._build_incident(chain, ip_alerts, ip))
                    matched = True
                    break
            if not matched and len(ip_alerts) >= 3:
                max_sev = self._max_severity(ip_alerts)
                if max_sev in ('high', 'critical'):
                    incidents.append(self._build_incident(
                        {'name': 'Multiple Alerts from {}'.format(ip),
                         'severity': max_sev, 'mitre': '',
                         'description': '{} alerts from same source IP.'.format(len(ip_alerts))},
                        ip_alerts, ip
                    ))

        return incidents

    @staticmethod
    def _chain_matches(sequence, types) -> bool:
        idx = 0
        for t in types:
            if idx < len(sequence) and sequence[idx] in t:
                idx += 1
        return idx >= len(sequence)

    @staticmethod
    def _max_severity(alerts) -> str:
        order = ['informational', 'low', 'medium', 'high', 'critical']
        max_s = 'informational'
        for a in alerts:
            sev = a.get('severity', 'informational')
            if sev in order and order.index(sev) > order.index(max_s):
                max_s = sev
        return max_s

    @staticmethod
    def _build_incident(chain, alerts, source_ip) -> dict:
        timeline = [
            {'time': str(a.get('timestamp', '')), 'event': a.get('title', '')}
            for a in sorted(alerts, key=lambda x: x.get('timestamp') or datetime.utcnow())
        ]
        return {
            'title':         chain['name'],
            'description':   chain['description'],
            'threat_type':   alerts[0].get('threat_type', 'unknown'),
            'severity':      chain['severity'],
            'source_ip':     source_ip,
            'target_asset':  alerts[0].get('hostname', 'Unknown'),
            'attack_chain':  json.dumps([a.get('title') for a in alerts]),
            'mitre_mapping': json.dumps({'chain': chain.get('mitre', '')}),
            'timeline':      json.dumps(timeline),
        }
