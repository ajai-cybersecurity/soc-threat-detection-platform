"""
SOC Threat Detection Engine
Modular rule-based detection with MITRE ATT&CK mapping.
Covers: Brute Force, Password Spray, Recon, Privesc, Persistence, Web Attacks,
        Lateral Movement, Defense Evasion, Windows-specific, Sysmon, Firewall.
"""
import uuid
import json
from datetime import datetime, timedelta
from collections import defaultdict


SEVERITY_WEIGHT = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


class ThreatDetector:
    def __init__(self, db_session=None):
        self.db = db_session
        # Sliding-window counters {key: [(timestamp, count)]}
        self._counters = defaultdict(list)

    # ─────────────── PUBLIC INTERFACE ───────────────────────
    def analyze_parsed_logs(self, parsed_logs: list) -> list:
        """Run all detection rules over a batch of parsed log dicts."""
        alerts = []
        # Group for statistical rules
        by_ip   = defaultdict(list)
        by_user = defaultdict(list)
        by_type = defaultdict(list)

        for log in parsed_logs:
            src = log.get('source_ip')
            usr = log.get('username')
            lt  = log.get('log_type', '')
            if src:
                by_ip[src].append(log)
            if usr:
                by_user[usr].append(log)
            by_type[lt].append(log)
            # Per-event rules
            alerts += self._per_event_rules(log)

        # Aggregate / statistical rules
        alerts += self._brute_force_detection(by_ip, by_user)
        alerts += self._password_spray_detection(by_ip)
        alerts += self._recon_detection(by_ip)
        alerts += self._privilege_escalation(by_user)
        alerts += self._persistence_detection(parsed_logs)
        alerts += self._lateral_movement(parsed_logs)
        alerts += self._defense_evasion(parsed_logs)
        alerts += self._firewall_sweep(by_ip)

        return alerts

    # ─────────────── PER-EVENT RULES ────────────────────────
    def _per_event_rules(self, log: dict) -> list:
        alerts = []
        eid    = str(log.get('event_id', ''))
        etype  = log.get('event_type', '')
        sev    = log.get('severity', 'informational')

        # Windows: log cleared
        if eid == '1102':
            alerts.append(self._make_alert(
                'Audit Log Cleared', 'defense_evasion', 'critical',
                log, 'TA0005', 'T1070.001',
                'Windows Security event log was cleared – potential evidence destruction.'
            ))

        # Windows: new service installed
        elif eid in ('4697', '7045'):
            details = log.get('details', {})
            svc = details.get('ServiceName', details.get('param1', 'Unknown'))
            alerts.append(self._make_alert(
                f'New Service Installed: {svc}', 'persistence', 'high',
                log, 'TA0003', 'T1543.003',
                f'A new Windows service was installed: {svc}. Verify legitimacy.'
            ))

        # Windows: scheduled task
        elif eid in ('4698', '4699', '4700'):
            alerts.append(self._make_alert(
                'Scheduled Task Modified', 'persistence', 'high',
                log, 'TA0003', 'T1053.005',
                'Scheduled task created/deleted/enabled – common persistence technique.'
            ))

        # Windows: account created
        elif eid == '4720':
            details = log.get('details', {})
            acct = details.get('TargetUserName', 'Unknown')
            alerts.append(self._make_alert(
                f'New Account Created: {acct}', 'persistence', 'high',
                log, 'TA0003', 'T1136.001',
                f'New local account created: {acct}. Verify with administrator.'
            ))

        # Windows: account lockout
        elif eid == '4740':
            alerts.append(self._make_alert(
                'Account Locked Out', 'credential_access', 'high',
                log, 'TA0006', 'T1110',
                'Account was locked out – may indicate brute force in progress.'
            ))

        # Windows: group membership changed
        elif eid in ('4728', '4732', '4756'):
            details = log.get('details', {})
            member = details.get('MemberName', 'Unknown')
            grp    = details.get('GroupName', 'Unknown')
            alerts.append(self._make_alert(
                f'Privileged Group Modified: {grp}', 'privilege_escalation', 'high',
                log, 'TA0004', 'T1098',
                f'{member} added to privileged group {grp}.'
            ))

        # Sysmon: remote thread
        elif eid == '8' or etype == 'sysmon_remote_thread':
            alerts.append(self._make_alert(
                'Remote Thread Injection Detected', 'execution', 'critical',
                log, 'TA0002', 'T1055',
                'CreateRemoteThread detected – possible process injection attack.'
            ))

        # Sysmon: process access (credential dumping)
        elif eid == '10' or etype == 'sysmon_proc_access':
            details = log.get('details', {})
            target = details.get('TargetImage', '').lower()
            if any(p in target for p in ('lsass', 'winlogon', 'csrss')):
                alerts.append(self._make_alert(
                    'Credential Dumping Attempt', 'credential_access', 'critical',
                    log, 'TA0006', 'T1003.001',
                    f'Process accessed sensitive process: {target} – possible LSASS dump.'
                ))

        # Linux: root login
        elif etype == 'root_login':
            alerts.append(self._make_alert(
                'Direct Root Login Detected', 'privilege_escalation', 'critical',
                log, 'TA0004', 'T1078.003',
                'Direct root login – violates least-privilege principle.'
            ))

        # Linux: sudo escalation
        elif etype == 'sudo_escalation':
            details = log.get('details', {})
            alerts.append(self._make_alert(
                f'Sudo Privilege Use: {log.get("username")}', 'privilege_escalation', 'medium',
                log, 'TA0004', 'T1548.003',
                f'User {log.get("username")} executed command via sudo.'
            ))

        # Web: SQL injection
        elif 'sql_injection' in str(log.get('details', {}).get('threats', [])):
            alerts.append(self._make_alert(
                'SQL Injection Attempt', 'web_attack', 'critical',
                log, 'TA0009', 'T1190',
                f'SQL injection pattern detected in request path: {log.get("path", "")}'
            ))

        # Web: XSS
        elif 'xss_attempt' in str(log.get('details', {}).get('threats', [])):
            alerts.append(self._make_alert(
                'Cross-Site Scripting Attempt', 'web_attack', 'high',
                log, 'TA0009', 'T1189',
                f'XSS pattern detected in request path: {log.get("path", "")}'
            ))

        # Web: Command injection
        elif 'command_injection' in str(log.get('details', {}).get('threats', [])):
            alerts.append(self._make_alert(
                'Command Injection Attempt', 'web_attack', 'critical',
                log, 'TA0002', 'T1059',
                f'Command injection pattern in path: {log.get("path", "")}'
            ))

        # Web: path traversal
        elif 'path_traversal' in str(log.get('details', {}).get('threats', [])):
            alerts.append(self._make_alert(
                'Path Traversal Attempt', 'web_attack', 'high',
                log, 'TA0009', 'T1083',
                f'Directory traversal attempt detected: {log.get("path", "")}'
            ))

        return alerts

    # ─────────────── AGGREGATE RULES ────────────────────────
    def _brute_force_detection(self, by_ip, by_user) -> list:
        alerts = []
        # IP-based brute force: >5 failed logins from same IP
        for ip, logs in by_ip.items():
            failures = [l for l in logs if l.get('event_type') in
                        ('brute_force', 'logon_failure', 'auth_failure', 'invalid_user')]
            if len(failures) >= 5:
                severity = 'critical' if len(failures) >= 20 else 'high'
                alerts.append(self._make_alert(
                    f'Brute Force Attack from {ip}',
                    'brute_force', severity, failures[-1],
                    'TA0006', 'T1110.001',
                    f'{len(failures)} failed authentication attempts from {ip}.',
                    event_count=len(failures)
                ))
        # User-based: same user targeted from multiple IPs
        for user, logs in by_user.items():
            if not user or user in ('-', 'SYSTEM', 'LOCAL SERVICE'):
                continue
            failures = [l for l in logs if l.get('event_type') in
                        ('brute_force', 'logon_failure', 'auth_failure')]
            unique_ips = set(l.get('source_ip') for l in failures if l.get('source_ip'))
            if len(failures) >= 5 and len(unique_ips) >= 2:
                alerts.append(self._make_alert(
                    f'Credential Stuffing Against: {user}',
                    'credential_stuffing', 'high', failures[-1],
                    'TA0006', 'T1110.004',
                    f'{len(failures)} failures for user {user} from {len(unique_ips)} IPs.',
                    event_count=len(failures)
                ))
        return alerts

    def _password_spray_detection(self, by_ip) -> list:
        alerts = []
        for ip, logs in by_ip.items():
            failures = [l for l in logs if l.get('event_type') in
                        ('logon_failure', 'brute_force', 'auth_failure')]
            unique_users = set(l.get('username') for l in failures if l.get('username'))
            if len(unique_users) >= 5 and len(failures) >= 10:
                alerts.append(self._make_alert(
                    f'Password Spray Attack from {ip}',
                    'password_spray', 'critical', failures[-1],
                    'TA0006', 'T1110.003',
                    f'{ip} attempted login against {len(unique_users)} unique users.',
                    event_count=len(failures)
                ))
        return alerts

    def _recon_detection(self, by_ip) -> list:
        alerts = []
        for ip, logs in by_ip.items():
            # 404 enumeration
            f404 = [l for l in logs if l.get('details', {}).get('status') == 404]
            if len(f404) >= 10:
                alerts.append(self._make_alert(
                    f'Directory Enumeration from {ip}',
                    'reconnaissance', 'high', f404[-1],
                    'TA0043', 'T1083',
                    f'{len(f404)} HTTP 404 responses to {ip} – likely directory scanning.',
                    event_count=len(f404)
                ))
            # Suspicious user agents
            sus = [l for l in logs if l.get('event_type') == 'suspicious_user_agent']
            if sus:
                alerts.append(self._make_alert(
                    f'Security Scanner Detected from {ip}',
                    'reconnaissance', 'high', sus[-1],
                    'TA0043', 'T1595',
                    f'Known security scanning tool detected from {ip}.',
                    event_count=len(sus)
                ))
        return alerts

    def _privilege_escalation(self, by_user) -> list:
        alerts = []
        for user, logs in by_user.items():
            priv = [l for l in logs if l.get('event_type') in
                    ('privilege_assign', 'sudo_escalation', 'explicit_logon')]
            if len(priv) >= 3:
                alerts.append(self._make_alert(
                    f'Repeated Privilege Requests: {user}',
                    'privilege_escalation', 'high', priv[-1],
                    'TA0004', 'T1078',
                    f'User {user} made {len(priv)} privilege escalation attempts.',
                    event_count=len(priv)
                ))
        return alerts

    def _persistence_detection(self, logs) -> list:
        alerts = []
        task_logs = [l for l in logs if l.get('event_type') in
                     ('task_create', 'service_install')]
        if len(task_logs) >= 3:
            alerts.append(self._make_alert(
                'Multiple Persistence Mechanisms Detected',
                'persistence', 'critical', task_logs[-1],
                'TA0003', 'T1543',
                f'{len(task_logs)} service/task installations detected – possible persistence.',
                event_count=len(task_logs)
            ))
        return alerts

    def _lateral_movement(self, logs) -> list:
        alerts = []
        # Look for network login type 3 events (4624 type 3)
        net_logins = [l for l in logs if
                      l.get('event_id') == '4624' and
                      str(l.get('details', {}).get('LogonType', '')) == '3']
        by_src = defaultdict(list)
        for l in net_logins:
            if l.get('source_ip'):
                by_src[l['source_ip']].append(l)
        for ip, ip_logs in by_src.items():
            unique_targets = set(l.get('hostname') for l in ip_logs if l.get('hostname'))
            if len(unique_targets) >= 3:
                alerts.append(self._make_alert(
                    f'Lateral Movement Detected from {ip}',
                    'lateral_movement', 'critical', ip_logs[-1],
                    'TA0008', 'T1021',
                    f'{ip} authenticated to {len(unique_targets)} different systems.',
                    event_count=len(ip_logs)
                ))
        return alerts

    def _defense_evasion(self, logs) -> list:
        alerts = []
        cleared = [l for l in logs if l.get('event_id') == '1102']
        if cleared:
            alerts.append(self._make_alert(
                'Event Log Cleared', 'defense_evasion', 'critical', cleared[0],
                'TA0005', 'T1070.001',
                'Windows event log was cleared – evidence of defense evasion.'
            ))
        # Sysmon: suspicious process names
        for log in logs:
            details = log.get('details', {})
            proc    = (details.get('Image') or details.get('CommandLine') or '').lower()
            if any(t in proc for t in ('mimikatz', 'bloodhound', 'cobalt', 'meterpreter',
                                        'powersploit', 'empire', 'psexec', 'wce.exe',
                                        'procdump', 'dumpert')):
                alerts.append(self._make_alert(
                    'Known Attack Tool Detected', 'execution', 'critical', log,
                    'TA0002', 'T1059',
                    f'Known offensive security tool detected: {proc[:100]}'
                ))
        return alerts

    def _firewall_sweep(self, by_ip) -> list:
        alerts = []
        for ip, logs in by_ip.items():
            drops = [l for l in logs if l.get('action') in ('DROP', 'DENY', 'BLOCK', 'REJECT')]
            if len(drops) >= 15:
                alerts.append(self._make_alert(
                    f'Port Scan / Firewall Sweep from {ip}',
                    'reconnaissance', 'high', drops[-1],
                    'TA0043', 'T1046',
                    f'{len(drops)} blocked connections from {ip} – possible port scan.',
                    event_count=len(drops)
                ))
        return alerts

    # ─────────────── ALERT BUILDER ──────────────────────────
    @staticmethod
    def _make_alert(title, threat_type, severity, log, tactic='', technique='',
                    description='', event_count=1) -> dict:
        return {
            'alert_id':        f'ALT-{uuid.uuid4().hex[:12].upper()}',
            'title':           title,
            'threat_type':     threat_type,
            'severity':        severity,
            'source_ip':       log.get('source_ip'),
            'destination_ip':  log.get('destination_ip'),
            'username':        log.get('username'),
            'hostname':        log.get('hostname'),
            'timestamp':       log.get('timestamp', datetime.utcnow()),
            'mitre_tactic':    tactic,
            'mitre_technique': technique,
            'description':     description,
            'event_count':     event_count,
            'raw_evidence':    json.dumps({'log': log.get('raw_log', '')[:500]}),
        }
