"""
Linux auth.log / syslog parser
Detects: failed logins, invalid users, sudo escalation, auth failures.
"""
import re
from .base_parser import BaseParser


class LinuxParser(BaseParser):
    def __init__(self):
        super().__init__()
        self.name = 'linux'

    # Patterns ordered by specificity
    PATTERNS = [
        ('brute_force',          re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port \d+', re.I)),
        ('invalid_user',         re.compile(r'Invalid user (\S+) from (\S+)', re.I)),
        ('auth_failure',         re.compile(r'authentication failure.*user=(\S+)', re.I)),
        ('sudo_escalation',      re.compile(r'sudo:\s+(\S+)\s+:.*COMMAND=(.*)', re.I)),
        ('sudo_incorrect',       re.compile(r'sudo:\s+(\S+)\s+:.*incorrect password attempts', re.I)),
        ('accepted_password',    re.compile(r'Accepted password for (\S+) from (\S+) port \d+', re.I)),
        ('accepted_publickey',   re.compile(r'Accepted publickey for (\S+) from (\S+) port \d+', re.I)),
        ('session_opened',       re.compile(r'session opened for user (\S+)', re.I)),
        ('session_closed',       re.compile(r'session closed for user (\S+)', re.I)),
        ('connection_closed',    re.compile(r'Received disconnect from (\S+) port \d+', re.I)),
        ('max_auth_exceeded',    re.compile(r'error: maximum authentication attempts exceeded.*from (\S+)', re.I)),
        ('root_login',           re.compile(r'ROOT LOGIN\s+(?:on|from)\s+(\S+)', re.I)),
    ]

    TS_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)')

    def parse_line(self, line: str) -> dict:
        m = self.TS_RE.match(line)
        if not m:
            return None
        ts_str, hostname, service, pid, message = m.groups()
        timestamp = self.safe_datetime(ts_str)

        event_type = 'info'
        username   = None
        source_ip  = None
        severity   = 'informational'
        details    = {}

        for etype, pattern in self.PATTERNS:
            pm = pattern.search(message)
            if pm:
                event_type = etype
                groups = pm.groups()
                if etype in ('brute_force', 'invalid_user', 'accepted_password', 'accepted_publickey'):
                    username  = groups[0] if groups else None
                    source_ip = groups[1] if len(groups) > 1 else None
                elif etype in ('auth_failure', 'sudo_escalation', 'sudo_incorrect', 'session_opened', 'session_closed'):
                    username = groups[0] if groups else None
                elif etype == 'connection_closed':
                    source_ip = groups[0] if groups else None
                elif etype == 'max_auth_exceeded':
                    source_ip = groups[0] if groups else None
                elif etype == 'root_login':
                    source_ip = groups[0] if groups else None

                severity = self._map_severity(etype)
                details['pattern'] = etype
                break

        return {
            'timestamp': timestamp,
            'log_type': 'linux',
            'hostname': hostname,
            'service': service,
            'pid': pid,
            'message': message,
            'event_type': event_type,
            'username': username,
            'source_ip': source_ip,
            'severity': severity,
            'is_threat': severity in ('medium', 'high', 'critical'),
            'raw_log': line,
            'details': details,
        }

    @staticmethod
    def _map_severity(etype: str) -> str:
        mapping = {
            'brute_force':        'high',
            'invalid_user':       'medium',
            'auth_failure':       'medium',
            'sudo_escalation':    'high',
            'sudo_incorrect':     'high',
            'max_auth_exceeded':  'critical',
            'root_login':         'critical',
            'accepted_password':  'low',
            'accepted_publickey': 'informational',
            'session_opened':     'informational',
            'session_closed':     'informational',
            'connection_closed':  'informational',
        }
        return mapping.get(etype, 'informational')
