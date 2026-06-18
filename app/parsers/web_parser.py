"""
Apache / Nginx access & error log parser
Detects: 404 enumeration, directory scanning, SQL injection, XSS, bad user-agents.
"""
import re
from .base_parser import BaseParser

SUSPICIOUS_UA = re.compile(
    r'(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|burpsuite|'
    r'metasploit|havij|acunetix|nessus|openvas|hydra|medusa|zgrab|'
    r'python-requests|curl/|wget/|scrapy)', re.I)

SQLI_RE   = re.compile(r'(union.*select|select.*from|insert.*into|drop.*table|'
                        r'exec\s*\(|xp_cmdshell|or\s+1\s*=\s*1|--|;--)', re.I)
XSS_RE    = re.compile(r'(<script|javascript:|onerror=|onload=|eval\(|alert\()', re.I)
CMDI_RE   = re.compile(r'(\||;|`|\$\(|&&|\|\|)\s*(cat|ls|id|whoami|wget|curl|bash|sh)', re.I)
PATH_TRAV = re.compile(r'(\.\./|\.\.\\|%2e%2e)', re.I)
ADMIN_RE  = re.compile(r'/(admin|phpmyadmin|wp-admin|manager|console|actuator|\.env|\.git|'
                        r'config|backup|shell|cmd|eval)', re.I)


class ApacheParser(BaseParser):
    def __init__(self):
        super().__init__()
        self.name = 'apache'

    COMBINED_LOG = re.compile(
        r'(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\w+)\s+([^\s"]+)[^"]*"\s+(\d{3})\s+(\S+)'
        r'(?:\s+"([^"]*)"\s+"([^"]*)")?'
    )

    def parse_line(self, line: str) -> dict:
        m = self.COMBINED_LOG.match(line)
        if not m:
            return None
        ip, user, ts_str, method, path, status, size, referer, ua = m.groups()
        timestamp  = self.safe_datetime(ts_str.split()[0])
        status     = int(status)
        threats    = []
        severity   = 'informational'

        if status == 404:
            threats.append('404_enumeration')
        if status in (400, 403):
            threats.append('forbidden_access')
        if ua and SUSPICIOUS_UA.search(ua):
            threats.append('suspicious_user_agent')
        if SQLI_RE.search(path):
            threats.append('sql_injection')
            severity = 'critical'
        if XSS_RE.search(path):
            threats.append('xss_attempt')
            severity = 'high'
        if CMDI_RE.search(path):
            threats.append('command_injection')
            severity = 'critical'
        if PATH_TRAV.search(path):
            threats.append('path_traversal')
            severity = 'high'
        if ADMIN_RE.search(path):
            threats.append('admin_access_attempt')
            if severity == 'informational':
                severity = 'medium'

        if threats and severity == 'informational':
            severity = 'medium'

        return {
            'timestamp': timestamp,
            'log_type':  'apache',
            'source_ip': ip,
            'username':  user if user != '-' else None,
            'method':    method,
            'path':      path,
            'status_code': status,
            'user_agent': ua,
            'event_type': threats[0] if threats else 'access',
            'severity':   severity,
            'is_threat':  bool(threats),
            'raw_log':    line,
            'details':    {'threats': threats, 'method': method, 'status': status},
        }


class NginxParser(ApacheParser):
    def __init__(self):
        super().__init__()
        self.name = 'nginx'

    def parse_line(self, line: str) -> dict:
        result = super().parse_line(line)
        if result:
            result['log_type'] = 'nginx'
        return result
