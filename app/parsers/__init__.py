"""
Parser registry – detects log type and delegates to correct parser.
"""
import os
import json
from .linux_parser   import LinuxParser
from .web_parser     import ApacheParser, NginxParser
from .windows_parser import WindowsEventParser, SysmonParser, FirewallParser

PARSERS = {
    'linux':         LinuxParser(),
    'apache':        ApacheParser(),
    'nginx':         NginxParser(),
    'windows_event': WindowsEventParser(),
    'sysmon':        SysmonParser(),
    'firewall':      FirewallParser(),
}


def detect_log_type(filepath: str, hint: str = None) -> str:
    if hint and hint in PARSERS:
        return hint
    fname = os.path.basename(filepath).lower()
    if 'sysmon' in fname:
        return 'sysmon'
    if 'firewall' in fname or 'fw' in fname:
        return 'firewall'
    if 'auth' in fname or 'secure' in fname:
        return 'linux'
    if 'apache' in fname or 'access' in fname:
        return 'apache'
    if 'nginx' in fname:
        return 'nginx'
    if 'windows' in fname or 'security' in fname or 'system' in fname or 'evtx' in fname:
        return 'windows_event'
    if 'syslog' in fname:
        return 'linux'
    # Peek first 10 lines for auto-detection
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            sample = ''.join(f.readline() for _ in range(10))
        if '<Event' in sample or 'EventID' in sample:
            return 'windows_event'
        if 'sysmon' in sample.lower():
            return 'sysmon'
        if 'ALLOW\t' in sample or 'DROP\t' in sample:
            return 'firewall'
        if any(k in sample for k in ('Failed password', 'Invalid user', 'sshd', 'sudo')):
            return 'linux'
        if '"GET' in sample or '"POST' in sample or 'HTTP/' in sample:
            return 'apache'
    except Exception:
        pass
    return 'linux'


def parse_log_file(filepath: str, log_type: str = None) -> list:
    detected = detect_log_type(filepath, log_type)
    parser   = PARSERS.get(detected, PARSERS['linux'])
    results  = parser.parse_file(filepath)
    for r in results:
        r.setdefault('log_type', detected)
        if 'details' in r and isinstance(r['details'], dict):
            r['parsed_data'] = json.dumps(r['details'])
    return results, detected
