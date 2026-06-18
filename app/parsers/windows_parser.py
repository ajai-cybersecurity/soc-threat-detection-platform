"""
Windows Event Log parser – supports both .evtx (via pywin32/xml) and plain text exports.
Handles Event IDs: 4624/4625/4627/4634/4648/4672/4673/4688/4697/4698/4720/4722/
                   4724/4725/4728/4732/4740/4756/7045/1102 + Sysmon 1-25 + Firewall.
"""
import re
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from .base_parser import BaseParser


EVENT_SEVERITY = {
    '4624': 'informational',  # Successful logon
    '4625': 'high',           # Failed logon
    '4627': 'medium',         # Group membership info
    '4634': 'informational',  # Logoff
    '4647': 'informational',  # User-initiated logoff
    '4648': 'medium',         # Logon with explicit credentials
    '4672': 'medium',         # Special privileges assigned
    '4673': 'medium',         # Privileged service called
    '4674': 'medium',         # Operation attempted on privileged object
    '4688': 'low',            # Process created
    '4697': 'high',           # Service installed
    '4698': 'high',           # Scheduled task created
    '4699': 'high',           # Scheduled task deleted
    '4700': 'high',           # Scheduled task enabled
    '4701': 'medium',         # Scheduled task disabled
    '4702': 'medium',         # Scheduled task updated
    '4720': 'high',           # User account created
    '4722': 'medium',         # User account enabled
    '4723': 'medium',         # Password change attempted
    '4724': 'high',           # Password reset attempted
    '4725': 'high',           # User account disabled
    '4726': 'high',           # User account deleted
    '4728': 'high',           # Member added to global group
    '4732': 'high',           # Member added to local group
    '4740': 'high',           # Account locked out
    '4756': 'high',           # Member added to universal group
    '4776': 'medium',         # NTLM auth attempt
    '4798': 'medium',         # User's local group membership enumerated
    '4799': 'medium',         # Security-enabled local group membership enumerated
    '7034': 'high',           # Service crashed
    '7045': 'critical',       # Service installed (new)
    '1102': 'critical',       # Audit log cleared
    '4616': 'high',           # System time changed
    '4657': 'medium',         # Registry value modified
    # Sysmon events
    '1':  'low',    # Process Create
    '2':  'medium', # File creation time changed
    '3':  'low',    # Network connection
    '4':  'low',    # Sysmon service state changed
    '5':  'medium', # Process terminated
    '6':  'high',   # Driver loaded
    '7':  'medium', # Image loaded
    '8':  'high',   # CreateRemoteThread
    '9':  'medium', # RawAccessRead
    '10': 'high',   # ProcessAccess
    '11': 'low',    # FileCreate
    '12': 'medium', # RegistryEvent (object create/delete)
    '13': 'medium', # RegistryEvent (value set)
    '14': 'medium', # RegistryEvent (key/value rename)
    '15': 'medium', # FileCreateStreamHash
    '17': 'high',   # PipeEvent (created)
    '18': 'high',   # PipeEvent (connected)
    '19': 'high',   # WmiEvent
    '20': 'high',   # WmiEvent
    '21': 'high',   # WmiEvent
    '22': 'low',    # DNS Query
    '23': 'medium', # FileDelete
    '24': 'medium', # ClipboardChange
    '25': 'high',   # ProcessTampering
    '26': 'medium', # FileDeleteDetected
}

MITRE_MAP = {
    '4625': ('TA0006', 'T1110', 'Credential Access – Brute Force'),
    '4648': ('TA0008', 'T1550', 'Lateral Movement – Pass-the-Hash'),
    '4672': ('TA0004', 'T1078', 'Privilege Escalation – Valid Accounts'),
    '4688': ('TA0002', 'T1059', 'Execution – Command and Scripting'),
    '4697': ('TA0003', 'T1543', 'Persistence – Create or Modify System Process'),
    '4698': ('TA0003', 'T1053', 'Persistence – Scheduled Task'),
    '4720': ('TA0003', 'T1136', 'Persistence – Create Account'),
    '4728': ('TA0004', 'T1098', 'Privilege Escalation – Account Manipulation'),
    '4732': ('TA0004', 'T1098', 'Privilege Escalation – Account Manipulation'),
    '4740': ('TA0040', 'T1531', 'Impact – Account Access Removal'),
    '7045': ('TA0003', 'T1543.003', 'Persistence – Windows Service'),
    '1102': ('TA0005', 'T1070.001', 'Defense Evasion – Clear Windows Event Logs'),
    '8':    ('TA0002', 'T1055', 'Execution – Process Injection'),
    '10':   ('TA0006', 'T1003', 'Credential Access – Credential Dumping'),
}


class WindowsEventParser(BaseParser):
    """Parse Windows Event Log XML (evtx exported) and plain text formats."""
    def __init__(self):
        super().__init__()
        self.name = 'windows'

    # ── XML-based EVTX export ──────────────────────────────────
    def parse_xml_event(self, xml_str: str) -> dict:
        try:
            root = ET.fromstring(xml_str)
            ns   = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

            system = root.find('e:System', ns) or root.find('System')
            if system is None:
                return None

            def get(tag):
                el = system.find(f'e:{tag}', ns) or system.find(tag)
                if el is not None:
                    return el.text or el.get('Name') or el.get('Value', '')
                return ''

            event_id  = get('EventID').strip()
            ts_str    = get('TimeCreated').strip() if system.find('e:TimeCreated', ns) is None else \
                        (system.find('e:TimeCreated', ns) or system.find('TimeCreated')).get('SystemTime', '')
            computer  = get('Computer')
            channel   = get('Channel')

            data = {}
            event_data = root.find('e:EventData', ns) or root.find('EventData')
            if event_data is not None:
                for d in event_data:
                    name = d.get('Name', d.tag)
                    data[name] = (d.text or '').strip()

            return self._build_record(event_id, ts_str, computer, channel, data, xml_str)
        except Exception as e:
            return None

    # ── Plain text / CSV Windows event format ─────────────────
    PLAIN_RE = re.compile(
        r'(?:EventID|Event ID|EvtID)[:\s]+(\d+).*?'
        r'(?:TimeGenerated|Date|Time)[:\s]+([^\n\r]+)',
        re.I | re.S
    )
    FIELD_RE = re.compile(r'(Subject|Account Name|Account Domain|Source Network Address|'
                           r'Logon Type|Process Name|Service Name|Target Account Name)[:\s]+([^\n\r]+)', re.I)

    def parse_line(self, line: str) -> dict:
        # Try XML
        if '<Event' in line or line.strip().startswith('<?xml'):
            return self.parse_xml_event(line)
        # Try structured text
        return self._parse_text_line(line)

    def _parse_text_line(self, line: str) -> dict:
        eid_m = re.search(r'\b(4624|4625|4627|4634|4648|4672|4673|4674|4688|4697|4698|4699|'
                           r'4700|4701|4702|4720|4722|4723|4724|4725|4726|4728|4732|4740|'
                           r'4756|4776|4798|4799|7034|7045|1102|4616|4657|'
                           r'\b[1-9]\b|\b1[0-9]\b|\b2[0-6]\b)\b', line)
        if not eid_m:
            return None
        event_id = eid_m.group(1)

        ip_m   = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
        user_m = re.search(r'(?:Account Name|User|Username)[:\s]+(\S+)', line, re.I)
        host_m = re.search(r'(?:Computer|Workstation|ComputerName)[:\s]+(\S+)', line, re.I)
        ts_m   = re.search(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})', line)

        data = {
            'SubjectUserName': user_m.group(1) if user_m else '',
            'IpAddress':       ip_m.group(1)   if ip_m   else '',
        }
        ts_str = ts_m.group(1) if ts_m else ''
        host   = host_m.group(1) if host_m else ''
        return self._build_record(event_id, ts_str, host, 'Security', data, line)

    def _build_record(self, event_id, ts_str, computer, channel, data, raw):
        try:
            timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except Exception:
            timestamp = self.safe_datetime(ts_str)

        severity = EVENT_SEVERITY.get(event_id, 'informational')
        is_threat = severity in ('medium', 'high', 'critical')
        mitre     = MITRE_MAP.get(event_id, ('', '', ''))

        source_ip = (data.get('IpAddress') or data.get('SourceAddress') or
                     data.get('ClientAddress') or '').replace('-', '').strip() or None
        username  = (data.get('TargetUserName') or data.get('SubjectUserName') or
                     data.get('AccountName') or '').replace('-', '').strip() or None

        event_type = self._event_type(event_id)

        return {
            'timestamp':       timestamp,
            'log_type':        'windows_event',
            'event_id':        event_id,
            'hostname':        computer,
            'channel':         channel,
            'username':        username,
            'source_ip':       source_ip,
            'event_type':      event_type,
            'severity':        severity,
            'is_threat':       is_threat,
            'raw_log':         raw[:2000],
            'mitre_tactic':    mitre[0],
            'mitre_technique': mitre[1],
            'mitre_desc':      mitre[2],
            'details':         data,
        }

    @staticmethod
    def _event_type(eid: str) -> str:
        mapping = {
            '4624': 'logon_success',    '4625': 'logon_failure',
            '4648': 'explicit_logon',   '4634': 'logoff',
            '4672': 'privilege_assign', '4673': 'privilege_use',
            '4688': 'process_create',   '4697': 'service_install',
            '4698': 'task_create',      '4720': 'account_create',
            '4722': 'account_enable',   '4724': 'password_reset',
            '4725': 'account_disable',  '4726': 'account_delete',
            '4728': 'group_member_add', '4732': 'group_member_add',
            '4740': 'account_lockout',  '4756': 'group_member_add',
            '7045': 'service_install',  '1102': 'log_cleared',
            '1':  'sysmon_process',     '3':  'sysmon_network',
            '6':  'sysmon_driver',      '8':  'sysmon_remote_thread',
            '10': 'sysmon_proc_access', '12': 'sysmon_registry',
            '13': 'sysmon_registry',    '22': 'sysmon_dns',
        }
        return mapping.get(eid, f'event_{eid}')


class SysmonParser(WindowsEventParser):
    """Sysmon-specific parser extending Windows parser."""
    def __init__(self):
        super().__init__()
        self.name = 'sysmon'

    def parse_line(self, line: str) -> dict:
        result = super().parse_line(line)
        if result:
            result['log_type'] = 'sysmon'
        return result


class FirewallParser(BaseParser):
    """Windows Firewall / pfSense / generic firewall log parser."""
    def __init__(self):
        super().__init__()
        self.name = 'firewall'

    WIN_FW_RE = re.compile(
        r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(ALLOW|DROP|INFO)\s+'
        r'(\w+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)'
    )
    GENERIC_RE = re.compile(
        r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}).*?'
        r'(ALLOW|DENY|DROP|BLOCK|ACCEPT|REJECT)\s+.*?'
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        re.I
    )

    def parse_line(self, line: str) -> dict:
        m = self.WIN_FW_RE.match(line)
        if m:
            date, time, action, proto, src_ip, dst_ip, src_port, dst_port = m.groups()
            ts = self.safe_datetime(f'{date} {time}', '%Y-%m-%d %H:%M:%S')
            is_block = action == 'DROP'
            return {
                'timestamp':  ts,
                'log_type':   'firewall',
                'action':     action,
                'protocol':   proto,
                'source_ip':  src_ip,
                'destination_ip': dst_ip,
                'source_port':    src_port,
                'dest_port':      dst_port,
                'event_type': 'fw_drop' if is_block else 'fw_allow',
                'severity':   'medium' if is_block else 'informational',
                'is_threat':  is_block,
                'raw_log':    line,
                'details':    {},
            }

        m2 = self.GENERIC_RE.search(line)
        if m2:
            ts_str, action, src_ip, dst_ip = m2.groups()
            ts = self.safe_datetime(ts_str)
            is_block = action.upper() in ('DENY', 'DROP', 'BLOCK', 'REJECT')
            return {
                'timestamp':  ts,
                'log_type':   'firewall',
                'action':     action.upper(),
                'source_ip':  src_ip,
                'destination_ip': dst_ip,
                'event_type': 'fw_block' if is_block else 'fw_allow',
                'severity':   'medium' if is_block else 'informational',
                'is_threat':  is_block,
                'raw_log':    line,
                'details':    {},
            }
        return None
