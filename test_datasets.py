import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app.parsers import parse_log_file
from app.detectors.threat_detector import ThreatDetector

files = [
    ('tests/FULL_TEST_auth.log',           'linux'),
    ('tests/FULL_TEST_apache.log',         'apache'),
    ('tests/FULL_TEST_windows_events.xml', 'windows_event'),
    ('tests/FULL_TEST_sysmon.xml',         'sysmon'),
    ('tests/FULL_TEST_firewall.log',       'firewall'),
]

detector = ThreatDetector()
total_logs = 0
total_alerts = 0

print("=" * 70)
for fpath, ftype in files:
    parsed, detected = parse_log_file(fpath, ftype)
    alerts  = detector.analyze_parsed_logs(parsed)
    threats = [p for p in parsed if p.get('is_threat')]
    total_logs   += len(parsed)
    total_alerts += len(alerts)
    sev_counts = {}
    for a in alerts:
        s = a.get('severity','low')
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print(f"FILE   : {fpath}")
    print(f"PARSED : {len(parsed)} log lines  |  THREATS: {len(threats)}  |  ALERTS: {len(alerts)}")
    if sev_counts:
        print(f"SEVS   : {sev_counts}")
    if alerts:
        seen = set()
        for a in alerts:
            k = a.get('threat_type','')
            if k not in seen:
                print(f"  -> [{a['severity'].upper():8}] {a['title']}")
                seen.add(k)
    print("-" * 70)

print(f"\nTOTAL LOGS: {total_logs}  |  TOTAL ALERTS: {total_alerts}")
print("=" * 70)
print("ALL DATASETS OK - Upload these files in the platform to test all tabs!")
