"""
Behavior Analytics – UBA/UEBA: impossible travel, off-hours, access anomalies.
"""
from datetime import datetime
from collections import defaultdict
from app.models.models import db, BehaviorAnomaly

BUSINESS_HOURS = (7, 19)
_ANOMALY_FIELDS = {'username', 'anomaly_type', 'description', 'risk_score', 'source_ip', 'detected_at'}


class BehaviorAnalytics:
    def analyze_user_behavior(self, logs: list) -> list:
        anomalies = []
        by_user = defaultdict(list)
        for log in logs:
            user = log.get('username')
            if user and user not in ('-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'):
                by_user[user].append(log)
        for user, user_logs in by_user.items():
            anomalies += self._check_off_hours(user, user_logs)
            anomalies += self._check_impossible_travel(user, user_logs)
            anomalies += self._check_excessive_failures(user, user_logs)
        return anomalies

    def _check_off_hours(self, user, logs) -> list:
        off = [l for l in logs
               if l.get('event_type') in ('logon_success', 'accepted_password')
               and isinstance(l.get('timestamp'), datetime)
               and not (BUSINESS_HOURS[0] <= l['timestamp'].hour <= BUSINESS_HOURS[1])]
        if not off:
            return []
        return [{'username': user, 'anomaly_type': 'off_hours_login',
                 'description': f'{user} logged in outside business hours {len(off)} times.',
                 'risk_score': min(len(off) * 15.0, 100),
                 'source_ip': off[-1].get('source_ip'),
                 'detected_at': off[-1].get('timestamp', datetime.utcnow())}]

    def _check_impossible_travel(self, user, logs) -> list:
        unique_ips = list(set(l.get('source_ip') for l in logs
                              if l.get('source_ip') and l.get('event_type') == 'logon_success'))
        if len(unique_ips) < 3:
            return []
        return [{'username': user, 'anomaly_type': 'multiple_source_ips',
                 'description': f'{user} authenticated from {len(unique_ips)} IPs: {", ".join(unique_ips[:5])}',
                 'risk_score': min(len(unique_ips) * 20.0, 100),
                 'source_ip': unique_ips[0],
                 'detected_at': datetime.utcnow()}]

    def _check_excessive_failures(self, user, logs) -> list:
        failures = [l for l in logs if l.get('event_type') in ('logon_failure', 'brute_force', 'auth_failure')]
        if len(failures) < 10:
            return []
        return [{'username': user, 'anomaly_type': 'excessive_failures',
                 'description': f'{user} had {len(failures)} authentication failures.',
                 'risk_score': min(len(failures) * 5.0, 100),
                 'source_ip': failures[-1].get('source_ip'),
                 'detected_at': failures[-1].get('timestamp', datetime.utcnow())}]

    def save_anomalies(self, anomalies: list):
        for a in anomalies:
            try:
                anomaly = BehaviorAnomaly(
                    username     = a.get('username'),
                    anomaly_type = a.get('anomaly_type'),
                    description  = a.get('description'),
                    risk_score   = a.get('risk_score', 0.0),
                    source_ip    = a.get('source_ip'),
                    detected_at  = a.get('detected_at', datetime.utcnow()),
                )
                db.session.add(anomaly)
            except Exception:
                pass
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()


behavior_analytics = BehaviorAnalytics()
