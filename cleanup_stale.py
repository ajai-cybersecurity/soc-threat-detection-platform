"""
Cleans up ALL orphaned alerts and incidents from deleted uploads.
Run this once to fix existing stale data: py cleanup_stale.py
"""
from app import create_app
app = create_app()

with app.app_context():
    from app.models.models import db, Alert, Incident, LogEntry, LogUpload

    existing_upload_ids = [r[0] for r in db.session.query(LogUpload.id).all()]
    existing_log_ids    = [r[0] for r in db.session.query(LogEntry.id).all()]

    print(f'Active uploads  : {existing_upload_ids}')
    print(f'Active log rows : {len(existing_log_ids)}')
    print(f'Alerts before   : {Alert.query.count()}')
    print(f'Incidents before: {Incident.query.count()}')

    if not existing_upload_ids and not existing_log_ids:
        # Nothing active — delete everything
        n_a = Alert.query.delete(synchronize_session=False)
        n_i = Incident.query.delete(synchronize_session=False)
        db.session.commit()
        print(f'Deleted {n_a} alerts, {n_i} incidents (no active uploads/logs)')
    else:
        # Delete alerts that are not linked to anything active
        all_alerts = Alert.query.all()
        deleted = 0
        for a in all_alerts:
            is_active = False
            if a.upload_id and a.upload_id in existing_upload_ids:
                is_active = True
            elif a.log_id and a.log_id in set(existing_log_ids):
                is_active = True
            if not is_active:
                db.session.delete(a)
                deleted += 1
        db.session.flush()

        # Delete incidents with no remaining alerts
        inc_deleted = 0
        for inc in Incident.query.all():
            if Alert.query.filter_by(incident_id=inc.id).count() == 0:
                db.session.delete(inc)
                inc_deleted += 1

        db.session.commit()
        print(f'Deleted {deleted} orphaned alerts, {inc_deleted} empty incidents')

    print(f'Alerts after    : {Alert.query.count()}')
    print(f'Incidents after : {Incident.query.count()}')
    print('Done.')
