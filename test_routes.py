from app import create_app
app = create_app()
c   = app.test_client()
with app.app_context():
    routes = ['/logs/', '/logs/entries', '/reports/', '/reports/generate']
    for r in routes:
        resp = c.get(r)
        print(f'{r:<30} -> {resp.status_code}')
print('ALL ROUTES OK')
