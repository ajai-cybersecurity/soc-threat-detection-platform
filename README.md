# SOC Platform

A Flask-based Security Operations Center (SOC) platform for log ingestion, threat detection, incident management, intelligence lookup, reporting, and AI-assisted analysis.

## Project Overview

`SOC Platform` is a modular Flask application that lets security analysts upload logs, detect threats, create incidents, track alerts, generate reports, and leverage AI assistance.

The app supports:
- log uploads and parsing for Linux auth/syslog, Windows Event, Sysmon, firewall, Apache, and Nginx logs
- rule-based threat detection and correlation into incidents
- security alerts dashboard, filtering, and status management
- incident creation, workflow, and comments
- threat intelligence lookup and local record storage
- AI analysis via OpenAI or Ollama for alert explanation and incident summaries
- report generation in PDF and CSV formats

## Repository Structure

Root files:
- `run.py` — application entrypoint and Flask app launch script
- `config.py` — configuration classes for development, production, and testing
- `requirements.txt` — Python dependencies
- `Dockerfile` — container image definition
- `docker-compose.yml` — local service definition for running the app in Docker
- `install.bat` — Windows install helper for dependencies
- `start.bat` — Windows startup helper
- `migrate_db.py` — one-time SQLite migration script
- `README.md` — project documentation

Important directories:
- `app/` — application package
- `app/blueprints/` — Flask route modules for each feature area
- `app/models/` — SQLAlchemy data model definitions and database setup
- `app/parsers/` — log parsing logic and parser registry
- `app/detectors/` — threat detection and correlation logic
- `app/intelligence/` — threat intelligence API client
- `app/reports/` — report generation utilities
- `app/utils/` — shared helpers, validators, and utilities
- `static/` — CSS, JavaScript, and image assets
- `templates/` — Jinja2 HTML templates for UI pages
- `uploads/` — user-uploaded log files
- `reports_output/` — generated report files
- `instance/` — runtime SQLite database and instance-specific data
- `logs/` — application or analysis logs
- `tests/` — sample datasets and test files

## Key Application Components

### Entry Point
- `run.py` creates the Flask app using `app.create_app` and starts the server on `0.0.0.0:5000`.
- The app uses `FLASK_ENV` to select `development` or `production` configuration.

### Flask App Factory
- `app/__init__.py` initializes the Flask application, SQLAlchemy, login manager, error handlers, health endpoint, and blueprint registration.
- It also seeds default users into the database on startup if they do not already exist.

### Configuration
- `config.py` defines `Config`, `DevelopmentConfig`, `ProductionConfig`, and `TestingConfig`.
- Important settings include:
  - `SECRET_KEY`
  - `SQLALCHEMY_DATABASE_URI`
  - `UPLOAD_FOLDER`
  - `REPORTS_FOLDER`
  - `ALLOWED_EXTENSIONS`
  - external API keys for malware/threat intelligence (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`)
  - email settings for alert notifications

### Data Models
- `app/models/models.py` defines the application schema using SQLAlchemy:
  - `User`
  - `LogEntry`
  - `LogUpload`
  - `Alert`
  - `Incident`
  - `IncidentComment`
  - `ThreatIntelligence`
  - `Report`
  - `AuditLog`
  - behavior analytics models: `UserBehaviorBaseline`, `BehaviorAnomaly`
  - `ForensicArtifact`

## Feature Areas

### Authentication
Blueprint: `app/blueprints/auth.py`
- `/auth/login` — user login
- `/auth/logout` — sign out
- `/auth/register` — create new user account
- `/auth/profile` — update email, department, password

### Dashboard
Blueprint: `app/blueprints/dashboard.py`
- `/` — main SOC overview page
- `/api/stats` — JSON dashboard statistics
- `/api/live-alerts` — live alert feed
- collects totals, trends, top source IPs, alert distribution, recent alerts/incidents

### Log Management
Blueprint: `app/blueprints/logs.py`
- `/logs/` — threat-focused log viewer and filter
- `/logs/entries` — full log entry browser
- `/logs/upload` — upload log files for analysis
- log upload flow:
  - save uploaded file to `uploads/`
  - detect log type automatically or honor user-selected type
  - parse logs using parser modules
  - save parsed logs to database
  - create alerts and link to log uploads

### Alert Management
Blueprint: `app/blueprints/alerts.py`
- `/alerts/` — alert list view
- `/alerts/<id>` — alert detail
- `/alerts/<id>/status` — update alert status
- `/alerts/<id>/false-positive` — mark false positive
- `/alerts/api/summary` — alert summary JSON

### Incident Management
Blueprint: `app/blueprints/incidents.py`
- `/incidents/` — incident list
- `/incidents/create` — create new incident manually
- `/incidents/<id>` — view incident detail
- `/incidents/<id>/update` — update status/severity/notes
- `/incidents/<id>/comment` — add investigation comment
- `/incidents/api/list` — incident list JSON

### Reporting
Blueprint: `app/blueprints/reports.py`
- `/reports/` — saved reports list
- `/reports/generate` — create PDF or CSV report
- `/reports/download/<id>` — download generated report
- `/reports/delete/<id>` — delete saved report
- report generation uses:
  - PDF: `app/reports/report_generator.py`
  - CSV: `app/reports/report_generator.py`
- reports are stored in `reports_output/`

### Threat Intelligence
Blueprint: `app/blueprints/intelligence.py`
- `/intelligence/` — threat intel history view
- `/intelligence/lookup` — lookup IP/domain/hash
- `/intelligence/api/check/<indicator>` — indicator API lookup
- stores results in `ThreatIntelligence` table

### Forensics
Blueprint: `app/blueprints/forensics.py`
- `/forensics/` — forensic artifact index
- `/forensics/artifact/add` — add a new artifact/hashes
- `/forensics/hash-check` — compute MD5/SHA1/SHA256 for a value

## Parsing and Detection

### Parsers
Parser registry: `app/parsers/__init__.py`
- detects log type and dispatches to parsers
- supports parser classes:
  - `LinuxParser`
  - `ApacheParser`
  - `NginxParser`
  - `WindowsEventParser`
  - `SysmonParser`
  - `FirewallParser`

Common log features:
- timestamp extraction
- source IP extraction
- username, hostname, event ID, severity
- severity mapping and threat flagging

### Threat Detection
- `app/detectors/threat_detector.py` performs rule-based detection:
  - per-event detections for Windows and Linux
  - brute force and password spray detection
  - reconnaissance and web attack detection
  - privilege escalation, persistence, lateral movement, defense evasion
  - builds alert records with MITRE ATT&CK mappings

### Correlation
- `app/detectors/correlation_engine.py` groups alerts into incident-worthy attack chains.
- matches sequences like reconnaissance → web attack, log clearing → persistence, etc.

### Behavior Analytics
- `app/utils/behavior_analytics.py` detects user anomalies:
  - off-hours logins
  - multiple source IPs / impossible travel
  - excessive authentication failures

## Configuration and Environment

### Required directories
- `uploads/` — log files saved after upload
- `reports_output/` — generated report files
- `instance/` — SQLite database and runtime files
- `logs/` — optional application logs

### Environment variables
The app uses `python-dotenv` if a `.env` file exists.
Common variables:
- `SECRET_KEY`
- `DATABASE_URL` (defaults to SQLite in `instance/soc_platform.db`)
- `MAX_CONTENT_LENGTH`
- `ALLOWED_EXTENSIONS`
- `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, `MAIL_PASSWORD`
- `ALERT_RECIPIENTS`
- `SESSION_COOKIE_SECURE`, `WTF_CSRF_ENABLED`
- `MONITOR_INTERVAL`, `AUTO_REFRESH_INTERVAL`

### Default database users
When the app first starts, it creates two seeded accounts if absent:
- `admin` / `Admin@SOC2024!`
- `analyst` / `Analyst@SOC2024!`

## Running the Project

### Windows native
1. Open PowerShell in `c:\SOC_Platform`
2. Create and activate a virtual environment:
   ```powershell
   py -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
3. Install dependencies:
   ```powershell
   py -m pip install --upgrade pip
   py -m pip install -r requirements.txt
   ```
4. Create directories if needed:
   ```powershell
   mkdir uploads reports_output instance logs
   ```
5. Run the app:
   ```powershell
   py run.py
   ```
6. Open the app in your browser:
   `http://localhost:5000`

### Using bundled batch scripts
- `install.bat` installs required Python dependencies
- `start.bat` launches the app in development mode

### Docker
1. Build and run with Docker Compose:
   ```powershell
   docker compose up --build
   ```
2. The service is exposed on `http://localhost:5000`
3. Log and report directories are mounted from the host.

### Notes for production
- `FLASK_ENV=production` is used in Docker.
- Use a production-ready database instead of SQLite by setting `DATABASE_URL`.
- Provide a strong `SECRET_KEY` and secure mail/API credentials.
- Mount persistent volumes for `uploads`, `reports_output`, and `instance`.

## Testing and Sample Data
- `tests/` contains sample Windows and Sysmon log exports for functional validation.
- Use the sample files to exercise log upload and detection flows.

## Application Workflows

### Log ingestion workflow
1. User uploads a log file via `/logs/upload`
2. The app saves the file into `uploads/`
3. The parser registry auto-detects the log type and parses each line
4. Parsed entries are stored in `LogEntry`
5. `ThreatDetector` evaluates logs and creates `Alert` records
6. `CorrelationEngine` can group related alerts into incidents

### Alert and incident workflow
- Analysts view alerts on `/alerts/`
- Alerts can be filtered by severity, threat type, and status
- Analysts create incidents from alerts or manually via `/incidents/create`
- Incident details, timeline, and related alerts are tracked
- Comments are captured for investigation notes

### Reporting workflow
- Reports are generated on `/reports/generate`
- Active reports include only data from uploads still present in the database
- PDF reports are styled with ReportLab and include executive summaries
- CSV reports export alert details

## Additional Notes
- The application uses Flask-Login for user sessions and route protection.
- If you use external AI or threat intelligence APIs, configure the appropriate keys in environment variables or `.env`.
- The app is intentionally modular to allow adding new parser types, detectors, and blueprint features.

## Useful Commands
- Install requirements: `py -m pip install -r requirements.txt`
- Run app: `py run.py`
- Start Docker: `docker compose up --build`
- Run migration script: `py migrate_db.py`

## Contact
For support or customization, inspect the relevant blueprint under `app/blueprints/`, parser under `app/parsers/`, and detection logic under `app/detectors/`.
