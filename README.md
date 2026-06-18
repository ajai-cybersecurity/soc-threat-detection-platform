# SOC Platform – Threat Detection & Incident Response System

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green)
![SQLite](https://img.shields.io/badge/Database-SQLite-orange)
![MITRE ATT%26CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-SOC-purple)

## Overview

SOC Platform is a Security Operations Center (SOC) simulation platform built using Python Flask. It enables analysts to upload and analyze security logs, detect threats using rule-based detection logic, manage alerts and incidents, enrich indicators using threat intelligence sources, perform basic forensic analysis, and generate professional security reports.

The platform is designed to demonstrate core SOC analyst workflows and security monitoring concepts in a centralized web-based interface.

---

## Features

### Security Dashboard

- Real-time SOC dashboard
- Alert statistics
- Incident statistics
- Severity distribution
- Threat trends visualization
- Top attacker visibility

### Log Analysis

Supports analysis of:

- Windows Event Logs
- Sysmon Logs
- Linux Authentication Logs
- Firewall Logs
- Apache Access Logs
- Nginx Access Logs

Capabilities:

- Log upload
- Automatic log type detection
- Event parsing
- Severity classification
- Threat tagging
- Search and filtering

---

### Threat Detection Engine

Rule-based detection framework capable of identifying:

- Brute Force Attacks
- Password Spray Attacks
- Credential Stuffing
- Account Lockouts
- Privilege Escalation
- Persistence Techniques
- Defense Evasion
- Suspicious Process Activity
- Service Installation Events
- Scheduled Task Modifications

---

### MITRE ATT&CK Mapping

Detected threats are automatically mapped to MITRE ATT&CK techniques.

Examples:

| Threat               | MITRE Technique |
| -------------------- | --------------- |
| Brute Force          | T1110.001       |
| Password Spray       | T1110.003       |
| Credential Stuffing  | T1110.004       |
| Privilege Escalation | T1078           |
| Persistence          | T1053           |
| Defense Evasion      | T1070           |

---

### Alert Management

Features:

- Alert Dashboard
- Severity Classification
- Alert Investigation
- Alert Status Tracking
- Alert Filtering
- MITRE Mapping Visibility

Severity Levels:

- Low
- Medium
- High
- Critical

---

### Incident Management

Features:

- Incident Creation
- Incident Tracking
- Incident Status Management
- Investigation Workflow
- Related Alert Correlation
- Incident Documentation

---

### Threat Intelligence

Integrated with VirusTotal.

Supports:

- IP Reputation Lookup
- Domain Reputation Lookup
- URL Reputation Lookup
- File Hash Reputation Lookup

Threat intelligence information includes:

- Reputation Score
- Malicious Detection Count
- Threat Tags
- Indicator Classification

---

### Digital Forensics

Basic forensic capabilities:

- MD5 Hash Generation
- SHA1 Hash Generation
- SHA256 Hash Generation
- Artifact Tracking
- Evidence Documentation

---

### Security Reporting

Generate:

- PDF Security Reports
- CSV Security Reports

Reports include:

- Executive Summary
- Threat Statistics
- Severity Distribution
- Top Threat Categories
- MITRE ATT&CK Mappings
- Incident Summary

---

## Technology Stack

### Backend

- Python
- Flask
- SQLAlchemy
- SQLite

### Frontend

- HTML
- CSS
- Bootstrap
- JavaScript
- Chart.js

### Security

- MITRE ATT&CK Framework
- VirusTotal API
- Rule-Based Detection Engine

### Reporting

- ReportLab
- CSV Export

---

## Project Architecture

```text
                ┌────────────────────┐
                │  Security Logs     │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │   Log Parsers      │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Detection Engine   │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │      Alerts        │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │     Incidents      │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Threat Intelligence│
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │      Reports       │
                └────────────────────┘
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/ajai-cybersecurity/soc-threat-detection-platform.git
cd soc-threat-detection-platform
```

### Create Virtual Environment

```bash
py -m venv venv
```

Activate:

```bash
venv\Scripts\activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment

Create `.env`

```env
SECRET_KEY=your_secret_key

DATABASE_URL=sqlite:///soc_platform.db

VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

### Run Application

```bash
py run.py
```

Open:

```text
http://localhost:5000
```

---

## Screenshots

### Dashboard

- Security Overview
- Threat Metrics
- Alert Statistics

### Alert Management

- Threat Detection Results
- MITRE Mapping

### Incident Management

- Investigation Tracking

### Threat Intelligence

- VirusTotal Reputation Lookup

### Reporting

- PDF and CSV Export

---

## Future Enhancements

Planned upgrades:

- Sigma Rule Support
- YARA Integration
- IOC Hunting Module
- Real-Time Log Monitoring
- SOAR Automation
- Advanced Correlation Engine
- Threat Hunting Dashboard
- PostgreSQL Support
- Multi-Tenant Architecture
- Wazuh Integration
- SIEM Integration

---

## Learning Objectives

This project demonstrates:

- Security Monitoring
- Threat Detection
- Incident Response
- Log Analysis
- Threat Intelligence
- Digital Forensics
- MITRE ATT&CK Mapping
- Security Reporting
- Flask Application Development

---

## Author

**Ajai M**

Cyber Security Engineer | SOC Analyst | DFIR Enthusiast

Areas of Interest:

- Security Operations Center (SOC)
- Digital Forensics
- Incident Response
- Threat Hunting
- Threat Intelligence
- Detection Engineering

GitHub:
https://github.com/ajai-cybersecurity

LinkedIn:
https://www.linkedin.com/in/ajai-m-189a39351/

---

## License

This project is intended for educational, research, and portfolio purposes.
