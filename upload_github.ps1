# ===============================
# SOC Platform GitHub Automation
# ===============================

$RepoName = "soc-threat-detection-platform"
$GitHubUsername = "ajai-cybersecurity"

Write-Host ""
Write-Host "====================================="
Write-Host "SOC PLATFORM GITHUB UPLOADER"
Write-Host "====================================="
Write-Host ""

# Remove secrets
if (Test-Path ".env") {
    Write-Host "[+] Found .env file"

    if (!(Test-Path ".env.backup")) {
        Copy-Item .env .env.backup
        Write-Host "[+] Backup created: .env.backup"
    }

    git rm --cached .env 2>$null
}

# Create .gitignore
@"
__pycache__/
*.pyc

venv/
.env

instance/
uploads/
reports_output/

*.db
*.sqlite
*.sqlite3

.vscode/
.idea/

logs/
"@ | Set-Content .gitignore

Write-Host "[+] .gitignore created"

# Create env example
@"
SECRET_KEY=your_secret_key

DATABASE_URL=sqlite:///soc_platform.db

VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
OTX_API_KEY=your_key
"@ | Set-Content .env.example

Write-Host "[+] .env.example created"

# Git Init
if (!(Test-Path ".git")) {
    git init
    Write-Host "[+] Git initialized"
}

git add .
git commit -m "SOC Platform Initial Release"

git branch -M main

Write-Host ""
Write-Host "[+] Local repository ready"
Write-Host ""

Write-Host "Now create repository on GitHub:"
Write-Host "https://github.com/new"
Write-Host ""
Write-Host "Repository Name:"
Write-Host "$RepoName"
Write-Host ""

$answer = Read-Host "Repository created? (y/n)"

if ($answer -eq "y") {

    git remote remove origin 2>$null

    git remote add origin "https://github.com/$GitHubUsername/$RepoName.git"

    git push -u origin main

    Write-Host ""
    Write-Host "====================================="
    Write-Host "PROJECT UPLOADED SUCCESSFULLY"
    Write-Host "====================================="
    Write-Host ""
}