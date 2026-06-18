@echo off
echo ============================================================
echo   SOC Platform - Enterprise Threat Detection Platform
echo   Installing dependencies...
echo ============================================================

py -m pip install --upgrade pip
py -m pip install -r requirements.txt

echo.
echo ============================================================
echo   Installation complete!
echo   Run: py run.py
echo   Then open: http://localhost:5000
echo   Default login: admin / Admin@SOC2024!
echo ============================================================
pause
