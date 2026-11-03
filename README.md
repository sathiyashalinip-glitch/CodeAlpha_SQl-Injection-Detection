# CodeAlpha Task 2 — SQL Injection Detection System

A beginner-friendly Flask dashboard demonstrating suspicious-input detection, safe parameterized search, and security-event review.

## Features
- Rule-based detection for common SQL-like suspicious patterns.
- Low, Medium, and High risk labels.
- Sample-record search using parameterized SQL.
- Event log with timestamp, endpoint, source IP, matched rules, and review status.
- Responsive dashboard and `/health` endpoint.
- Pytest smoke tests.

## Important limitation
Educational demo only, not a production IDS/WAF or a guarantee that SQL injection is prevented. Heuristic rules can create false positives and miss unknown attacks. Use parameterized queries, least-privilege database accounts, secure configuration, and professional security testing in real applications. Test only systems you own or have explicit permission to assess.

## Run on Windows PowerShell
Use Python 3.11 or 3.12 if available. From this folder:
```powershell
py -3.12 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```
If Python 3.12 is not installed, use a version shown by `py --list`, for example `py -3.14 -m venv .venv`. If activation is blocked, skip activation:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```
Open http://127.0.0.1:5000.

## Demo
1. Search `Asha` in the sample directory.
2. Scan `hello student` to see Low risk.
3. Scan a harmless training string such as `' OR '1'='1` or `UNION SELECT` to see the detector log a possible event.
4. Click Review on an event.
5. Visit http://127.0.0.1:5000/health.

Do not enter real personal data or use this demo against third-party systems.

## Tests
```powershell
python -m pytest -q
```

## Upload to GitHub
Create an empty GitHub repository, then run these from this folder:
```powershell
git init
git add .
git status
git commit -m "Add CodeAlpha Task 2 SQL Injection Detection System"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```
Check that `.env` and `.venv` are not staged. Never commit credentials.

## Deployment note
This version uses local SQLite for easy local execution. SQLite files are generally not persistent in serverless deployments like Vercel. For public deployment, adapt database access to managed PostgreSQL with a serverless-compatible connection, or deploy to a host with persistent storage. Do not use the development secret in production.
