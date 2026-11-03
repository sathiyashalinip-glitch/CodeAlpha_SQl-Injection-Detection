import os,re,sqlite3
from datetime import datetime,timezone
from pathlib import Path
from flask import Flask,render_template,request,redirect,url_for,flash,jsonify
from dotenv import load_dotenv
load_dotenv()
ROOT=Path(__file__).resolve().parent
DB=os.getenv("DATABASE_PATH",str(ROOT/"security_monitor.db"))
app=Flask(__name__)
app.secret_key=os.getenv("SECRET_KEY","dev-only-change-this-secret")
RULES=[
("SQL comment marker",re.compile(r"(--|/\\*|\\*/)")),
("SQL statement separator",re.compile(r";")),
("Tautology-like expression",re.compile(r"\\b(or|and)\\b\\s+['\\"]?\\w+['\\"]?\\s*=\\s*['\\"]?\\w+['\\"]?",re.I)),
("UNION SELECT pattern",re.compile(r"\\bunion\\b\\s+\\bselect\\b",re.I)),
("Dangerous SQL keyword",re.compile(r"\\b(drop|alter|truncate|exec|execute)\\b",re.I)),
("Information schema reference",re.compile(r"\\binformation_schema\\b",re.I)),
("Time-delay function",re.compile(r"\\b(sleep|pg_sleep|benchmark)\\s*\\(",re.I))]
def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init_db():
 with db() as c:
  c.execute("""CREATE TABLE IF NOT EXISTS security_events(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL,source_ip TEXT NOT NULL,endpoint TEXT NOT NULL,input_value TEXT NOT NULL,risk_level TEXT NOT NULL,matched_rules TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Detected')""")
  c.execute("""CREATE TABLE IF NOT EXISTS demo_records(id INTEGER PRIMARY KEY AUTOINCREMENT,full_name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,department TEXT NOT NULL)""")
  if c.execute("SELECT COUNT(*) n FROM demo_records").fetchone()["n"]==0:
   c.executemany("INSERT INTO demo_records(full_name,email,department) VALUES(?,?,?)",[("Asha Kumar","asha@example.com","AI & Data Science"),("Ravi Kumar","ravi@example.com","Computer Science"),("Meena Raj","meena@example.com","Information Technology")])
def inspect_input(value):
 matches=[name for name,pat in RULES if pat.search(value or "")]
 return ("High" if len(matches)>=3 else "Medium" if matches else "Low"),matches
def log_event(value,endpoint,risk,matches):
 with db() as c:
  c.execute("INSERT INTO security_events(created_at,source_ip,endpoint,input_value,risk_level,matched_rules) VALUES(?,?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(timespec="seconds"),request.remote_addr or "unknown",endpoint,(value or "")[:1000],risk,", ".join(matches) if matches else "No suspicious rule matched"))
@app.get("/")
def index():
 q=request.args.get("q","").strip(); risk,matches=inspect_input(q)
 with db() as c:
  if q and not matches:
   rows=c.execute("SELECT id,full_name,email,department FROM demo_records WHERE full_name LIKE ? OR email LIKE ? OR department LIKE ? ORDER BY id",(f"%{q}%",f"%{q}%",f"%{q}%")).fetchall()
  else: rows=c.execute("SELECT id,full_name,email,department FROM demo_records ORDER BY id").fetchall()
 if q and matches:
  log_event(q,"/",risk,matches); flash("Potentially suspicious input detected. It was logged and not used in the database search.","warning")
 with db() as c: events=c.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 10").fetchall()
 return render_template("index.html",rows=rows,events=events,query=q)
@app.post("/scan")
def scan():
 value=request.form.get("input_value","")[:1000]; risk,matches=inspect_input(value); log_event(value,"/scan",risk,matches)
 flash(f"Scan result: {risk} risk. "+("Matched: "+", ".join(matches) if matches else "No known suspicious pattern detected."),"warning" if matches else "success")
 return redirect(url_for("index"))
@app.post("/events/<int:event_id>/resolve")
def resolve_event(event_id):
 with db() as c: c.execute("UPDATE security_events SET status='Reviewed' WHERE id=?",(event_id,))
 flash("Security event marked as reviewed.","success"); return redirect(url_for("index"))
@app.get("/health")
def health(): return jsonify(status="ok",service="CodeAlpha Task 2 SQL Injection Detection Demo")
with app.app_context(): init_db()
if __name__=="__main__": app.run(debug=os.getenv("FLASK_DEBUG","false").lower()=="true",port=int(os.getenv("PORT","5000")))
