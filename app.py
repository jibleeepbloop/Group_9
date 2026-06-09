from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, EmailStr
import uvicorn
import os
from db import get_conn, generate_salt, hash_password, verify_password

CCTV_FEED_BASE = "https://merchants-centres-trace-pressure.trycloudflare.com/stream?key=praise-the-fool"
CCTV_STREAM_PATH = "/stream?key=[stream-key]"

def cctv_remote_url() -> str:
    return CCTV_FEED_BASE.rstrip("/") + CCTV_STREAM_PATH

app = FastAPI()

# CORS (development only)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- request models ----------
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    repass: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ActivityLogRequest(BaseModel):
    email: EmailStr
    action: str

# ---------- Auth endpoints ----------
@app.post("/api/signup")
def signup(data: SignupRequest):
    if data.password != data.repass:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = %s", (data.email.lower(),))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered.")
    salt = generate_salt()
    pw_hash = hash_password(data.password, salt)
    cursor.execute(
        "INSERT INTO users (name, email, password_hash, salt) VALUES (%s, %s, %s, %s)",
        (data.name.strip(), data.email.lower(), pw_hash, salt)
    )
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "Account created."}

@app.post("/api/login")
def login(data: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    email = data.email.lower()
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name, password_hash, salt FROM admins WHERE email = %s", (email,)
    )
    admin_row = cursor.fetchone()
    if admin_row and verify_password(
        data.password, admin_row["salt"], admin_row["password_hash"]
    ):
        name = admin_row["name"]
        cursor.execute(
            "INSERT INTO login_logs (email, name, status, ip) VALUES (%s, %s, 'SUCCESS', %s)",
            (email, name, ip),
        )
        conn.commit()
        conn.close()
        return {"status": "ok", "name": name, "email": email, "role": "admin"}

    cursor.execute(
        "SELECT name, password_hash, salt FROM users WHERE email = %s", (email,)
    )
    row = cursor.fetchone()
    if row and verify_password(data.password, row["salt"], row["password_hash"]):
        name = row["name"]
        cursor.execute(
            "INSERT INTO login_logs (email, name, status, ip) VALUES (%s, %s, 'SUCCESS', %s)",
            (email, name, ip),
        )
        conn.commit()
        conn.close()
        return {"status": "ok", "name": name, "email": email, "role": "user"}

    cursor.execute(
        "INSERT INTO login_logs (email, name, status, ip) VALUES (%s, %s, 'FAILED', %s)",
        (email, None, ip),
    )
    conn.commit()
    conn.close()
    raise HTTPException(status_code=401, detail="Invalid email or password.")

# ---------- Activity logging ----------
@app.post("/api/user/log-activity")
def log_user_activity(data: ActivityLogRequest):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = %s", (data.email.lower(),))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User account not found.")
    cursor.execute("INSERT INTO user_activities (email, action) VALUES (%s, %s)", (data.email.lower(), data.action.strip()))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "Activity captured."}


@app.get("/api/admin/users")
def admin_users():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users ORDER BY id DESC")
    users_rows = [dict(r) for r in cursor.fetchall()]
    for user in users_rows:
        cursor.execute(
            """
            SELECT action, timestamp FROM user_activities
            WHERE email = %s ORDER BY id DESC LIMIT 100
            """,
            (user["email"],),
        )
        user["activities"] = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"users": users_rows}


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    if row:
        cursor.execute("DELETE FROM user_activities WHERE email = %s", (row["email"],))
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/api/admin/logs")
def admin_logs(limit: int = 200):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, email, name, status, ip, logged_at FROM login_logs ORDER BY id DESC LIMIT %s",
        (max(1, min(limit, 500)),),
    )
    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"logs": logs}




@app.get("/api/admin/live-logins")
def live_logins(limit: int = 20):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT email, name, status, ip, logged_at
        FROM login_logs
        ORDER BY id DESC
        LIMIT %s
        """,
        (max(1, min(limit, 100)),),
    )

    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"logs": logs}


class MotionLogRequest(BaseModel):
    start_time: str
    end_time: str | None = None
    duration_seconds: float | None = None


@app.post("/api/motion/log")
def log_motion(data: MotionLogRequest):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO motion_events (start_time, end_time, duration_seconds) VALUES (%s, %s, %s)",
        (data.start_time, data.end_time, data.duration_seconds),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/api/motion/events")
def motion_events(limit: int = 200):
    conn = get_conn()
    cursor = conn.cursor()
    lim = max(1, min(limit, 500))
    cursor.execute(
        "SELECT id, start_time, end_time, duration_seconds FROM motion_events ORDER BY id DESC LIMIT %s",
        (lim,),
    )
    events = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT COUNT(*) AS c FROM motion_events")
    total = cursor.fetchone()["c"]
    cursor.execute(
        "SELECT COUNT(*) AS c FROM motion_events WHERE start_time::date = CURRENT_DATE"
    )
    today_count = cursor.fetchone()["c"]
    conn.close()
    return {"events": events, "total": total, "today_count": today_count}


def _proxy_cctv_stream():
    """Relay MJPEG from the Cloudflare tunnel through this app (same-origin for the browser)."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        cctv_remote_url(),
        headers={"User-Agent": "YosanCCTV/1.0", "Accept": "*/*"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                yield chunk
    except urllib.error.HTTPError:
        return
    except OSError:
        return


@app.get("/api/cctv/stream")
def cctv_stream():
    return StreamingResponse(
        _proxy_cctv_stream(),
        media_type="multipart/x-mixed-replace; boundary=frame",
    )


# ---------- Shared style ----------
YOSAN_BASE_STYLE = """
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'DM Sans', sans-serif;
    min-height: 100vh;
    background: linear-gradient(145deg, #EEF4FF 0%, #DBEAFE 50%, #BAE6FD 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1.5rem;
  }

  .card {
    background: rgba(255, 255, 255, 0.90);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(147, 197, 253, 0.4);
    border-radius: 20px;
    padding: 2.5rem 2rem;
    width: 100%;
    max-width: 440px;
    box-shadow: 0 8px 40px rgba(37, 99, 235, 0.10), 0 1px 3px rgba(37, 99, 235, 0.06);
  }

  .brand {
    text-align: center;
    margin-bottom: 1.75rem;
  }

  .brand h1 {
    font-family: 'Plus Jakarta Sans', sans-serif;
    font-size: 3rem;
    font-weight: 800;
    color: #1D4ED8;
    line-height: 1;
    letter-spacing: -2px;
  }

  .brand p {
    font-size: 0.8rem;
    color: #fff;
    background: linear-gradient(90deg, #2563EB, #38BDF8);
    display: inline-block;
    padding: 3px 14px;
    border-radius: 20px;
    margin-top: 8px;
    font-weight: 600;
    letter-spacing: 0.8px;
    text-transform: uppercase;
  }

  label {
    display: block;
    font-size: 0.82rem;
    color: #475569;
    margin-bottom: 5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  input {
    display: block;
    width: 100%;
    padding: 11px 16px;
    border: 1.5px solid #BFDBFE;
    border-radius: 10px;
    font-size: 0.95rem;
    color: #1E293B;
    background: #F8FAFF;
    outline: none;
    margin-bottom: 1rem;
    transition: border-color 0.2s, box-shadow 0.2s;
    font-family: 'DM Sans', sans-serif;
  }

  input:focus {
    border-color: #2563EB;
    background: #fff;
    box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
  }

  .btn-primary {
    display: block;
    width: 100%;
    padding: 13px;
    border-radius: 10px;
    font-size: 0.95rem;
    font-weight: 700;
    font-family: 'DM Sans', sans-serif;
    cursor: pointer;
    border: none;
    background: linear-gradient(135deg, #2563EB 0%, #38BDF8 100%);
    color: #fff;
    letter-spacing: 0.5px;
    box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35);
    transition: all 0.15s;
    margin-top: 6px;
    text-decoration: none;
    text-align: center;
    text-transform: uppercase;
  }

  .btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(37, 99, 235, 0.45);
  }

  .btn-primary:active {
    transform: translateY(1px);
    box-shadow: 0 2px 8px rgba(37, 99, 235, 0.25);
  }

  .btn-outline {
    display: block;
    width: 100%;
    padding: 12px;
    border-radius: 10px;
    font-size: 0.95rem;
    font-weight: 600;
    font-family: 'DM Sans', sans-serif;
    cursor: pointer;
    border: 1.5px solid #BFDBFE;
    background: transparent;
    color: #2563EB;
    text-align: center;
    text-decoration: none;
    transition: all 0.15s;
    margin-top: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .btn-outline:hover {
    background: #EFF6FF;
    border-color: #2563EB;
  }

  .msg {
    margin-top: 14px;
    font-size: 0.88rem;
    padding: 10px 14px;
    border-radius: 10px;
    display: none;
    font-weight: 500;
  }

  .msg.success { background: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; display: block; }
  .msg.error   { background: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; display: block; }

  .footer {
    margin-top: 1.25rem;
    font-size: 0.88rem;
    color: #94A3B8;
    text-align: center;
    font-weight: 500;
  }

  .footer a { color: #2563EB; text-decoration: none; font-weight: 600; }
  .footer a:hover { text-decoration: underline; }

  .divider {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 1.2rem 0;
    color: #CBD5E1;
    font-size: 0.82rem;
  }

  .divider::before,
  .divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: #E2E8F0;
  }
"""

# ---------- Frontend HTML ----------

LANDING_HTML = f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Yosan</title>
  <style>
    {YOSAN_BASE_STYLE}
    .card {{ text-align: center; }}
    .brand h1 {{ font-size: 4rem; }}
    .tagline {{
      font-size: 0.95rem; color: #64748B; margin-bottom: 2rem;
      font-weight: 400; line-height: 1.6;
    }}
    .hero-icon {{
      width: 64px; height: 64px;
      background: linear-gradient(135deg, #DBEAFE, #BAE6FD);
      border-radius: 18px; display: flex; align-items: center;
      justify-content: center; margin: 0 auto 1.2rem;
      font-size: 1.8rem; box-shadow: 0 4px 14px rgba(37,99,235,0.15);
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="hero-icon">🎥</div>
    <div class="brand">
      <h1>Yosan</h1>
      <p>CCTV MONITORING</p>
    </div>
    <p class="tagline">Intelligent CCTV monitoring with motion detection.<br>Create an account or sign in to begin.</p>
    <a class="btn-primary" href="/signup">Create Account</a>
    <a class="btn-outline" href="/login">Sign In</a>
  </div>
</body>
</html>
"""

SIGNUP_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Sign Up — Yosan</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap');
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; font-family: 'DM Sans', sans-serif; }
    body {
      background: linear-gradient(145deg, #EEF4FF 0%, #DBEAFE 50%, #BAE6FD 100%);
      display: flex; flex-direction: column;
      align-items: center; justify-content: center; min-height: 100vh;
    }
    .topbar {
      position: fixed; top: 0; left: 0; right: 0; height: 60px;
      background: rgba(255,255,255,0.92); backdrop-filter: blur(12px);
      border-bottom: 1px solid rgba(147,197,253,0.4);
      box-shadow: 0 1px 12px rgba(37,99,235,0.08);
      display: flex; align-items: center; padding: 0 2rem; z-index: 10;
    }
    .topbar-logo { display: flex; align-items: center; gap: 10px; }
    .topbar-logo-icon {
      width: 32px; height: 32px;
      background: linear-gradient(135deg, #2563EB, #38BDF8);
      border-radius: 8px; display: flex; align-items: center;
      justify-content: center; font-size: 1rem;
    }
    .topbar-logo span {
      font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1.3rem;
      font-weight: 800; color: #1D4ED8; letter-spacing: -1px;
    }
    .page {
      display: flex; width: min(1000px, 96vw); min-height: 580px;
      border-radius: 18px; overflow: hidden;
      box-shadow: 0 20px 60px rgba(37,99,235,0.15), 0 1px 3px rgba(37,99,235,0.06);
      margin-top: 76px; margin-bottom: 24px;
    }
    .left {
      width: 48%;
      background: linear-gradient(160deg, #1D4ED8 0%, #2563EB 60%, #0EA5E9 100%);
      border-radius: 18px 0 0 18px; padding: 2.8rem 2.6rem 2.2rem;
      display: flex; flex-direction: column; justify-content: center;
      position: relative; overflow: hidden;
    }
    .left::before {
      content: ''; position: absolute; top: -80px; right: -80px;
      width: 260px; height: 260px; background: rgba(255,255,255,0.07); border-radius: 50%;
    }
    .left::after {
      content: ''; position: absolute; bottom: -60px; left: -40px;
      width: 180px; height: 180px; background: rgba(255,255,255,0.05); border-radius: 50%;
    }
    .panel-brand { display: flex; align-items: center; gap: 12px; margin-bottom: 1.6rem; }
    .panel-brand-icon {
      width: 44px; height: 44px; background: rgba(255,255,255,0.18);
      border-radius: 12px; display: flex; align-items: center;
      justify-content: center; font-size: 1.4rem; border: 1px solid rgba(255,255,255,0.25);
    }
    .panel-brand-text .name {
      font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1.5rem;
      font-weight: 800; color: #fff; letter-spacing: -1px;
    }
    .panel-brand-text .sub {
      font-size: 0.72rem; color: rgba(255,255,255,0.6); margin-top: 1px;
      text-transform: uppercase; letter-spacing: 0.6px;
    }
    .panel-header { margin-bottom: 1.6rem; }
    .panel-header h2 {
      font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1.9rem;
      font-weight: 800; color: #fff; letter-spacing: -1.5px; line-height: 1.1;
    }
    .panel-header p { font-size: 0.88rem; color: rgba(255,255,255,0.6); margin-top: 4px; }
    .field-group { margin-bottom: 0.8rem; }
    .field-group input {
      width: 100%; padding: 12px 18px;
      background: rgba(255,255,255,0.12);
      border: 1.5px solid rgba(255,255,255,0.25);
      border-radius: 10px; font-family: 'DM Sans', sans-serif;
      font-size: 0.95rem; color: #fff; outline: none;
      transition: background 0.15s, border-color 0.15s;
    }
    .field-group input::placeholder { color: rgba(255,255,255,0.45); }
    .field-group input:focus {
      background: rgba(255,255,255,0.2); border-color: rgba(255,255,255,0.6);
      box-shadow: 0 0 0 3px rgba(255,255,255,0.1);
    }
    .checks { margin: 0.5rem 0 1rem; }
    .check-row {
      display: flex; align-items: flex-start; gap: 8px; margin-bottom: 6px;
      font-family: 'DM Sans', sans-serif; font-size: 0.82rem;
      color: rgba(255,255,255,0.75); cursor: pointer;
    }
    .check-row input[type=checkbox] {
      display: inline-block; width: 16px !important; height: 16px !important;
      margin-bottom: 0 !important; padding: 0 !important; border: none !important;
      border-radius: 4px !important; background: none !important;
      box-shadow: none !important; accent-color: #38BDF8;
      flex-shrink: 0; margin-top: 2px; cursor: pointer;
    }
    .check-row a { color: #BAE6FD; text-decoration: underline; }
    .submit-btn {
      width: 100%; display: block; padding: 13px; background: #fff;
      border: none; border-radius: 10px; font-family: 'DM Sans', sans-serif;
      font-size: 0.95rem; font-weight: 700; color: #1D4ED8; letter-spacing: 0.3px;
      cursor: pointer; box-shadow: 0 4px 14px rgba(0,0,0,0.15);
      transition: all 0.15s; text-transform: uppercase;
    }
    .submit-btn:hover  { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(0,0,0,0.2); }
    .submit-btn:active { transform: translateY(1px); box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .msg {
      margin-top: 10px; font-size: 0.85rem; padding: 9px 14px;
      border-radius: 8px; display: none; font-weight: 500; text-align: center;
    }
    .msg.success { background: rgba(16,185,129,0.2); color: #6EE7B7; border: 1px solid rgba(110,231,183,0.3); display: block; }
    .msg.error   { background: rgba(239,68,68,0.2); color: #FCA5A5; border: 1px solid rgba(252,165,165,0.3); display: block; }
    .panel-footer { margin-top: 1rem; font-size: 0.82rem; color: rgba(255,255,255,0.5); text-align: center; }
    .panel-footer a { color: #BAE6FD; font-weight: 600; text-decoration: none; }
    .panel-footer a:hover { text-decoration: underline; }
    .right {
      flex: 1; background: #fff; border-radius: 0 18px 18px 0; position: relative;
      overflow: hidden; display: flex; flex-direction: column;
      align-items: center; justify-content: center; gap: 1.5rem; padding: 2.5rem;
    }
    .right-title {
      font-family: 'Plus Jakarta Sans', sans-serif; font-size: 2rem;
      font-weight: 800; color: #1D4ED8; letter-spacing: -1.5px;
      text-align: center; z-index: 1;
    }
    .right-sub { font-size: 0.9rem; color: #64748B; text-align: center; line-height: 1.6; max-width: 280px; z-index: 1; }
    .features { display: flex; flex-direction: column; gap: 0.8rem; z-index: 1; width: 100%; max-width: 260px; }
    .feature-item {
      display: flex; align-items: center; gap: 12px; padding: 12px 16px;
      background: #F0F7FF; border-radius: 12px; border: 1px solid #DBEAFE;
    }
    .feature-icon {
      width: 36px; height: 36px;
      background: linear-gradient(135deg, #2563EB, #38BDF8);
      border-radius: 8px; display: flex; align-items: center;
      justify-content: center; font-size: 1rem; flex-shrink: 0;
    }
    .feature-text { font-size: 0.85rem; font-weight: 600; color: #1E293B; }
    .blob { position: absolute; opacity: 0.06; border-radius: 50%; background: #2563EB; }
    .blob-1 { width: 320px; height: 320px; top: -100px; right: -100px; }
    .blob-2 { width: 200px; height: 200px; bottom: -60px; left: -40px; }
    .link-btn {
      background: none; border: none; padding: 0;
      font-family: 'DM Sans', sans-serif; font-size: inherit;
      color: #BAE6FD; text-decoration: underline; cursor: pointer;
    }
    .link-btn:hover { color: #fff; }
    .modal-backdrop {
      display: none; position: fixed; inset: 0;
      background: rgba(15,23,42,0.6); backdrop-filter: blur(4px);
      z-index: 9999; align-items: center; justify-content: center;
    }
    .modal-backdrop.open { display: flex; }
    .modal-box {
      background: #fff; border-radius: 16px; width: min(520px, 92vw);
      max-height: 80vh; display: flex; flex-direction: column;
      box-shadow: 0 20px 60px rgba(15,23,42,0.25); border: 1px solid rgba(147,197,253,0.4);
      animation: modalIn 0.2s ease;
    }
    @keyframes modalIn { from { opacity:0; transform:scale(0.96) translateY(12px); } to { opacity:1; transform:scale(1) translateY(0); } }
    .modal-header { display:flex; align-items:center; justify-content:space-between; padding:1.2rem 1.5rem 0.9rem; border-bottom:1px solid #E2E8F0; }
    .modal-header h2 { font-family:'Plus Jakarta Sans',sans-serif; font-size:1.2rem; font-weight:700; color:#1E293B; letter-spacing:-0.5px; }
    .modal-close { background:#F1F5F9; border:none; font-size:1.2rem; color:#64748B; cursor:pointer; line-height:1; padding:4px 8px; border-radius:6px; transition:all 0.1s; }
    .modal-close:hover { background:#FEE2E2; color:#DC2626; }
    .modal-body { padding:1.2rem 1.5rem; overflow-y:auto; flex:1; }
    .modal-body h3 { font-family:'DM Sans',sans-serif; font-size:0.85rem; font-weight:700; color:#2563EB; text-transform:uppercase; letter-spacing:0.5px; margin:1rem 0 0.3rem; }
    .modal-body h3:first-child { margin-top:0; }
    .modal-body p { font-family:'DM Sans',sans-serif; font-size:0.88rem; color:#475569; line-height:1.6; }
    .modal-footer { padding:0.9rem 1.5rem 1.2rem; border-top:1px solid #E2E8F0; display:flex; justify-content:flex-end; }
    .modal-done { padding:10px 28px; background:linear-gradient(135deg,#2563EB,#38BDF8); border:none; border-radius:8px; font-family:'DM Sans',sans-serif; font-size:0.9rem; font-weight:700; color:#fff; cursor:pointer; box-shadow:0 4px 12px rgba(37,99,235,0.3); transition:all 0.15s; text-transform:uppercase; letter-spacing:0.3px; }
    .modal-done:hover { transform:translateY(-1px); box-shadow:0 6px 16px rgba(37,99,235,0.4); }
    @media (max-width: 700px) { .page { flex-direction: column; width: 96vw; } .left { width: 100%; border-radius: 18px 18px 0 0; } .right { display: none; } }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="topbar-logo">
      <div class="topbar-logo-icon">🎥</div>
      <span>Yosan</span>
    </div>
  </div>
  <div class="page">
    <div class="left">
      <div class="panel-brand">
        <div class="panel-brand-icon">🎥</div>
        <div class="panel-brand-text">
          <div class="name">Yosan</div>
          <div class="sub">CCTV MONITORING</div>
        </div>
      </div>
      <div class="panel-header">
        <h2>Create Account</h2>
        <p>Start monitoring in seconds.</p>
      </div>
      <div class="field-group"><input id="username" type="text" placeholder="Full Name" autocomplete="username"/></div>
      <div class="field-group"><input id="email" type="email" placeholder="Email Address" autocomplete="email"/></div>
      <div class="field-group"><input id="password" type="password" placeholder="Password" autocomplete="new-password"/></div>
      <div class="field-group"><input id="repass" type="password" placeholder="Confirm Password" autocomplete="new-password"/></div>
      <div class="checks">
        <div class="check-row">
          <input type="checkbox" id="terms"/>
          <label for="terms">I agree to the&nbsp;<button type="button" class="link-btn" onclick="openModal('termsModal')">Terms and Conditions</button></label>
        </div>
        <div class="check-row">
          <input type="checkbox" id="privacy"/>
          <label for="privacy">I have read the&nbsp;<button type="button" class="link-btn" onclick="openModal('privacyModal')">Privacy Policy</button></label>
        </div>
      </div>
      <button class="submit-btn" onclick="doSignup()">Create Account</button>
      <div id="msg" class="msg"></div>
      <div class="panel-footer">Already have an account? <a href="/login">Sign in</a> &nbsp;·&nbsp; <a href="/">Home</a></div>
    </div>
    <div class="right">
      <div class="blob blob-1"></div>
      <div class="blob blob-2"></div>
      <div class="right-title">Welcome to<br>Yosan</div>
      <p class="right-sub">Monitor your CCTV cameras.</p>
      <div class="features">
        <div class="feature-item"><div class="feature-icon">🌐</div><span class="feature-text">Live CCTV Monitoring</span></div>
        <div class="feature-item"><div class="feature-icon">🎯</div><span class="feature-text">Motion Detection</span></div>
        <div class="feature-item"><div class="feature-icon">🔒</div><span class="feature-text">Secure Access Logs</span></div>
      </div>
    </div>
  </div>

  <div id="termsModal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="termsTitle">
    <div class="modal-box">
      <div class="modal-header"><h2 id="termsTitle">Terms and Conditions</h2><button class="modal-close" onclick="closeModal('termsModal')">&times;</button></div>
      <div class="modal-body">
        <h3>1. Acceptance of Terms</h3><p>By creating an account and using Yosan, you agree to be bound by these Terms and Conditions.</p>
        <h3>2. Use of Service</h3><p>Yosan is a CCTV monitoring tool. You agree to use the service only for lawful purposes.</p>
        <h3>3. Account Responsibility</h3><p>You are responsible for maintaining the confidentiality of your account credentials.</p>
        <h3>4. Camera & Privacy</h3><p>You are solely responsible for ensuring camera usage complies with local privacy laws. Do not monitor spaces without consent.</p>
        <h3>5. Modifications</h3><p>We reserve the right to modify these terms at any time.</p>
        <h3>6. Termination</h3><p>We may suspend or terminate your account at our discretion if you violate these terms.</p>
      </div>
      <div class="modal-footer"><button class="modal-done" onclick="acceptAndClose('termsModal','terms')">I Agree</button></div>
    </div>
  </div>

  <div id="privacyModal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="privacyTitle">
    <div class="modal-box">
      <div class="modal-header"><h2 id="privacyTitle">Privacy Policy</h2><button class="modal-close" onclick="closeModal('privacyModal')">&times;</button></div>
      <div class="modal-body">
        <h3>1. Information We Collect</h3><p>We collect your name, email, and system activity logs. We do not sell your data to third parties.</p>
        <h3>2. Camera Data</h3><p>Camera streams and motion detection data are processed locally on your server and are not transmitted to Anthropic or any third party.</p>
        <h3>3. Data Security</h3><p>We take reasonable measures to protect your data, including password hashing and secure storage.</p>
        <h3>4. Your Rights</h3><p>You may request deletion of your account and associated data at any time.</p>
        <h3>5. Changes</h3><p>We may update this Privacy Policy periodically.</p>
      </div>
      <div class="modal-footer"><button class="modal-done" onclick="acceptAndClose('privacyModal','privacy')">I Have Read This</button></div>
    </div>
  </div>
<script>
function openModal(id) { document.getElementById(id).classList.add('open'); document.body.style.overflow='hidden'; }
function closeModal(id) { document.getElementById(id).classList.remove('open'); document.body.style.overflow=''; }
function acceptAndClose(modalId, checkboxId) { document.getElementById(checkboxId).checked=true; closeModal(modalId); }
document.addEventListener('click', function(e) { if(e.target.classList.contains('modal-backdrop')){ e.target.classList.remove('open'); document.body.style.overflow=''; } });
document.addEventListener('keydown', function(e) { if(e.key==='Escape'){ document.querySelectorAll('.modal-backdrop.open').forEach(m=>{ m.classList.remove('open'); document.body.style.overflow=''; }); } });

async function doSignup() {
  const msg = document.getElementById('msg');
  msg.className = 'msg';
  if (!document.getElementById('terms').checked || !document.getElementById('privacy').checked) {
    msg.className = 'msg error'; msg.textContent = 'Please accept the terms and privacy policy.'; return;
  }
  const payload = { name: document.getElementById('username').value, email: document.getElementById('email').value, password: document.getElementById('password').value, repass: document.getElementById('repass').value };
  try {
    const res = await fetch('/api/signup', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
    const data = await res.json();
    if (!res.ok) throw data;
    msg.className = 'msg success'; msg.textContent = 'Account created! Redirecting…';
    setTimeout(() => { window.location.href = '/login'; }, 900);
  } catch(e) { msg.className = 'msg error'; msg.textContent = e.detail || 'Something went wrong.'; }
}
</script>
</body>
</html>
"""

LOGIN_HTML = f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Sign In — Yosan</title>
  <style>
    {YOSAN_BASE_STYLE}
    .card {{ position: relative; overflow: hidden; }}
    .card::before {{
      content: ''; position: absolute; top: -40px; right: -40px;
      width: 180px; height: 180px;
      background: radial-gradient(circle, rgba(37,99,235,0.06), transparent 70%);
      border-radius: 50%; pointer-events: none;
    }}
    .hero-icon {{
      width: 52px; height: 52px;
      background: linear-gradient(135deg, #DBEAFE, #BAE6FD);
      border-radius: 14px; display: flex; align-items: center;
      justify-content: center; font-size: 1.4rem;
      box-shadow: 0 4px 12px rgba(37,99,235,0.12); margin-bottom: 1rem;
    }}
    .brand h1 {{ font-size: 2.2rem; letter-spacing: -1.5px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="hero-icon">🔐</div>
    <div class="brand">
      <h1>Welcome back</h1>
      <p>Sign in to Yosan</p>
    </div>
    <label for="loginEmail">Email Address</label>
    <input id="loginEmail" type="email" placeholder="you@email.com" />
    <label for="loginPass">Password</label>
    <input id="loginPass" type="password" placeholder="Your password" />
    <button id="loginButton" class="btn-primary">Sign In</button>
    <div id="out" class="msg"></div>
    <div class="footer">No account yet? <a href="/signup">Create one</a> &nbsp;·&nbsp; <a href="/">Home</a></div>
  </div>
<script>
async function doLogin() {{
  const out = document.getElementById('out');
  out.className = 'msg';
  const payload = {{ email: document.getElementById('loginEmail').value, password: document.getElementById('loginPass').value }};
  try {{
    const res = await fetch('/api/login', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(payload) }});
    const data = await res.json();
    if (!res.ok) throw data;
    localStorage.setItem('yosan_user', data.name);
    localStorage.setItem('yosan_role', data.role);
    if (data.role === 'user') {{
      localStorage.setItem('yosan_email', data.email);
    }} else {{
      localStorage.removeItem('yosan_email');
    }}
    out.className = 'msg success';
    out.textContent = 'Welcome back, ' + data.name + '! Redirecting…';
    setTimeout(() => {{
      window.location.href = data.role === 'admin' ? '/admin' : '/dashboard';
    }}, 700);
  }} catch(e) {{
    out.className = 'msg error';
    out.textContent = e.detail || 'Something went wrong.';
  }}
}}

document.addEventListener('DOMContentLoaded', function() {{
  const loginButton = document.getElementById('loginButton');
  if (loginButton) {{
    loginButton.addEventListener('click', doLogin);
  }}
}});
</script>
</body>
</html>
"""

DASHBOARD_HTML = f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Dashboard — Yosan</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap');
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html, body {{
      height: 100%; font-family: 'DM Sans', sans-serif;
      background: linear-gradient(145deg, #EEF4FF 0%, #DBEAFE 50%, #BAE6FD 100%);
      min-height: 100vh;
    }}
    .shell {{ display: flex; height: 100vh; overflow: hidden; }}

    /* ── Sidebar ── */
    .sidebar {{
      width: 240px; flex-shrink: 0;
      background: linear-gradient(180deg, #1D4ED8 0%, #2563EB 60%, #1E40AF 100%);
      box-shadow: 4px 0 20px rgba(29,78,216,0.25);
      display: flex; flex-direction: column; position: relative; z-index: 2;
    }}
    .sidebar-brand {{
      display: flex; align-items: center; gap: 10px;
      padding: 1.5rem 1.4rem 1.2rem;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }}
    .sidebar-brand-icon {{
      width: 36px; height: 36px; background: rgba(255,255,255,0.15);
      border-radius: 10px; display: flex; align-items: center;
      justify-content: center; font-size: 1.1rem; border: 1px solid rgba(255,255,255,0.2);
    }}
    .sidebar-brand-text .name {{
      font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1.2rem;
      font-weight: 800; color: #fff; letter-spacing: -0.8px;
    }}
    .sidebar-brand-text .sub {{
      font-size: 0.68rem; color: rgba(255,255,255,0.5); margin-top: 1px;
      text-transform: uppercase; letter-spacing: 0.5px;
    }}
    .nav-section {{ padding: 1rem 0.8rem 0.4rem; }}
    .nav-section-label {{
      font-size: 0.65rem; font-weight: 700; color: rgba(255,255,255,0.35);
      text-transform: uppercase; letter-spacing: 1px; padding: 0 0.6rem;
    }}
    .nav-item {{
      display: flex; align-items: center; gap: 10px;
      padding: 0.75rem 1rem; cursor: pointer;
      background: transparent; border-radius: 10px; margin: 2px 0.4rem;
      text-decoration: none; transition: background 0.15s;
      border: none; width: calc(100% - 0.8rem); color: rgba(255,255,255,0.65);
    }}
    .nav-item:hover {{ background: rgba(255,255,255,0.1); color: #fff; }}
    .nav-item.active {{
      background: rgba(255,255,255,0.15); color: #fff;
      box-shadow: inset 0 0 0 1px rgba(255,255,255,0.15);
    }}
    .nav-item .nav-label {{ font-family: 'DM Sans', sans-serif; font-size: 0.88rem; font-weight: 600; }}
    .nav-icon {{ font-size: 1rem; width: 22px; text-align: center; flex-shrink: 0; }}
    .sidebar-spacer {{ flex: 1; }}
    .sidebar-logout {{ padding: 1rem 1.2rem 1.2rem; border-top: 1px solid rgba(255,255,255,0.1); }}
    .sidebar-logout a {{
      display: flex; align-items: center; gap: 8px; padding: 10px 14px;
      border-radius: 10px; background: rgba(255,255,255,0.08);
      color: rgba(255,255,255,0.7); font-family: 'DM Sans', sans-serif;
      font-size: 0.88rem; font-weight: 600; text-decoration: none; transition: all 0.15s;
    }}
    .sidebar-logout a:hover {{ background: rgba(255,255,255,0.15); color: #fff; }}

    /* ── Main ── */
    .main {{ flex: 1; display: flex; flex-direction: column; overflow-y: auto; }}
    .topbar {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 1rem 2rem; background: rgba(255,255,255,0.9);
      backdrop-filter: blur(12px); border-bottom: 1px solid rgba(147,197,253,0.3);
      box-shadow: 0 1px 8px rgba(37,99,235,0.06); position: sticky; top: 0; z-index: 1;
    }}
    .topbar-title {{ font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1.15rem; font-weight: 700; color: #1E293B; letter-spacing: -0.5px; }}
    .topbar-user {{ display: flex; align-items: center; gap: 10px; }}
    .topbar-user-avatar {{
      width: 34px; height: 34px;
      background: linear-gradient(135deg, #2563EB, #38BDF8);
      border-radius: 50%; display: flex; align-items: center;
      justify-content: center; font-size: 0.85rem; font-weight: 700; color: #fff;
    }}
    .topbar-user-name {{ font-family: 'DM Sans', sans-serif; font-size: 0.9rem; font-weight: 600; color: #334155; }}

    /* ── Views ── */
    .view {{ display: none; padding: 1.8rem 2rem 2rem; flex: 1; }}
    .view.active {{ display: block; }}

    /* ── Panels ── */
    .panel {{
      background: rgba(255,255,255,0.85); border: 1px solid rgba(147,197,253,0.3);
      border-radius: 16px; box-shadow: 0 4px 16px rgba(37,99,235,0.07); padding: 1.5rem;
    }}
    .panel-header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.2rem; }}
    .panel-title {{ font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1rem; font-weight: 700; color: #1E293B; letter-spacing: -0.3px; }}

    .stats-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr)); gap: 0.9rem; margin-bottom: 1.4rem; }}
    .stat-card {{
      background: #fff; border: 1px solid rgba(147,197,253,0.35);
      border-radius: 14px; box-shadow: 0 2px 8px rgba(37,99,235,0.06); padding: 1.1rem 1.2rem;
    }}
    .stat-label {{ font-family: 'DM Sans', sans-serif; font-size: 0.75rem; color: #64748B; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; }}
    .stat-value {{ font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1.9rem; font-weight: 800; color: #1E293B; letter-spacing: -1.5px; line-height: 1.1; margin-top: 4px; }}
    .stat-icon {{ font-size: 1.3rem; margin-bottom: 4px; }}

    .refresh-btn {{
      padding: 7px 18px; background: linear-gradient(135deg, #2563EB, #38BDF8);
      border: none; border-radius: 8px; font-family: 'DM Sans', sans-serif;
      font-size: 0.82rem; font-weight: 700; color: #fff; cursor: pointer;
      box-shadow: 0 2px 8px rgba(37,99,235,0.3); transition: all 0.15s;
    }}
    .refresh-btn:hover {{ transform: translateY(-1px); box-shadow: 0 4px 12px rgba(37,99,235,0.4); }}

    .filter-row {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }}
    .filter-btn {{
      padding: 5px 16px; border-radius: 8px; border: 1.5px solid #BFDBFE;
      background: #fff; font-family: 'DM Sans', sans-serif; font-size: 0.8rem;
      font-weight: 600; color: #2563EB; cursor: pointer; transition: all 0.12s;
    }}
    .filter-btn.active, .filter-btn:hover {{ background: #2563EB; border-color: #2563EB; color: #fff; }}

    .log-table {{ width: 100%; border-collapse: collapse; }}
    .log-table th {{
      text-align: left; font-family: 'DM Sans', sans-serif; font-size: 0.75rem;
      font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.4px;
      padding-bottom: 10px; border-bottom: 1.5px solid #E2E8F0;
    }}
    .log-table td {{
      padding: 10px 0; font-size: 0.87rem; color: #334155; font-weight: 500;
      border-bottom: 1px solid #F1F5F9;
    }}
    .log-table tr:last-child td {{ border-bottom: none; }}
    .log-table tr:hover td {{ background: #F8FAFF; }}
    .badge {{
      display: inline-block; padding: 3px 10px; border-radius: 6px;
      font-size: 0.72rem; font-weight: 700; font-family: 'DM Sans', sans-serif;
      text-transform: uppercase; letter-spacing: 0.3px;
    }}
    .badge-success {{ background: #ECFDF5; color: #059669; }}
    .badge-failed  {{ background: #FEF2F2; color: #DC2626; }}
    .badge-motion  {{ background: #FFF7ED; color: #EA580C; }}
    .no-logs {{ text-align: center; padding: 2rem; font-family: 'DM Sans', sans-serif; color: #94A3B8; font-size: 0.9rem; }}

    /* ── Camera view ── */
    .cam-wrap {{ display: flex; flex-direction: column; align-items: center; gap: 1.2rem; }}
    .cam-video-box {{
      width: 100%; max-width: 700px; border-radius: 14px;
      border: 2px solid #BFDBFE; background: #0F172A; overflow: hidden;
      box-shadow: 0 6px 24px rgba(37,99,235,0.12);
      min-height: 200px; display: flex; align-items: center; justify-content: center;
      position: relative;
    }}
    .cam-placeholder {{ font-family: 'DM Sans', sans-serif; color: #38BDF8; font-size: 0.95rem; padding: 3rem; text-align: center; opacity: 0.7; }}
    .motion-indicator {{
      position: absolute; top: 12px; right: 12px;
      background: rgba(0,0,0,0.6); border-radius: 8px;
      padding: 5px 12px; font-family: 'DM Sans', sans-serif;
      font-size: 0.8rem; font-weight: 700; color: #fff;
      display: none;
    }}
    .motion-indicator.visible {{ display: block; }}
    .motion-indicator.alert {{ background: rgba(220,38,38,0.85); animation: pulse 1s infinite; }}
    .motion-indicator.ok {{ background: rgba(5,150,105,0.85); }}
    @keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.6; }} }}
    .cam-controls {{ display: flex; gap: 0.8rem; flex-wrap: wrap; justify-content: center; }}
    .cam-btn {{
      padding: 10px 22px; border-radius: 8px; border: none;
      background: linear-gradient(135deg, #2563EB, #38BDF8); color: #fff;
      font-family: 'DM Sans', sans-serif; font-size: 0.9rem; font-weight: 600;
      cursor: pointer; box-shadow: 0 3px 10px rgba(37,99,235,0.3); transition: all 0.15s;
    }}
    .cam-btn:hover {{ transform: translateY(-1px); box-shadow: 0 5px 14px rgba(37,99,235,0.4); }}
    .cam-btn:active {{ transform: translateY(1px); }}
    .cam-btn-red {{ background: linear-gradient(135deg, #EF4444, #F87171); box-shadow: 0 3px 10px rgba(239,68,68,0.3); }}
    .cam-btn-red:hover {{ box-shadow: 0 5px 14px rgba(239,68,68,0.4); }}
    .cam-btn-green {{ background: linear-gradient(135deg, #059669, #34D399); box-shadow: 0 3px 10px rgba(5,150,105,0.3); }}
    #cam-status {{ font-family: 'DM Sans', sans-serif; font-size: 0.88rem; color: #64748B; min-height: 1.4rem; font-weight: 500; }}

    @media (max-width: 700px) {{
      .sidebar {{ width: 56px; }}
      .nav-label, .sidebar-brand-text, .nav-section-label {{ display: none; }}
      .sidebar-logout a {{ font-size: 0; padding: 10px 0; justify-content: center; }}
    }}

    /* ── Welcome Banner ── */
    .welcome-banner {{
      display: flex; align-items: center; justify-content: space-between;
      background: linear-gradient(135deg, #1D4ED8 0%, #38BDF8 100%);
      border-radius: 16px; padding: 1.4rem 1.6rem; margin-bottom: 1.4rem;
      color: #fff; box-shadow: 0 6px 24px rgba(37,99,235,0.25);
    }}
    .welcome-left {{ display: flex; align-items: center; gap: 1rem; }}
    .welcome-avatar {{
      width: 52px; height: 52px; background: rgba(255,255,255,0.2);
      border-radius: 50%; display: flex; align-items: center; justify-content: center;
      font-size: 1.4rem; font-weight: 800; color: #fff;
      border: 2px solid rgba(255,255,255,0.3);
    }}
    .welcome-name {{ font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1.1rem; font-weight: 700; }}
    .welcome-sub {{ font-size: 0.82rem; opacity: 0.75; margin-top: 2px; }}
    .welcome-time {{ font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1.5rem; font-weight: 800; opacity: 0.9; letter-spacing: -1px; }}

    /* ── Info Grid ── */
    .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px,1fr)); gap: 1rem; margin-top: 1rem; }}
    .info-card {{
      background: rgba(255,255,255,0.85); border: 1px solid rgba(147,197,253,0.3);
      border-radius: 14px; padding: 1.2rem; box-shadow: 0 2px 10px rgba(37,99,235,0.06);
    }}
    .info-card-header {{ font-family: 'Plus Jakarta Sans', sans-serif; font-size: 0.92rem; font-weight: 700; color: #1E293B; margin-bottom: 0.9rem; }}
    .info-card-body {{ display: flex; flex-direction: column; gap: 0.6rem; }}
    .quick-btn {{
      padding: 10px 16px; border-radius: 10px; border: 1.5px solid #BFDBFE;
      background: #EFF6FF; color: #2563EB; font-family: 'DM Sans', sans-serif;
      font-size: 0.88rem; font-weight: 600; cursor: pointer; text-align: left;
      transition: all 0.15s;
    }}
    .quick-btn:hover {{ background: #2563EB; color: #fff; border-color: #2563EB; }}
    .tips-list {{ gap: 0.5rem; }}
    .tip-item {{ font-size: 0.85rem; color: #475569; padding: 6px 0; border-bottom: 1px solid #F1F5F9; }}
    .tip-item:last-child {{ border-bottom: none; }}

    /* ── Account View ── */
    .account-avatar-row {{ display: flex; align-items: center; gap: 1.2rem; margin-bottom: 1.5rem; padding-bottom: 1.2rem; border-bottom: 1px solid #E2E8F0; }}
    .account-big-avatar {{
      width: 64px; height: 64px; background: linear-gradient(135deg, #2563EB, #38BDF8);
      border-radius: 50%; display: flex; align-items: center; justify-content: center;
      font-size: 1.8rem; font-weight: 800; color: #fff;
    }}
    .account-name {{ font-family: 'Plus Jakarta Sans', sans-serif; font-size: 1.3rem; font-weight: 700; color: #1E293B; }}
    .account-role-badge {{
      display: inline-block; padding: 3px 12px; border-radius: 20px;
      background: #EFF6FF; color: #2563EB; font-size: 0.75rem; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px;
    }}
    .account-info-row {{ display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #F1F5F9; }}
    .account-info-row:last-of-type {{ border-bottom: none; }}
    .account-info-label {{ font-size: 0.82rem; color: #64748B; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; }}
    .account-info-val {{ font-size: 0.92rem; color: #1E293B; font-weight: 600; }}
  </style>
</head>
<body>
<div class="shell">

  <aside class="sidebar" aria-label="Sidebar navigation">
    <div class="sidebar-brand">
      <div class="sidebar-brand-icon">🎥</div>
      <div class="sidebar-brand-text">
        <div class="name">Yosan</div>
        <div class="sub">My Dashboard</div>
      </div>
    </div>
    <div class="nav-section">
      <div class="nav-section-label">Main Menu</div>
    </div>
    <button class="nav-item active" id="nav-home" onclick="showView('home')">
      <span class="nav-icon">🏠</span>
      <span class="nav-label">Overview</span>
    </button>
    <button class="nav-item" id="nav-camera" onclick="showView('camera')">
      <span class="nav-icon">📷</span>
      <span class="nav-label">Camera</span>
    </button>
    <button class="nav-item" id="nav-account" onclick="showView('account')">
      <span class="nav-icon">👤</span>
      <span class="nav-label">My Account</span>
    </button>
    <div class="sidebar-spacer"></div>
    <div class="sidebar-logout">
      <a href="/" onclick="disconnectCctv(); localStorage.removeItem('yosan_user'); localStorage.removeItem('yosan_email'); localStorage.removeItem('yosan_role');">
        <span>🚪</span> Sign Out
      </a>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <span class="topbar-title" id="page-title">Camera</span>
      <div class="topbar-user">
        <div class="topbar-user-avatar" id="user-avatar">?</div>
        <span class="topbar-user-name" id="username">friend</span>
      </div>
    </header>

    <!-- ── View: Overview ── -->
    <div class="view active" id="view-home">
      <div class="welcome-banner">
        <div class="welcome-left">
          <div class="welcome-avatar" id="home-avatar">?</div>
          <div>
            <div class="welcome-name">Welcome back, <span id="home-username">friend</span>! 👋</div>
            <div class="welcome-sub">Here's what's happening with your cameras today.</div>
          </div>
        </div>
        <div class="welcome-time" id="welcome-clock"></div>
      </div>

      <div class="stats-row">
        <div class="stat-card">
          <div class="stat-icon">📋</div>
          <div class="stat-label">Events Today</div>
          <div class="stat-value" id="ov-events-today">—</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">📊</div>
          <div class="stat-label">Total Events</div>
          <div class="stat-value" id="ov-events-total">—</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">🔴</div>
          <div class="stat-label">Camera</div>
          <div class="stat-value" id="ov-cam-status" style="font-size:1rem;margin-top:8px;">Offline</div>
        </div>
      </div>

      <div class="info-grid">
        <div class="info-card">
          <div class="info-card-header">🚀 Quick Actions</div>
          <div class="info-card-body">
            <button class="quick-btn" onclick="showView('camera')">📷 Open Camera</button>
            <button class="quick-btn" onclick="showView('account')">👤 My Account</button>
          </div>
        </div>
        <div class="info-card">
          <div class="info-card-header">💡 Tips</div>
          <div class="info-card-body tips-list">
            <div class="tip-item">🔒 Keep your password strong and unique.</div>
            <div class="tip-item">🎯 Motion detection works best in stable lighting.</div>
            <div class="tip-item">📷 Use Connect CCTV to view your remote camera feed.</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ── View: Camera ── -->
    <div class="view" id="view-camera">
      <div class="stats-row">
        <div class="stat-card">
          <div class="stat-icon">🔴</div>
          <div class="stat-label">Camera Status</div>
          <div class="stat-value" id="stat-cam-status" style="font-size:1.1rem;margin-top:8px;">Offline</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">🎯</div>
          <div class="stat-label">Motion</div>
          <div class="stat-value" id="stat-motion" style="font-size:1.1rem;margin-top:8px;">—</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">📋</div>
          <div class="stat-label">Events Today</div>
          <div class="stat-value" id="stat-events-today">—</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">📊</div>
          <div class="stat-label">Total Events</div>
          <div class="stat-value" id="stat-events-total">—</div>
        </div>
      </div>

      <div class="panel cam-wrap">
        <div class="cam-video-box" id="cam-box">
          <div class="cam-placeholder" id="cam-placeholder">🎥<br><br>Click <b>Connect CCTV</b> to view<br>your camera feed</div>
          <img id="cctv-img" alt="CCTV feed" style="display:none; width:100%; border-radius:12px; object-fit:cover;" />
          <canvas id="motion-canvas" style="display:none;"></canvas>
          <div class="motion-indicator" id="motion-indicator">● Monitoring</div>
        </div>
        <div class="cam-controls" style="margin-top:1rem;">
          <button class="cam-btn cam-btn-green" onclick="connectCctv()">▶ Connect CCTV</button>
          <button class="cam-btn cam-btn-red" onclick="disconnectCctv()">■ Disconnect CCTV</button>
        </div>
        <div id="cctv-feedback" style="margin-top:0.8rem; font-size:0.9rem; color:#334155;"></div>
        <p id="cam-status"></p>
      </div>
    </div>

    <!-- ── View: My Account ── -->
    <div class="view" id="view-account">
      <div class="panel" style="max-width:520px;">
        <div class="panel-header">
          <span class="panel-title">👤 My Account</span>
        </div>
        <div class="account-avatar-row">
          <div class="account-big-avatar" id="acct-avatar">?</div>
          <div>
            <div class="account-name" id="acct-name">—</div>
            <div class="account-role-badge">User</div>
          </div>
        </div>
        <div class="account-info-row"><span class="account-info-label">Logged in as</span><span class="account-info-val" id="acct-name2">—</span></div>
        <div class="account-info-row"><span class="account-info-label">Role</span><span class="account-info-val">Standard User</span></div>
        <div class="account-info-row"><span class="account-info-label">Session</span><span class="account-info-val" id="acct-session">Active</span></div>
        <div style="margin-top:1.5rem;">
          <a href="/" onclick="disconnectCctv(); localStorage.removeItem('yosan_user'); localStorage.removeItem('yosan_email'); localStorage.removeItem('yosan_role');" class="cam-btn cam-btn-red" style="display:inline-flex;align-items:center;gap:8px;text-decoration:none;padding:10px 20px;border-radius:8px;">🚪 Sign Out</a>
        </div>
      </div>
    </div>


</div><!-- .shell -->

<script>
  // ── Activity tracking (regular users only) ──
  async function trackActivity(action) {{
    const email = localStorage.getItem('yosan_email');
    if (!email || localStorage.getItem('yosan_role') === 'admin') return;
    try {{
      await fetch('/api/user/log-activity', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ email, action }})
      }});
    }} catch (e) {{}}
  }}

  document.addEventListener('click', (e) => {{
    const el = e.target.closest('button, a.quick-btn, .nav-item, .cam-btn, a[href="/"]');
    if (!el) return;
    const label = (el.textContent || '').trim().replace(/\\s+/g, ' ').substring(0, 80);
    if (label) trackActivity('Clicked: ' + label);
  }});

  // ── Username ──
  const storedName = localStorage.getItem('yosan_user');
  if (!storedName || !localStorage.getItem('yosan_email')) {{
    window.location.href = '/login';
  }}
  if (storedName) {{
    document.getElementById('username').textContent = storedName;
    document.getElementById('user-avatar').textContent = storedName.charAt(0).toUpperCase();
    document.getElementById('home-username').textContent = storedName;
    document.getElementById('home-avatar').textContent = storedName.charAt(0).toUpperCase();
    document.getElementById('acct-avatar').textContent = storedName.charAt(0).toUpperCase();
    document.getElementById('acct-name').textContent = storedName;
    document.getElementById('acct-name2').textContent = storedName;
  }}

  // ── Live clock ──
  function updateClock() {{
    const now = new Date();
    document.getElementById('welcome-clock').textContent =
      now.toLocaleTimeString([], {{ hour: '2-digit', minute: '2-digit' }});
  }}
  updateClock(); setInterval(updateClock, 1000);

  // ── View switching ──
  function showView(name) {{
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    document.getElementById('view-' + name).classList.add('active');
    document.getElementById('nav-' + name).classList.add('active');
    const titles = {{ home: 'Overview', camera: 'Camera', account: 'My Account' }};
    document.getElementById('page-title').textContent = titles[name] || name;
    trackActivity('Opened view: ' + name);
  }}

  // ── CCTV + motion detection ──
  let cctvImage     = null;
  let cctvConnected = false;
  let motionTimer   = null;
  let prevPixels    = null;
  let motionActive  = false;
  let motionStart   = null;
  let eventsToday   = 0;
  let eventsTotal   = 0;
  const MOTION_THRESHOLD  = 30;
  const MOTION_MIN_PCT    = 0.8;
  const MOTION_COOLDOWN   = 4000;
  let lastMotionLog = 0;

  const CCTV_STREAM_URL = '{cctv_remote_url()}';
  const CCTV_PROXY_PATH = '/api/cctv/stream';

  function connectCctv() {{
    const feedback = document.getElementById('cctv-feedback');
    disconnectCctv();
    trackActivity('Connected CCTV');

    const img = document.getElementById('cctv-img');

    feedback.textContent = 'Connecting to CCTV…';
    feedback.style.color = '#64748B';
    document.getElementById('cam-status').textContent = '⏳ Connecting to CCTV...';
    document.getElementById('cam-status').style.color = '#64748B';

    function onConnected() {{
      img.style.display = 'block';
      cctvConnected = true;
      cctvImage = img;
      document.getElementById('cam-placeholder').style.display = 'none';
      document.getElementById('stat-cam-status').textContent = 'Live';
      document.getElementById('stat-cam-status').style.color = '#059669';
      document.getElementById('ov-cam-status').textContent = 'Live';
      document.getElementById('ov-cam-status').style.color = '#059669';
      document.getElementById('cam-status').textContent = '🟢 CCTV feed connected.';
      document.getElementById('cam-status').style.color = '#059669';
      feedback.textContent = 'CCTV connected.';
      feedback.style.color = '#059669';
      document.getElementById('motion-indicator').className = 'motion-indicator visible ok';
      document.getElementById('motion-indicator').textContent = '● Monitoring';
      prevPixels = null;
      startMotionDetection();
    }}

    function onFailed() {{
      img.style.display = 'none';
      cctvConnected = false;
      cctvImage = null;
      document.getElementById('cam-placeholder').style.display = 'block';
      document.getElementById('cam-status').textContent = '🔴 Could not load CCTV stream.';
      document.getElementById('cam-status').style.color = '#DC2626';
      feedback.textContent = 'Could not load CCTV. Is cloudflared running and exposing /stream?';
      feedback.style.color = '#DC2626';
    }}

    let attempt = 0;
    img.onload = onConnected;
    img.onerror = () => {{
      attempt += 1;
      if (attempt === 1) {{
        feedback.textContent = 'Trying direct tunnel URL…';
        img.src = CCTV_STREAM_URL + '?t=' + Date.now();
      }} else if (attempt === 2) {{
        feedback.textContent = 'Trying server proxy…';
        img.src = CCTV_PROXY_PATH + '?t=' + Date.now();
      }} else {{
        onFailed();
      }}
    }};

    // Same-origin proxy first (most reliable from the dashboard)
    img.src = CCTV_PROXY_PATH + '?t=' + Date.now();
  }}

  function disconnectCctv() {{
    trackActivity('Disconnected CCTV');
    if (motionTimer) {{ clearInterval(motionTimer); motionTimer = null; }}
    prevPixels = null;
    motionActive = false;
    const img = document.getElementById('cctv-img');
    const feedback = document.getElementById('cctv-feedback');
    img.onload = null;
    img.onerror = null;
    img.src = '';
    img.style.display = 'none';
    cctvConnected = false;
    cctvImage = null;
    document.getElementById('cam-placeholder').style.display = 'block';
    document.getElementById('cam-status').textContent = '⏹ CCTV disconnected';
    document.getElementById('cam-status').style.color = '#64748B';
    document.getElementById('stat-cam-status').textContent = 'Offline';
    document.getElementById('stat-cam-status').style.color = '#DC2626';
    document.getElementById('ov-cam-status').textContent = 'Offline';
    document.getElementById('ov-cam-status').style.color = '#DC2626';
    document.getElementById('motion-indicator').className = 'motion-indicator';
    document.getElementById('stat-motion').textContent = '—';
    document.getElementById('stat-motion').style.color = '';
    feedback.textContent = 'CCTV disconnected.';
    feedback.style.color = '#64748B';
  }}

  function startMotionDetection() {{
    const img    = document.getElementById('cctv-img');
    const canvas = document.getElementById('motion-canvas');
    const W = 160, H = 120;
    canvas.width  = W;
    canvas.height = H;
    const ctx = canvas.getContext('2d');

    if (motionTimer) clearInterval(motionTimer);
    motionTimer = setInterval(() => {{
      if (!cctvConnected || !img.complete || !img.naturalWidth) return;
      ctx.drawImage(img, 0, 0, W, H);
      const frame = ctx.getImageData(0, 0, W, H).data;  // RGBA flat array

      if (!prevPixels) {{ prevPixels = frame.slice(); return; }}

      // Count changed pixels
      let changed = 0;
      const total = W * H;
      for (let i = 0; i < frame.length; i += 4) {{
        const dr = Math.abs(frame[i]   - prevPixels[i]);
        const dg = Math.abs(frame[i+1] - prevPixels[i+1]);
        const db = Math.abs(frame[i+2] - prevPixels[i+2]);
        if (dr > MOTION_THRESHOLD || dg > MOTION_THRESHOLD || db > MOTION_THRESHOLD) changed++;
      }}
      prevPixels = frame.slice();

      const pct = (changed / total) * 100;
      const detected = pct >= MOTION_MIN_PCT;
      const ind  = document.getElementById('motion-indicator');
      const stat = document.getElementById('stat-motion');

      if (detected) {{
        ind.className = 'motion-indicator visible alert';
        ind.textContent = '⚠ MOTION DETECTED';
        stat.textContent = '⚠ Motion';
        stat.style.color = '#DC2626';

        if (!motionActive) {{
          motionActive = true;
          motionStart  = new Date();
        }}

        // Log event with cooldown
        const now = Date.now();
        if (now - lastMotionLog > MOTION_COOLDOWN) {{
          lastMotionLog = now;
          logMotionEvent();
        }}
      }} else {{
        ind.className = 'motion-indicator visible ok';
        ind.textContent = '● Monitoring';
        stat.textContent = 'Clear';
        stat.style.color = '#059669';
        motionActive = false;
        motionStart  = null;
      }}
    }}, 200);  // check 5× per second
  }}

  async function logMotionEvent() {{
    const now = new Date().toISOString().replace('T',' ').substring(0,19);
    try {{
      await fetch('/api/motion/log', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ start_time: now, end_time: now, duration_seconds: 0 }})
      }});
      eventsTotal++;
      eventsToday++;
      document.getElementById('stat-events-today').textContent = eventsToday;
      document.getElementById('stat-events-total').textContent = eventsTotal;
    }} catch(e) {{}}
  }}

  // ── Motion Events ──
  async function loadMotionEvents() {{
    document.getElementById('motion-log-container').innerHTML = '<div class="no-logs">Loading…</div>';
    try {{
      const res  = await fetch('/api/motion/events?limit=200');
      const data = await res.json();
      const events = data.events || [];
      document.getElementById('stat-events-today').textContent = data.today_count ?? '—';
      document.getElementById('stat-events-total').textContent = data.total ?? '—';
      if (!events.length) {{
        document.getElementById('motion-log-container').innerHTML = '<div class="no-logs">No motion events recorded yet.</div>';
        return;
      }}
      const rows = events.map(e => `
        <tr>
          <td style="color:#94A3B8;font-size:0.8rem;">${{e.id}}</td>
          <td>${{escHtml(e.start_time)}}</td>
          <td>${{e.end_time ? escHtml(e.end_time) : '<span style="color:#bbb;">ongoing</span>'}}</td>
          <td>${{e.duration_seconds != null ? e.duration_seconds.toFixed(2) + 's' : '—'}}</td>
        </tr>`).join('');
      document.getElementById('motion-log-container').innerHTML = `
        <table class="log-table">
          <thead><tr><th>#</th><th>Start Time</th><th>End Time</th><th>Duration</th></tr></thead>
          <tbody>${{rows}}</tbody>
        </table>`;
    }} catch(e) {{
      document.getElementById('motion-log-container').innerHTML = '<div class="no-logs">⚠️ Could not load motion events.</div>';
    }}
  }}


  function escHtml(s) {{
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }}

  // Boot — load initial event counts for overview + camera view
  trackActivity('Opened dashboard');
  (async () => {{
    try {{
      const res = await fetch('/api/motion/events?limit=1');
      const data = await res.json();
      const today = data.today_count ?? '0';
      const total = data.total ?? '0';
      document.getElementById('stat-events-today').textContent = today;
      document.getElementById('stat-events-total').textContent = total;
      document.getElementById('ov-events-today').textContent = today;
      document.getElementById('ov-events-total').textContent = total;
    }} catch(e) {{}}
  }})();
</script>
</body>
</html>
"""

ADMIN_HTML = f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Admin — Yosan</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap');
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html, body {{ height: 100%; font-family: 'DM Sans', sans-serif; background: linear-gradient(145deg,#0F172A 0%,#1E293B 100%); min-height: 100vh; color: #E2E8F0; }}
    .shell {{ display: flex; height: 100vh; overflow: hidden; }}
    .sidebar {{ width: 230px; flex-shrink: 0; background: #0F172A; border-right: 1px solid rgba(255,255,255,0.07); display: flex; flex-direction: column; }}
    .sidebar-brand {{ padding: 1.4rem 1.2rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.07); }}
    .sidebar-brand .name {{ font-family: 'Plus Jakarta Sans',sans-serif; font-size: 1.2rem; font-weight: 800; color: #F59E0B; letter-spacing: -0.5px; }}
    .sidebar-brand .sub {{ font-size: 0.68rem; color: rgba(255,255,255,0.3); text-transform: uppercase; letter-spacing: 0.5px; }}
    .nav-item {{ display: flex; align-items: center; gap: 10px; padding: 0.7rem 1rem; cursor: pointer; background: transparent; border-radius: 8px; margin: 2px 0.6rem; border: none; width: calc(100% - 1.2rem); color: rgba(255,255,255,0.5); font-family: 'DM Sans',sans-serif; font-size: 0.88rem; font-weight: 600; transition: all 0.15s; text-align: left; }}
    .nav-item:hover {{ background: rgba(255,255,255,0.06); color: #fff; }}
    .nav-item.active {{ background: rgba(245,158,11,0.15); color: #F59E0B; }}
    .nav-icon {{ font-size: 1rem; width: 20px; text-align: center; }}
    .sidebar-spacer {{ flex: 1; }}
    .sidebar-logout {{ padding: 1rem; border-top: 1px solid rgba(255,255,255,0.07); }}
    .sidebar-logout a {{ display: flex; align-items: center; gap: 8px; padding: 9px 12px; border-radius: 8px; background: rgba(239,68,68,0.1); color: #FCA5A5; font-size: 0.85rem; font-weight: 600; text-decoration: none; transition: all 0.15s; }}
    .sidebar-logout a:hover {{ background: rgba(239,68,68,0.2); color: #fff; }}
    .main {{ flex: 1; display: flex; flex-direction: column; overflow-y: auto; }}
    .topbar {{ display: flex; align-items: center; justify-content: space-between; padding: 1rem 2rem; background: rgba(15,23,42,0.8); backdrop-filter: blur(12px); border-bottom: 1px solid rgba(255,255,255,0.07); position: sticky; top: 0; z-index: 1; }}
    .topbar-title {{ font-family: 'Plus Jakarta Sans',sans-serif; font-size: 1.1rem; font-weight: 700; color: #F59E0B; }}
    .topbar-badge {{ background: rgba(245,158,11,0.15); border: 1px solid rgba(245,158,11,0.3); color: #F59E0B; font-size: 0.72rem; font-weight: 700; padding: 3px 10px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.5px; }}
    .view {{ display: none; padding: 1.8rem 2rem; flex: 1; }}
    .view.active {{ display: block; }}
    .panel {{ background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 1.4rem; margin-bottom: 1.2rem; }}
    .panel-header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.1rem; }}
    .panel-title {{ font-family: 'Plus Jakarta Sans',sans-serif; font-size: 1rem; font-weight: 700; color: #F1F5F9; }}
    .stats-row {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(140px,1fr)); gap: 0.9rem; margin-bottom: 1.4rem; }}
    .stat-card {{ background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 1.1rem; text-align: center; }}
    .stat-icon {{ font-size: 1.4rem; margin-bottom: 0.4rem; }}
    .stat-label {{ font-size: 0.72rem; font-weight: 600; color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
    .stat-value {{ font-family: 'Plus Jakarta Sans',sans-serif; font-size: 1.6rem; font-weight: 800; color: #F1F5F9; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    thead th {{ text-align: left; padding: 8px 10px; font-size: 0.72rem; font-weight: 700; color: rgba(255,255,255,0.35); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid rgba(255,255,255,0.07); }}
    tbody tr {{ border-bottom: 1px solid rgba(255,255,255,0.04); transition: background 0.1s; }}
    tbody tr:hover {{ background: rgba(255,255,255,0.03); }}
    tbody td {{ padding: 9px 10px; color: #CBD5E1; }}
    .badge {{ display: inline-block; padding: 2px 9px; border-radius: 20px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }}
    .badge-success {{ background: rgba(16,185,129,0.15); color: #6EE7B7; }}
    .badge-failed  {{ background: rgba(239,68,68,0.15);  color: #FCA5A5; }}
    .btn {{ padding: 7px 16px; border: none; border-radius: 8px; font-family: 'DM Sans',sans-serif; font-size: 0.82rem; font-weight: 700; cursor: pointer; transition: all 0.15s; }}
    .btn-amber {{ background: rgba(245,158,11,0.15); color: #F59E0B; border: 1px solid rgba(245,158,11,0.3); }}
    .btn-amber:hover {{ background: rgba(245,158,11,0.25); }}
    .btn-danger {{ background: rgba(239,68,68,0.15); color: #FCA5A5; border: 1px solid rgba(239,68,68,0.3); font-size: 0.78rem; padding: 4px 12px; }}
    .btn-danger:hover {{ background: rgba(239,68,68,0.3); }}
    .no-data {{ text-align: center; color: rgba(255,255,255,0.25); padding: 2rem; font-size: 0.88rem; }}
    .filter-row {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }}
    .filter-btn {{ padding: 5px 14px; border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; background: transparent; color: rgba(255,255,255,0.4); font-family: 'DM Sans',sans-serif; font-size: 0.78rem; font-weight: 600; cursor: pointer; transition: all 0.15s; }}
    .filter-btn.active {{ background: rgba(245,158,11,0.15); border-color: rgba(245,158,11,0.4); color: #F59E0B; }}

    /* ── Admin Camera view ── */
    .cam-wrap {{ display: flex; flex-direction: column; align-items: center; gap: 1.2rem; }}
    .cam-video-box {{
      width: 100%; max-width: 720px; border-radius: 14px;
      border: 2px solid rgba(245,158,11,0.35); background: #000; overflow: hidden;
      box-shadow: 0 6px 28px rgba(0,0,0,0.5);
      min-height: 200px; display: flex; align-items: center; justify-content: center;
      position: relative;
    }}
    .cam-placeholder {{ font-family: 'DM Sans', sans-serif; color: #F59E0B; font-size: 0.95rem; padding: 3rem; text-align: center; opacity: 0.6; }}
    .motion-indicator {{
      position: absolute; top: 12px; right: 12px;
      background: rgba(0,0,0,0.65); border-radius: 8px;
      padding: 5px 12px; font-family: 'DM Sans', sans-serif;
      font-size: 0.8rem; font-weight: 700; color: #fff; display: none;
    }}
    .motion-indicator.visible {{ display: block; }}
    .motion-indicator.alert {{ background: rgba(220,38,38,0.85); animation: mpulse 1s infinite; }}
    .motion-indicator.ok {{ background: rgba(5,150,105,0.85); }}
    @keyframes mpulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.6; }} }}
    .cam-controls {{ display: flex; gap: 0.8rem; flex-wrap: wrap; justify-content: center; }}
    .cam-btn {{
      padding: 10px 22px; border-radius: 8px; border: none;
      background: rgba(245,158,11,0.15); color: #F59E0B;
      border: 1px solid rgba(245,158,11,0.35);
      font-family: 'DM Sans', sans-serif; font-size: 0.9rem; font-weight: 700;
      cursor: pointer; transition: all 0.15s;
    }}
    .cam-btn:hover {{ background: rgba(245,158,11,0.28); }}
    .cam-btn-green {{ background: rgba(5,150,105,0.15); color: #34D399; border-color: rgba(52,211,153,0.35); }}
    .cam-btn-green:hover {{ background: rgba(5,150,105,0.28); }}
    .cam-btn-red {{ background: rgba(239,68,68,0.15); color: #FCA5A5; border-color: rgba(252,165,165,0.35); }}
    .cam-btn-red:hover {{ background: rgba(239,68,68,0.28); }}
    #adm-cam-status {{ font-family: 'DM Sans', sans-serif; font-size: 0.88rem; color: rgba(255,255,255,0.45); min-height: 1.4rem; font-weight: 500; }}
  </style>
</head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="sidebar-brand">
      <div class="name">🛡 Yosan Admin</div>
      <div class="sub">Control Panel</div>
    </div>
    <div style="padding:0.8rem 0.4rem 0;">
      <button class="nav-item active" id="nav-users" onclick="showView('users')"><span class="nav-icon">👥</span> Users</button>
      <button class="nav-item" id="nav-logs" onclick="showView('logs')"><span class="nav-icon">🛡️</span> Login Logs</button>
      <button class="nav-item" id="nav-camera" onclick="showView('camera')"><span class="nav-icon">📷</span> Camera</button>
    </div>
    <div class="sidebar-spacer"></div>
    <div class="sidebar-logout">
      <a href="/login" onclick="localStorage.clear()"><span>🚪</span> Sign Out</a>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <span class="topbar-title" id="page-title">User Management</span>
      <span class="topbar-badge">Admin</span>
    </header>

    <!-- Users -->
    <div class="view active" id="view-users">
      <div class="stats-row">
        <div class="stat-card"><div class="stat-icon">👥</div><div class="stat-label">Total Users</div><div class="stat-value" id="stat-users">—</div></div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Registered Users</span>
          <button class="btn btn-amber" onclick="loadUsers()">↻ Refresh</button>
        </div>
        <div id="users-container"><div class="no-data">Loading…</div></div>
      </div>
    </div>

    <!-- Login Logs -->
    <div class="view" id="view-logs">
      <div class="stats-row">
        <div class="stat-card"><div class="stat-icon">🔢</div><div class="stat-label">Total</div><div class="stat-value" id="stat-total">—</div></div>
        <div class="stat-card"><div class="stat-icon">✅</div><div class="stat-label">Success</div><div class="stat-value" id="stat-success" style="color:#6EE7B7;">—</div></div>
        <div class="stat-card"><div class="stat-icon">❌</div><div class="stat-label">Failed</div><div class="stat-value" id="stat-failed" style="color:#FCA5A5;">—</div></div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Login Activity</span>
          <button class="btn btn-amber" onclick="loadLogs()">↻ Refresh</button>
        </div>
        <div class="filter-row">
          <button class="filter-btn active" id="f-all"     onclick="setFilter('all')">All</button>
          <button class="filter-btn"        id="f-SUCCESS" onclick="setFilter('SUCCESS')">Success</button>
          <button class="filter-btn"        id="f-FAILED"  onclick="setFilter('FAILED')">Failed</button>
        </div>
        <div id="logs-container"><div class="no-data">Loading…</div></div>
      </div>
    </div>

    <!-- Camera -->
    <div class="view" id="view-camera">
      <div class="stats-row">
        <div class="stat-card"><div class="stat-icon">🔴</div><div class="stat-label">CCTV Status</div><div class="stat-value" id="adm-stat-cam" style="font-size:1.1rem;margin-top:8px;">Offline</div></div>
        <div class="stat-card"><div class="stat-icon">🎥</div><div class="stat-label">CCTV Screen</div><div class="stat-value" id="adm-stat-motion" style="font-size:1.1rem;margin-top:8px;">—</div></div>
      </div>

      <div class="panel cam-wrap">
        <div class="cam-video-box" id="adm-cam-box">
          <div class="cam-placeholder" id="adm-cam-placeholder">🎥<br><br>Click <b>Connect CCTV</b> to view<br>the camera feed</div>
          <img id="adm-cctv-img" alt="CCTV feed" style="display:none; width:100%; border-radius:12px; object-fit:cover;" />
          <canvas id="adm-motion-canvas" style="display:none;"></canvas>
          <div class="motion-indicator" id="adm-motion-indicator">● Monitoring</div>
        </div>
        <div class="cam-controls" style="margin-top:1rem;">
          <button class="cam-btn cam-btn-green" onclick="admConnectCctv()">▶ Connect CCTV</button>
          <button class="cam-btn cam-btn-red"   onclick="admDisconnectCctv()">■ Disconnect CCTV</button>
        </div>
        <div id="adm-cctv-feedback" style="margin-top:0.8rem; font-size:0.9rem; color:rgba(255,255,255,0.45);"></div>
        <p id="adm-cam-status"></p>
      </div>


    </div>
  </div>
</div>

<script>
  // Guard: redirect if not admin
  if (localStorage.getItem('yosan_role') !== 'admin') {{
    window.location.href = '/login';
  }}

  function showView(name) {{
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    document.getElementById('view-' + name).classList.add('active');
    document.getElementById('nav-' + name).classList.add('active');
    const titles = {{ users: 'User Management', logs: 'Login Logs', motion: 'Motion Events', camera: 'Camera' }};
    document.getElementById('page-title').textContent = titles[name];
    if (name === 'users')  loadUsers();
    if (name === 'logs')   loadLogs();
    if (name === 'motion') loadMotion();
    if (name === 'camera') admLoadMotionEvents();
  }}

  function esc(s) {{ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}

  function formatActivities(activities) {{
    if (!activities || !activities.length) {{
      return '<div style="font-size:0.78rem;color:rgba(255,255,255,0.25);font-style:italic;">No activity yet.</div>';
    }}
    const items = activities.map(a =>
      '<li style="margin-bottom:4px;font-size:0.78rem;color:rgba(255,255,255,0.55);">' +
      esc(a.action) + ' <span style="opacity:0.6">(' + esc(a.timestamp) + ')</span></li>'
    ).join('');
    return '<ul style="margin:0.5rem 0 0;padding-left:1rem;max-height:140px;overflow-y:auto;">' + items + '</ul>';
  }}

  // ── Users ──
  async function loadUsers() {{
    try {{
      const data = await fetch('/api/admin/users').then(r => r.json());
      document.getElementById('stat-users').textContent = data.users.length;
      if (!data.users.length) {{
        document.getElementById('users-container').innerHTML = '<div class="no-data">No registered users yet.</div>';
        return;
      }}
      const rows = data.users.map(u => `
        <tr>
          <td style="color:#64748B;font-size:0.78rem;">${{u.id}}</td>
          <td>
            <div style="font-weight:700;color:#F1F5F9;">${{esc(u.name)}}</div>
            <div style="font-family:monospace;font-size:0.8rem;color:#94A3B8;">${{esc(u.email)}}</div>
            ${{formatActivities(u.activities)}}
          </td>
          <td><button class="btn btn-danger" onclick="deleteUser(${{u.id}}, this)">🗑 Delete</button></td>
        </tr>`).join('');
      document.getElementById('users-container').innerHTML = `
        <table><thead><tr><th>#</th><th>User & Activity</th><th>Action</th></tr></thead>
        <tbody>${{rows}}</tbody></table>`;
    }} catch(e) {{
      document.getElementById('users-container').innerHTML = '<div class="no-data">⚠️ Failed to load users.</div>';
    }}
  }}

  async function deleteUser(id, btn) {{
    if (!confirm('Delete this user? This cannot be undone.')) return;
    btn.disabled = true; btn.textContent = '…';
    try {{
      await fetch('/api/admin/users/' + id, {{ method: 'DELETE' }});
      loadUsers();
    }} catch(e) {{ btn.disabled = false; btn.textContent = '🗑 Delete'; }}
  }}

  // ── Login Logs ──
  let allLogs = [], currentFilter = 'all';
  async function loadLogs() {{
    try {{
      const data = await fetch('/api/admin/logs?limit=200').then(r => r.json());
      allLogs = data.logs;
      document.getElementById('stat-total').textContent   = allLogs.length;
      document.getElementById('stat-success').textContent = allLogs.filter(l => l.status==='SUCCESS').length;
      document.getElementById('stat-failed').textContent  = allLogs.filter(l => l.status==='FAILED').length;
      renderLogs();
    }} catch(e) {{
      document.getElementById('logs-container').innerHTML = '<div class="no-data">⚠️ Failed to load logs.</div>';
    }}
  }}

  function setFilter(f) {{
    currentFilter = f;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('f-' + f).classList.add('active');
    renderLogs();
  }}

  function renderLogs() {{
    const filtered = currentFilter === 'all' ? allLogs : allLogs.filter(l => l.status === currentFilter);
    if (!filtered.length) {{ document.getElementById('logs-container').innerHTML = '<div class="no-data">No entries.</div>'; return; }}
    const rows = filtered.map(l => `
      <tr>
        <td style="color:#64748B;font-size:0.78rem;">${{l.id}}</td>
        <td style="font-family:monospace;font-size:0.82rem;">${{esc(l.email)}}</td>
        <td>${{esc(l.name || '—')}}</td>
        <td><span class="badge badge-${{l.status.toLowerCase()}}">${{esc(l.status)}}</span></td>
        <td style="color:#64748B;font-size:0.78rem;">${{esc(l.ip)}}</td>
        <td style="color:#64748B;font-size:0.78rem;">${{esc(l.logged_at)}}</td>
      </tr>`).join('');
    document.getElementById('logs-container').innerHTML = `
      <table><thead><tr><th>#</th><th>Email</th><th>Name</th><th>Status</th><th>IP</th><th>Time</th></tr></thead>
      <tbody>${{rows}}</tbody></table>`;
  }}

  // ── Motion Events ──
  async function loadMotion() {{
    try {{
      const data = await fetch('/api/motion/events?limit=200').then(r => r.json());
      document.getElementById('stat-motion-today').textContent = data.today_count ?? '0';
      document.getElementById('stat-motion-total').textContent = data.total ?? '0';
      if (!data.events.length) {{ document.getElementById('motion-container').innerHTML = '<div class="no-data">No motion events yet.</div>'; return; }}
      const rows = data.events.map(e => `
        <tr>
          <td style="color:#64748B;font-size:0.78rem;">${{e.id}}</td>
          <td>${{esc(e.start_time)}}</td>
          <td>${{e.end_time ? esc(e.end_time) : '—'}}</td>
          <td>${{e.duration_seconds != null ? e.duration_seconds.toFixed(2) + 's' : '—'}}</td>
        </tr>`).join('');
      document.getElementById('motion-container').innerHTML = `
        <table><thead><tr><th>#</th><th>Start Time</th><th>End Time</th><th>Duration</th></tr></thead>
        <tbody>${{rows}}</tbody></table>`;
    }} catch(e) {{
      document.getElementById('motion-container').innerHTML = '<div class="no-data">⚠️ Failed to load events.</div>';
    }}
  }}

  // ── Admin Camera / CCTV ──
  const ADM_CCTV_STREAM_URL = '{cctv_remote_url()}';
  const ADM_CCTV_PROXY_PATH = '/api/cctv/stream';
  const ADM_MOTION_THRESHOLD = 30;
  const ADM_MOTION_MIN_PCT   = 0.8;
  const ADM_MOTION_COOLDOWN  = 4000;

  let admCctvConnected = false;
  let admMotionTimer   = null;
  let admPrevPixels    = null;
  let admMotionActive  = false;
  let admLastMotionLog = 0;
  let admEventsToday   = 0;
  let admEventsTotal   = 0;

  function admConnectCctv() {{
    admDisconnectCctv();
    const img      = document.getElementById('adm-cctv-img');
    const feedback = document.getElementById('adm-cctv-feedback');

    feedback.textContent = 'Connecting to CCTV…';
    feedback.style.color = 'rgba(255,255,255,0.45)';
    document.getElementById('adm-cam-status').textContent = '⏳ Connecting…';

    function onConnected() {{
      img.style.display = 'block';
      admCctvConnected = true;
      document.getElementById('adm-cam-placeholder').style.display = 'none';
      document.getElementById('adm-stat-cam').textContent = 'Live';
      document.getElementById('adm-stat-cam').style.color = '#34D399';
      document.getElementById('adm-cam-status').textContent = '🟢 CCTV feed connected.';
      document.getElementById('adm-cam-status').style.color = '#34D399';
      feedback.textContent = 'CCTV connected.';
      feedback.style.color = '#34D399';
      document.getElementById('adm-motion-indicator').className = 'motion-indicator visible ok';
      document.getElementById('adm-motion-indicator').textContent = '● Monitoring';
      admPrevPixels = null;
      admStartMotionDetection();
    }}

    function onFailed() {{
      img.style.display = 'none';
      admCctvConnected = false;
      document.getElementById('adm-cam-placeholder').style.display = 'block';
      document.getElementById('adm-cam-status').textContent = '🔴 Could not load CCTV stream.';
      document.getElementById('adm-cam-status').style.color = '#FCA5A5';
      feedback.textContent = 'Could not load CCTV. Is cloudflared running?';
      feedback.style.color = '#FCA5A5';
    }}

    let attempt = 0;
    img.onload  = onConnected;
    img.onerror = () => {{
      attempt += 1;
      if (attempt === 1) {{
        feedback.textContent = 'Trying direct tunnel URL…';
        img.src = ADM_CCTV_STREAM_URL + '?t=' + Date.now();
      }} else if (attempt === 2) {{
        feedback.textContent = 'Trying server proxy…';
        img.src = ADM_CCTV_PROXY_PATH + '?t=' + Date.now();
      }} else {{
        onFailed();
      }}
    }};
    img.src = ADM_CCTV_PROXY_PATH + '?t=' + Date.now();
  }}

  function admDisconnectCctv() {{
    if (admMotionTimer) {{ clearInterval(admMotionTimer); admMotionTimer = null; }}
    admPrevPixels    = null;
    admMotionActive  = false;
    const img      = document.getElementById('adm-cctv-img');
    const feedback = document.getElementById('adm-cctv-feedback');
    img.onload  = null;
    img.onerror = null;
    img.src = '';
    img.style.display = 'none';
    admCctvConnected = false;
    document.getElementById('adm-cam-placeholder').style.display = 'block';
    document.getElementById('adm-cam-status').textContent = '⏹ CCTV disconnected.';
    document.getElementById('adm-cam-status').style.color = 'rgba(255,255,255,0.4)';
    document.getElementById('adm-stat-cam').textContent   = 'Offline';
    document.getElementById('adm-stat-cam').style.color   = '#FCA5A5';
    document.getElementById('adm-motion-indicator').className = 'motion-indicator';
    document.getElementById('adm-stat-motion').textContent = '—';
    document.getElementById('adm-stat-motion').style.color = '';
    feedback.textContent = 'CCTV disconnected.';
    feedback.style.color = 'rgba(255,255,255,0.4)';
  }}

  function admStartMotionDetection() {{
    const img    = document.getElementById('adm-cctv-img');
    const canvas = document.getElementById('adm-motion-canvas');
    const W = 160, H = 120;
    canvas.width  = W;
    canvas.height = H;
    const ctx = canvas.getContext('2d');

    if (admMotionTimer) clearInterval(admMotionTimer);
    admMotionTimer = setInterval(() => {{
      if (!admCctvConnected || !img.complete || !img.naturalWidth) return;
      ctx.drawImage(img, 0, 0, W, H);
      const frame = ctx.getImageData(0, 0, W, H).data;

      if (!admPrevPixels) {{ admPrevPixels = frame.slice(); return; }}

      let changed = 0;
      const total = W * H;
      for (let i = 0; i < frame.length; i += 4) {{
        const dr = Math.abs(frame[i]   - admPrevPixels[i]);
        const dg = Math.abs(frame[i+1] - admPrevPixels[i+1]);
        const db = Math.abs(frame[i+2] - admPrevPixels[i+2]);
        if (dr > ADM_MOTION_THRESHOLD || dg > ADM_MOTION_THRESHOLD || db > ADM_MOTION_THRESHOLD) changed++;
      }}
      admPrevPixels = frame.slice();

      const pct      = (changed / total) * 100;
      const detected = pct >= ADM_MOTION_MIN_PCT;
      const ind      = document.getElementById('adm-motion-indicator');
      const stat     = document.getElementById('adm-stat-motion');

      if (detected) {{
        ind.className   = 'motion-indicator visible alert';
        ind.textContent = '⚠ MOTION DETECTED';
        stat.textContent  = '⚠ Motion';
        stat.style.color  = '#FCA5A5';

        if (!admMotionActive) {{
          admMotionActive = true;
        }}

        const now = Date.now();
        if (now - admLastMotionLog > ADM_MOTION_COOLDOWN) {{
          admLastMotionLog = now;
          admLogMotionEvent();
        }}
      }} else {{
        ind.className   = 'motion-indicator visible ok';
        ind.textContent = '● Monitoring';
        stat.textContent  = 'Clear';
        stat.style.color  = '#34D399';
        admMotionActive   = false;
      }}
    }}, 200);
  }}

  async function admLogMotionEvent() {{
    const now = new Date().toISOString().replace('T',' ').substring(0,19);
    try {{
      await fetch('/api/motion/log', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ start_time: now, end_time: now, duration_seconds: 0 }})
      }});
      admEventsTotal++;
      admEventsToday++;
      document.getElementById('adm-stat-today').textContent = admEventsToday;
      document.getElementById('adm-stat-total').textContent = admEventsTotal;
    }} catch(e) {{}}
  }}

  async function admLoadMotionEvents() {{
    document.getElementById('adm-motion-log').innerHTML = '<div class="no-data">Loading…</div>';
    try {{
      const data   = await fetch('/api/motion/events?limit=200').then(r => r.json());
      admEventsToday = data.today_count ?? 0;
      admEventsTotal = data.total ?? 0;
      document.getElementById('adm-stat-today').textContent = admEventsToday;
      document.getElementById('adm-stat-total').textContent = admEventsTotal;
      if (!data.events.length) {{
        document.getElementById('adm-motion-log').innerHTML = '<div class="no-data">No motion events yet.</div>';
        return;
      }}
      const rows = data.events.map(e => `
        <tr>
          <td style="color:rgba(255,255,255,0.3);font-size:0.78rem;">${{e.id}}</td>
          <td>${{esc(e.start_time)}}</td>
          <td>${{e.end_time ? esc(e.end_time) : '<span style="opacity:0.4">ongoing</span>'}}</td>
          <td>${{e.duration_seconds != null ? e.duration_seconds.toFixed(2) + 's' : '—'}}</td>
        </tr>`).join('');
      document.getElementById('adm-motion-log').innerHTML = `
        <table><thead><tr><th>#</th><th>Start Time</th><th>End Time</th><th>Duration</th></tr></thead>
        <tbody>${{rows}}</tbody></table>`;
    }} catch(e) {{
      document.getElementById('adm-motion-log').innerHTML = '<div class="no-data">⚠️ Failed to load events.</div>';
    }}
  }}

  // Load default view
  loadUsers();
</script>
</body>
</html>
"""

# ---------- Page routes ----------
@app.get("/", response_class=HTMLResponse)
def landing():
    return HTMLResponse(content=LANDING_HTML)

@app.get("/signup", response_class=HTMLResponse)
def signup_page():
    return HTMLResponse(content=SIGNUP_HTML)

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return HTMLResponse(content=ADMIN_HTML)

# ---------- Run ----------
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
