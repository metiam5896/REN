import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import sqlite3
import base64
import logging
from datetime import datetime, timedelta
from urllib.parse import quote, unquote
from collections import deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, BackgroundTasks
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import psutil
import aiosqlite

# ==========================================
# CONFIGURATION & LOGGING
# ==========================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("REN-Panel")

DB_PATH = "ren_panel.db"
CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", "ren-super-secret-key-change-me"),
    "telegram_bot_token": os.environ.get("TG_BOT_TOKEN", ""),
    "telegram_chat_id": os.environ.get("TG_CHAT_ID", ""),
}

# ==========================================
# DATABASE INITIALIZATION (SQLite)
# ==========================================
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, value TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS inbounds (
                uuid TEXT PRIMARY KEY, label TEXT, protocol TEXT, limit_bytes INTEGER, 
                used_bytes INTEGER, max_connections INTEGER, created_at TEXT, 
                active INTEGER, expiry TEXT, telegram_alert_sent INTEGER DEFAULT 0
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, expires_at REAL
            )
        """)
        # Initialize default admin password if not exists
        async with db.execute("SELECT value FROM settings WHERE key='admin_pw'") as cursor:
            if not await cursor.fetchone():
                default_pw = hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))
                await db.execute("INSERT INTO settings (key, value) VALUES ('admin_pw', ?)", (default_pw,))
                await db.execute("INSERT INTO settings (key, value) VALUES ('custom_domain', ?)", ("",))
                await db.execute("INSERT INTO settings (key, value) VALUES ('clean_ips', ?)", ("[]",))
        await db.commit()

def hash_password(pw: str, salt: bytes = None) -> str:
    if not salt: salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1)
    return salt.hex() + "$" + dk.hex()

def verify_password(pw: str, db_hash: str) -> bool:
    try:
        salt_hex, dk_hex = db_hash.split("$")
        salt = bytes.fromhex(salt_hex)
        return hash_password(pw, salt) == db_hash
    except Exception:
        return False

# ==========================================
# FASTAPI LIFESPAN & APP SETUP
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    asyncio.create_task(keep_alive_task())
    asyncio.create_task(check_expirations_task())
    yield

app = FastAPI(title="REN Panel", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ==========================================
# GLOBAL STATE & HELPERS
# ==========================================
connections = {}
link_ip_map = {}
stats = {"total_bytes": 0, "total_requests": 0, "start_time": time.time()}
hourly_traffic = {}
login_attempts = {}  # For rate limiting

async def get_setting(key: str, default=""):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT value FROM settings WHERE key=?", (key,)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else default

async def set_setting(key: str, value: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        await db.commit()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "").strip("/")

def generate_vless_link(uuid: str, remark: str, address: str = None) -> str:
    domain = get_domain()
    addr = address if address else domain
    params = {"encryption": "none", "security": "tls", "type": "ws", "host": domain, "path": f"/ws/{uuid}", "sni": domain, "fp": "chrome"}
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def generate_trojan_link(uuid: str, remark: str, address: str = None) -> str:
    domain = get_domain()
    addr = address if address else domain
    return f"trojan://{uuid}@{addr}:443?security=tls&type=ws&host={domain}&path=/ws/{uuid}&sni={domain}#{quote(remark)}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    return int(value)

# ==========================================
# AUTHENTICATION & SECURITY
# ==========================================
async def require_auth(request: Request):
    token = request.cookies.get("ren_session")
    if not token: raise HTTPException(401, "Unauthorized")
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT expires_at FROM sessions WHERE token=?", (token,)) as cursor:
            row = await cursor.fetchone()
            if not row or row[0] < time.time():
                if row: await db.execute("DELETE FROM sessions WHERE token=?", (token,))
                raise HTTPException(401, "Session expired")

def check_rate_limit(ip: str):
    now = time.time()
    if ip not in login_attempts: login_attempts[ip] = []
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 300] # 5 mins window
    if len(login_attempts[ip]) >= 5: raise HTTPException(429, "Too many attempts. Try later.")
    login_attempts[ip].append(now)

# ==========================================
# API ROUTES
# ==========================================
@app.post("/api/login")
async def api_login(request: Request):
    ip = request.client.host
    check_rate_limit(ip)
    body = await request.json()
    pw = str(body.get("password", ""))
    
    stored_hash = await get_setting("admin_pw")
    if not verify_password(pw, stored_hash):
        raise HTTPException(401, "Invalid password")
    
    token = secrets.token_urlsafe(32)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT INTO sessions (token, expires_at) VALUES (?, ?)", (token, time.time() + 86400*7))
        await db.commit()
    
    resp = JSONResponse({"ok": True})
    resp.set_cookie("ren_session", token, max_age=86400*7, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get("ren_session")
    if token:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("DELETE FROM sessions WHERE token=?", (token,))
            await db.commit()
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("ren_session", path="/")
    return resp

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM inbounds") as c: links_count = (await c.fetchone())[0]
    
    return {
        "total_traffic_mb": round(stats["total_bytes"] / (1024*1024), 2),
        "total_requests": stats["total_requests"],
        "uptime": str(timedelta(seconds=int(time.time() - stats["start_time"]))),
        "links_count": links_count,
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": hourly_traffic
    }

@app.post("/api/inbounds")
async def create_inbound(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = body.get("label", "New").strip()[:50]
    protocol = body.get("protocol", "vless").lower()
    if protocol not in ["vless", "trojan"]: protocol = "vless"
    
    limit_bytes = parse_size_to_bytes(float(body.get("limit_value", 0)), body.get("limit_unit", "GB"))
    max_conn = int(body.get("max_connections", 0))
    expiry_days = int(body.get("expiry_days", 0))
    expiry = (datetime.now() + timedelta(days=expiry_days)).isoformat() if expiry_days > 0 else ""
    
    uuid = label # Using label as UUID for simplicity in WS path, or generate random
    # Actually, let's generate a proper UUID for security
    uuid = str(secrets.token_hex(16))
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO inbounds (uuid, label, protocol, limit_bytes, used_bytes, max_connections, created_at, active, expiry)
            VALUES (?, ?, ?, ?, 0, ?, ?, 1, ?)
        """, (uuid, label, protocol, limit_bytes, max_conn, datetime.now().isoformat(), expiry))
        await db.commit()
        
    return {"ok": True, "uuid": uuid}

@app.get("/api/inbounds")
async def list_inbounds(_=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT * FROM inbounds ORDER BY created_at DESC") as cursor:
            rows = await cursor.fetchall()
    
    result = []
    for r in rows:
        uuid, label, protocol, limit_b, used_b, max_c, created, active, expiry, _ = r
        link = generate_vless_link(uuid, label) if protocol == "vless" else generate_trojan_link(uuid, label)
        result.append({
            "uuid": uuid, "label": label, "protocol": protocol, "limit_bytes": limit_b, 
            "used_bytes": used_b, "max_connections": max_c, "created_at": created, 
            "active": bool(active), "expiry": expiry, "link": link,
            "current_connections": len(link_ip_map.get(uuid, set()))
        })
    return {"inbounds": result}

@app.patch("/api/inbounds/{uuid}")
async def update_inbound(uuid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with aiosqlite.connect(DB_PATH) as db:
        if "active" in body: await db.execute("UPDATE inbounds SET active=? WHERE uuid=?", (int(body["active"]), uuid))
        if "reset_usage" in body and body["reset_usage"]: 
            await db.execute("UPDATE inbounds SET used_bytes=0, telegram_alert_sent=0 WHERE uuid=?", (uuid,))
        if "limit_value" in body:
            lb = parse_size_to_bytes(float(body["limit_value"]), body.get("limit_unit", "GB"))
            await db.execute("UPDATE inbounds SET limit_bytes=? WHERE uuid=?", (lb, uuid))
        await db.commit()
    return {"ok": True}

@app.delete("/api/inbounds/{uuid}")
async def delete_inbound(uuid: str, _=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM inbounds WHERE uuid=?", (uuid,))
        await db.commit()
    # Close active connections
    for cid, info in list(connections.items()):
        if info.get("uuid") == uuid:
            ws = info.get("ws")
            if ws: await ws.close(1000, "Deleted")
            connections.pop(cid, None)
    return {"ok": True}

@app.get("/sub/{uuid}")
async def subscription_endpoint(uuid: str, request: Request):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT * FROM inbounds WHERE uuid=?", (uuid,)) as cursor:
            row = await cursor.fetchone()
    
    if not row: raise HTTPException(404, "Not found")
    _, label, protocol, limit_b, used_b, max_c, created, active, expiry, _ = row
    
    if not active: raise HTTPException(403, "Disabled")
    if expiry and datetime.now() >= datetime.fromisoformat(expiry): raise HTTPException(403, "Expired")
    
    # UA Sniffing for Clash/Meta
    ua = request.headers.get("user-agent", "").lower()
    is_clash = "clash" in ua or "meta" in ua
    
    clean_ips = json.loads(await get_setting("clean_ips", "[]"))
    links = []
    
    base_link = generate_vless_link(uuid, label) if protocol == "vless" else generate_trojan_link(uuid, label)
    links.append(base_link)
    
    for ip in clean_ips:
        if is_clash:
            # Simplified Clash YAML generation could go here, but for standard sub, just add links
            pass
        l = generate_vless_link(uuid, f"{label}-{ip}", ip) if protocol == "vless" else generate_trojan_link(uuid, f"{label}-{ip}", ip)
        links.append(l)
        
    content = "\n".join(links)
    if not is_clash:
        content = base64.b64encode(content.encode()).decode()
        
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Subscription-Userinfo": f"upload=0; download={used_b}; total={limit_b}; expire={int(datetime.fromisoformat(expiry).timestamp()) if expiry else 0}"
    }
    return Response(content=content, headers=headers)

# ==========================================
# PROTOCOL PARSERS & WEBSOCKET TUNNEL
# ==========================================
async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24: raise ValueError("VLESS chunk too small")
    pos = 18 # 1 ver + 16 uuid + 1 addon_len
    pos += chunk[17] + 1 # skip addon
    cmd = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    
    if addr_type == 1: addr = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2: 
        dlen = chunk[pos]; pos += 1
        addr = chunk[pos:pos+dlen].decode(errors="ignore"); pos += dlen
    elif addr_type == 3: # IPv6
        addr = ":".join(f"{chunk[pos+i]:02x}{chunk[pos+i+1]:02x}" for i in range(0, 16, 2)); pos += 16
    else: raise ValueError("Unknown addr type")
    return cmd, addr, port, chunk[pos:]

async def parse_trojan_header(chunk: bytes):
    if len(chunk) < 58: raise ValueError("Trojan chunk too small")
    pos = 58 # 56 bytes password + 2 bytes CRLF
    cmd = chunk[pos]; pos += 1
    addr_type = chunk[pos]; pos += 1
    
    if addr_type == 1: addr = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 3:
        dlen = chunk[pos]; pos += 1
        addr = chunk[pos:pos+dlen].decode(errors="ignore"); pos += dlen
    elif addr_type == 4:
        addr = ":".join(f"{chunk[pos+i]:02x}{chunk[pos+i+1]:02x}" for i in range(0, 16, 2)); pos += 16
    else: raise ValueError("Unknown Trojan addr type")
    
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    return cmd, addr, port, chunk[pos:]

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    writer = None
    conn_id = secrets.token_urlsafe(8)
    client_ip = websocket.headers.get("x-forwarded-for", "unknown").split(",")[0].strip()
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT protocol, active, expiry, limit_bytes, used_bytes, max_connections FROM inbounds WHERE uuid=?", (uuid,)) as cursor:
                row = await cursor.fetchone()
        
        if not row or not row[1]: raise Exception("Disabled")
        protocol, _, expiry, limit_b, used_b, max_c = row
        
        if expiry and datetime.now() >= datetime.fromisoformat(expiry): raise Exception("Expired")
        if max_c > 0 and len(link_ip_map.get(uuid, set())) >= max_c and client_ip not in link_ip_map.get(uuid, set()):
            raise Exception("Connection limit reached")
            
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        first_chunk = first_msg.get("bytes") or b""
        if not first_chunk: return
        
        if protocol == "trojan":
            cmd, address, port, payload = await parse_trojan_header(first_chunk)
        else:
            cmd, address, port, payload = await parse_vless_header(first_chunk)
            
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "ws": websocket, "bytes": 0}
        if uuid not in link_ip_map: link_ip_map[uuid] = set()
        link_ip_map[uuid].add(client_ip)
        
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if payload: writer.write(payload); await writer.drain()
        
        async def ws_to_tcp():
            nonlocal writer
            while True:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect": break
                data = msg.get("bytes") or (msg.get("text") or "").encode()
                if not data: continue
                
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute("UPDATE inbounds SET used_bytes = used_bytes + ? WHERE uuid=?", (len(data), uuid))
                    await db.commit()
                
                stats["total_bytes"] += len(data)
                writer.write(data); await writer.drain()

        async def tcp_to_ws():
            while True:
                data = await reader.read(65536)
                if not data: break
                
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute("UPDATE inbounds SET used_bytes = used_bytes + ? WHERE uuid=?", (len(data), uuid))
                    await db.commit()
                    
                stats["total_bytes"] += len(data)
                await websocket.send_bytes(data)

        await asyncio.gather(ws_to_tcp(), tcp_to_ws())
        
    except Exception as e:
        logger.error(f"WS Error {uuid}: {e}")
    finally:
        if writer: writer.close()
        connections.pop(conn_id, None)
        if uuid in link_ip_map:
            link_ip_map[uuid].discard(client_ip)
            if not link_ip_map[uuid]: link_ip_map.pop(uuid, None)
        try: await websocket.close()
        except: pass

# ==========================================
# BACKGROUND TASKS
# ==========================================
async def keep_alive_task():
    while True:
        await asyncio.sleep(600)
        domain = get_domain()
        if domain and domain != "localhost":
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
            except: pass

async def check_expirations_task():
    while True:
        await asyncio.sleep(3600) # Check every hour
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT uuid, label, limit_bytes, used_bytes, expiry, telegram_alert_sent FROM inbounds") as cursor:
                rows = await cursor.fetchall()
                
        for r in rows:
            uuid, label, limit_b, used_b, expiry, alert_sent = r
            if limit_b > 0 and used_b >= limit_b * 0.9 and not alert_sent:
                await send_telegram(f"⚠️ هشدار: اینباوند `{label}` به 90% حجم خود رسیده است.")
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute("UPDATE inbounds SET telegram_alert_sent=1 WHERE uuid=?", (uuid,))
                    await db.commit()

async def send_telegram(text: str):
    token = CONFIG["telegram_bot_token"]
    chat_id = CONFIG["telegram_chat_id"]
    if not token or not chat_id: return
    try:
        async with httpx.AsyncClient() as client:
            await client.get(f"https://api.telegram.org/bot{token}/sendMessage", params={"chat_id": chat_id, "text": text})
    except: pass

# ==========================================
# FRONTEND (HTML/JS)
# ==========================================
# Note: Using Tailwind & Alpine.js via CDN for a modern, lightweight UI.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REN Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .glass { background: rgba(255, 255, 255, 0.03); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.05); }
        .dark .glass { background: rgba(0, 0, 0, 0.2); }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
    </style>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { colors: { primary: '#8b5cf6', accent: '#ec4899' } } }
        }
    </script>
</head>
<body class="bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100 transition-colors" x-data="panel()">
    
    <!-- Login Page -->
    <div x-show="!auth" class="min-h-screen flex items-center justify-center p-4">
        <div class="glass rounded-2xl p-8 w-full max-w-md shadow-2xl">
            <h1 class="text-3xl font-bold text-center mb-2 bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">REN Panel</h1>
            <p class="text-center text-gray-500 mb-8">Advanced Gateway Management</p>
            <form @submit.prevent="login()">
                <input type="password" x-model="password" placeholder="Enter Password" class="w-full bg-gray-100 dark:bg-gray-800 rounded-lg px-4 py-3 mb-4 focus:ring-2 focus:ring-primary outline-none transition">
                <button type="submit" class="w-full bg-gradient-to-r from-primary to-accent text-white font-semibold py-3 rounded-lg hover:opacity-90 transition">Sign In</button>
                <p x-show="error" class="text-red-500 text-sm mt-4 text-center" x-text="error"></p>
            </form>
        </div>
    </div>

    <!-- Dashboard -->
    <div x-show="auth" class="flex h-screen overflow-hidden">
        <!-- Sidebar -->
        <aside class="w-64 glass flex flex-col hidden md:flex">
            <div class="p-6 border-b border-gray-200 dark:border-gray-800">
                <h2 class="text-xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">REN Panel</h2>
            </div>
            <nav class="flex-1 p-4 space-y-2">
                <button @click="page='dashboard'" :class="page==='dashboard' ? 'bg-primary/10 text-primary' : 'hover:bg-gray-100 dark:hover:bg-gray-800'" class="w-full flex items-center gap-3 px-4 py-2 rounded-lg transition">Dashboard</button>
                <button @click="page='inbounds'" :class="page==='inbounds' ? 'bg-primary/10 text-primary' : 'hover:bg-gray-100 dark:hover:bg-gray-800'" class="w-full flex items-center gap-3 px-4 py-2 rounded-lg transition">Inbounds</button>
                <button @click="page='settings'" :class="page==='settings' ? 'bg-primary/10 text-primary' : 'hover:bg-gray-100 dark:hover:bg-gray-800'" class="w-full flex items-center gap-3 px-4 py-2 rounded-lg transition">Settings</button>
            </nav>
            <div class="p-4 border-t border-gray-200 dark:border-gray-800">
                <button @click="logout()" class="w-full text-red-500 hover:bg-red-500/10 px-4 py-2 rounded-lg transition">Logout</button>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 overflow-y-auto p-4 md:p-8">
            <!-- Dashboard Page -->
            <div x-show="page==='dashboard'">
                <h1 class="text-2xl font-bold mb-6">Dashboard</h1>
                <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                    <div class="glass rounded-xl p-4"><p class="text-gray-500 text-sm">Traffic</p><p class="text-2xl font-bold" x-text="stats.total_traffic_mb + ' MB'"></p></div>
                    <div class="glass rounded-xl p-4"><p class="text-gray-500 text-sm">Inbounds</p><p class="text-2xl font-bold" x-text="stats.links_count"></p></div>
                    <div class="glass rounded-xl p-4"><p class="text-gray-500 text-sm">CPU</p><p class="text-2xl font-bold" x-text="stats.cpu_percent + '%'"></p></div>
                    <div class="glass rounded-xl p-4"><p class="text-gray-500 text-sm">RAM</p><p class="text-2xl font-bold" x-text="stats.memory_percent + '%'"></p></div>
                </div>
                <div class="glass rounded-xl p-4">
                    <h3 class="font-semibold mb-4">Traffic Chart</h3>
                    <div id="chart"></div>
                </div>
            </div>

            <!-- Inbounds Page -->
            <div x-show="page==='inbounds'">
                <div class="flex justify-between items-center mb-6">
                    <h1 class="text-2xl font-bold">Inbounds</h1>
                    <button @click="showAddModal=true" class="bg-primary text-white px-4 py-2 rounded-lg hover:opacity-90 transition">+ Add Inbound</button>
                </div>
                <div class="glass rounded-xl overflow-hidden">
                    <table class="w-full text-left">
                        <thead class="bg-gray-100 dark:bg-gray-800/50 text-gray-500 text-sm uppercase">
                            <tr><th class="p-4">Label</th><th class="p-4">Protocol</th><th class="p-4">Usage</th><th class="p-4">Status</th><th class="p-4">Actions</th></tr>
                        </thead>
                        <tbody>
                            <template x-for="inb in inbounds" :key="inb.uuid">
                                <tr class="border-t border-gray-200 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/30 transition">
                                    <td class="p-4 font-medium" x-text="inb.label"></td>
                                    <td class="p-4"><span class="px-2 py-1 rounded text-xs bg-primary/10 text-primary" x-text="inb.protocol.toUpperCase()"></span></td>
                                    <td class="p-4 text-sm" x-text="formatBytes(inb.used_bytes) + ' / ' + (inb.limit_bytes ? formatBytes(inb.limit_bytes) : '∞')"></td>
                                    <td class="p-4">
                                        <button @click="toggleInbound(inb)" :class="inb.active ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'" class="px-3 py-1 rounded text-xs font-semibold transition" x-text="inb.active ? 'Active' : 'Disabled'"></button>
                                    </td>
                                    <td class="p-4 flex gap-2">
                                        <button @click="copyLink(inb.link)" class="text-blue-500 hover:bg-blue-500/10 p-2 rounded transition">Copy</button>
                                        <button @click="deleteInbound(inb.uuid)" class="text-red-500 hover:bg-red-500/10 p-2 rounded transition">Delete</button>
                                    </td>
                                </tr>
                            </template>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Settings Page -->
            <div x-show="page==='settings'">
                <h1 class="text-2xl font-bold mb-6">Settings</h1>
                <div class="glass rounded-xl p-6 max-w-2xl">
                    <h3 class="font-semibold mb-4">Change Password</h3>
                    <form @submit.prevent="changePassword()">
                        <input type="password" x-model="newPw" placeholder="New Password" class="w-full bg-gray-100 dark:bg-gray-800 rounded-lg px-4 py-2 mb-4 outline-none">
                        <button type="submit" class="bg-primary text-white px-4 py-2 rounded-lg">Update</button>
                    </form>
                </div>
            </div>
        </main>
    </div>

    <!-- Add Modal -->
    <div x-show="showAddModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" @click.self="showAddModal=false">
        <div class="glass rounded-2xl p-6 w-full max-w-md" @click.stop>
            <h2 class="text-xl font-bold mb-4">Add Inbound</h2>
            <form @submit.prevent="addInbound()">
                <input type="text" x-model="newInb.label" placeholder="Label" class="w-full bg-gray-100 dark:bg-gray-800 rounded-lg px-4 py-2 mb-3 outline-none">
                <select x-model="newInb.protocol" class="w-full bg-gray-100 dark:bg-gray-800 rounded-lg px-4 py-2 mb-3 outline-none">
                    <option value="vless">VLESS</option>
                    <option value="trojan">Trojan</option>
                </select>
                <input type="number" x-model="newInb.limit_value" placeholder="Limit (GB)" class="w-full bg-gray-100 dark:bg-gray-800 rounded-lg px-4 py-2 mb-4 outline-none">
                <div class="flex gap-2">
                    <button type="button" @click="showAddModal=false" class="flex-1 bg-gray-200 dark:bg-gray-700 py-2 rounded-lg">Cancel</button>
                    <button type="submit" class="flex-1 bg-primary text-white py-2 rounded-lg">Create</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function panel() {
            return {
                auth: false, password: '', error: '', page: 'dashboard',
                stats: {}, inbounds: [], showAddModal: false,
                newInb: { label: '', protocol: 'vless', limit_value: 0 }, newPw: '',
                init() {
                    this.checkAuth();
                    setInterval(() => { if(this.auth) this.loadStats(); }, 5000);
                },
                async checkAuth() {
                    try {
                        const r = await fetch('/stats');
                        this.auth = r.ok;
                        if(this.auth) { this.loadStats(); this.loadInbounds(); }
                    } catch(e) { this.auth = false; }
                },
                async login() {
                    try {
                        const r = await fetch('/api/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({password: this.password}) });
                        if(!r.ok) throw new Error('Invalid');
                        this.auth = true; this.error = ''; this.loadStats(); this.loadInbounds();
                    } catch(e) { this.error = 'Invalid password or rate limited'; }
                },
                async logout() { await fetch('/api/logout', {method:'POST'}); this.auth = false; },
                async loadStats() {
                    const r = await fetch('/stats'); this.stats = await r.json();
                    this.updateChart();
                },
                async loadInbounds() {
                    const r = await fetch('/api/inbounds'); this.inbounds = (await r.json()).inbounds;
                },
                async addInbound() {
                    await fetch('/api/inbounds', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...this.newInb, limit_unit: 'GB'}) });
                    this.showAddModal = false; this.newInb = { label: '', protocol: 'vless', limit_value: 0 };
                    this.loadInbounds();
                },
                async toggleInbound(inb) {
                    await fetch(`/api/inbounds/${inb.uuid}`, { method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({active: !inb.active}) });
                    this.loadInbounds();
                },
                async deleteInbound(uuid) {
                    if(!confirm('Delete?')) return;
                    await fetch(`/api/inbounds/${uuid}`, { method: 'DELETE' });
                    this.loadInbounds();
                },
                copyLink(link) { navigator.clipboard.writeText(link); alert('Copied!'); },
                formatBytes(b) { if(!b) return '0 B'; const k=1024, s=['B','KB','MB','GB']; const i=Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i]; },
                updateChart() {
                    // ApexCharts logic here
                }
            }
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return HTMLResponse(content=HTML_TEMPLATE)

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
