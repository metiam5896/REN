# =============================================================================
# REN Gateway - نسخه ۳.۰ (پیشرفته و کامل)
# =============================================================================
# امکانات: پروتکل‌های VLESS, VMess, Trojan, Shadowsocks
# احراز هویت JWT + Argon2، Rate Limiting، اعلان تلگرام، کش آمار،
# بکاپ خودکار، WebSocket لحظه‌ای، پشتیبانی از دامنه‌های متعدد،
# رابط کاربری مدرن با نمودارهای پیشرفته، دو زبانه (فارسی/انگلیسی)
# =============================================================================

import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import binascii
import socket
import logging
from datetime import datetime, timedelta
from urllib.parse import quote, unquote
from collections import deque, defaultdict
from typing import Optional, Dict, List, Any, Union
from contextlib import asynccontextmanager
import pytz

# ---------- کتابخانه‌های شخص ثالث ----------
from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
import uvicorn
import httpx
import psutil
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship, Mapped, mapped_column
from sqlalchemy import select, update, delete, func
from passlib.context import CryptContext
from jose import JWTError, jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- تنظیمات لاگ ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("REN-Gateway")

# ---------- تنظیمات برنامه ----------
class Settings:
    APP_NAME = "REN"
    VERSION = "3.0.0"
    PORT = int(os.environ.get("PORT", 8000))
    SECRET_KEY = os.environ.get("SECRET_KEY", "ren-super-secret-key-change-me")
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRE_MINUTES = 15
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./ren.db")
    RATE_LIMIT_REQUESTS = 60
    RATE_LIMIT_PERIOD = 60
    SESSION_COOKIE = "ren_session"
    MAX_CONNECTIONS_PER_IP = 5
    TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
    BACKUP_INTERVAL_HOURS = 24
    CACHE_TTL_SECONDS = 30

settings = Settings()

# ---------- امنیت ----------
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# ---------- JWT ----------
def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "refresh": True})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ---------- Rate Limiter ----------
limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.RATE_LIMIT_REQUESTS}/{settings.RATE_LIMIT_PERIOD} second"])

# ---------- پایگاه داده ----------
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    email: Mapped[Optional[str]] = mapped_column(sa.String(128), nullable=True)
    role: Mapped[str] = mapped_column(sa.String(20), default="user")
    traffic_limit: Mapped[int] = mapped_column(sa.BigInteger, default=0)
    traffic_used: Mapped[int] = mapped_column(sa.BigInteger, default=0)
    expiry_date: Mapped[Optional[datetime]] = mapped_column(sa.DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    rate_limit_override: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, default=datetime.utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(sa.DateTime, nullable=True)
    telegram_chat_id: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)

    inbounds: Mapped[List["Inbound"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    traffic_logs: Mapped[List["TrafficLog"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    notifications: Mapped[List["Notification"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class Inbound(Base):
    __tablename__ = "inbounds"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey("users.id"), nullable=False)
    protocol: Mapped[str] = mapped_column(sa.String(20), default="vless")
    port: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    uuid: Mapped[str] = mapped_column(sa.String(36), unique=True, index=True, nullable=False)
    remark: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    traffic_limit: Mapped[int] = mapped_column(sa.BigInteger, default=0)
    traffic_used: Mapped[int] = mapped_column(sa.BigInteger, default=0)
    max_connections: Mapped[int] = mapped_column(sa.Integer, default=0)
    expiry_date: Mapped[Optional[datetime]] = mapped_column(sa.DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    settings: Mapped[Optional[dict]] = mapped_column(sa.JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship(back_populates="inbounds")
    traffic_logs: Mapped[List["TrafficLog"]] = relationship(back_populates="inbound", cascade="all, delete-orphan")

class TrafficLog(Base):
    __tablename__ = "traffic_logs"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey("users.id"), nullable=False)
    inbound_id: Mapped[int] = mapped_column(sa.ForeignKey("inbounds.id"), nullable=False)
    bytes_sent: Mapped[int] = mapped_column(sa.BigInteger, default=0)
    bytes_received: Mapped[int] = mapped_column(sa.BigInteger, default=0)
    timestamp: Mapped[datetime] = mapped_column(sa.DateTime, default=datetime.utcnow, index=True)

    user: Mapped["User"] = relationship(back_populates="traffic_logs")
    inbound: Mapped["Inbound"] = relationship(back_populates="traffic_logs")

class Setting(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    key: Mapped[str] = mapped_column(sa.String(64), unique=True, nullable=False)
    value: Mapped[str] = mapped_column(sa.Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey("users.id"), nullable=False)
    type: Mapped[str] = mapped_column(sa.String(20))
    message: Mapped[str] = mapped_column(sa.Text)
    is_read: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship(back_populates="notifications")

# ---------- ایجاد موتور و سشن ----------
engine = create_async_engine(settings.DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# ---------- مدل‌های Pydantic ----------
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=4)
    email: Optional[str] = None
    role: str = "user"
    traffic_limit: int = 0
    expiry_date: Optional[datetime] = None
    rate_limit_override: Optional[int] = None
    telegram_chat_id: Optional[str] = None

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    traffic_limit: Optional[int] = None
    expiry_date: Optional[datetime] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None
    rate_limit_override: Optional[int] = None
    telegram_chat_id: Optional[str] = None

class InboundCreate(BaseModel):
    protocol: str = "vless"
    remark: str = Field(..., min_length=1, max_length=64)
    traffic_limit: int = 0
    max_connections: int = 0
    expiry_days: Optional[int] = None
    settings: Optional[dict] = None

class InboundUpdate(BaseModel):
    remark: Optional[str] = None
    protocol: Optional[str] = None
    traffic_limit: Optional[int] = None
    max_connections: Optional[int] = None
    expiry_date: Optional[datetime] = None
    is_active: Optional[bool] = None
    reset_usage: bool = False
    settings: Optional[dict] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

# ---------- ابزارهای کمکی ----------
def generate_uuid(seed: Optional[str] = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))
    h = hashlib.sha256(f"{seed}{settings.SECRET_KEY}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def get_domain() -> str:
    return os.environ.get("CUSTOM_DOMAIN") or os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def fmt_bytes(b: int) -> str:
    if b >= 1<<30:
        return f"{b/(1<<30):.2f} GB"
    if b >= 1<<20:
        return f"{b/(1<<20):.2f} MB"
    if b >= 1<<10:
        return f"{b/(1<<10):.2f} KB"
    return f"{b} B"

def is_expired(expiry_date: Optional[datetime]) -> bool:
    if not expiry_date:
        return False
    return datetime.utcnow() >= expiry_date

def expiry_epoch(expiry_date: Optional[datetime]) -> int:
    if not expiry_date:
        return 0
    return int(expiry_date.timestamp())

# ---------- تولید لینک با پشتیبانی از دامنه‌های متعدد ----------
def generate_link_for_domain(uuid: str, protocol: str, remark: str, domain: str, extra_params: dict = None) -> str:
    if protocol == "vless":
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": domain,
            "path": f"/ws/{uuid}",
            "sni": domain,
            "fp": "chrome",
            "alpn": "http/1.1",
        }
        if extra_params:
            params.update(extra_params)
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"vless://{uuid}@{domain}:443?{query}#{quote(remark)}"
    elif protocol == "vmess":
        config = {
            "v": "2",
            "ps": remark,
            "add": domain,
            "port": "443",
            "id": uuid,
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": domain,
            "path": f"/ws/{uuid}",
            "tls": "tls",
            "sni": domain,
            "alpn": "http/1.1",
            "fp": "chrome"
        }
        return "vmess://" + base64.b64encode(json.dumps(config).encode()).decode()
    elif protocol == "trojan":
        return f"trojan://{uuid}@{domain}:443?security=tls&type=ws&host={domain}&path=/ws/{uuid}&sni={domain}&fp=chrome&alpn=http/1.1#{quote(remark)}"
    elif protocol == "shadowsocks":
        method = "chacha20-ietf-poly1305"
        userinfo = f"{method}:{uuid}"
        return f"ss://{base64.b64encode(userinfo.encode()).decode()}@{domain}:443#{quote(remark)}"
    return ""

def generate_all_links(inbound: Inbound) -> List[str]:
    links = []
    main_domain = get_domain()
    extra_domains = inbound.settings.get("extra_domains", []) if inbound.settings else []
    all_domains = [main_domain] + extra_domains
    for domain in all_domains:
        if domain:
            links.append(generate_link_for_domain(inbound.uuid, inbound.protocol, inbound.remark, domain))
    return links

# ---------- پیاده‌سازی پروتکل‌ها ----------
async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("Chunk too small")
    pos = 0
    pos += 1
    pos += 16
    addon_len = first_chunk[pos]
    pos += 1
    pos += addon_len
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos+2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos+4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]
        pos += 1
        address = first_chunk[pos:pos+domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos+16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"Unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

parse_vmess_header = parse_vless_header
parse_trojan_header = parse_vless_header

async def parse_shadowsocks_header(first_chunk: bytes):
    if len(first_chunk) < 2:
        raise ValueError("Chunk too small")
    addr_type = first_chunk[0]
    pos = 1
    if addr_type == 1:
        address = ".".join(str(b) for b in first_chunk[pos:pos+4])
        pos += 4
    elif addr_type == 2:
        domain_len = first_chunk[pos]
        pos += 1
        address = first_chunk[pos:pos+domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        address = ":".join(f"{first_chunk[pos+i]:02x}{first_chunk[pos+i+1]:02x}" for i in range(0, 16, 2))
        pos += 16
    else:
        raise ValueError(f"Unknown address type: {addr_type}")
    port = int.from_bytes(first_chunk[pos:pos+2], "big")
    pos += 2
    return address, port, first_chunk[pos:]

# ---------- مدیریت اتصالات و کش ----------
connections: Dict[str, dict] = {}
connection_sockets: Dict[str, WebSocket] = {}
link_ip_map: Dict[str, set] = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=100)
hourly_traffic: Dict[str, int] = defaultdict(int)
cache = {}

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uuid: str) -> int:
    return len(link_ip_map.get(uuid, set()))

def remove_ip_from_link(uuid: str, ip: str):
    if uuid in link_ip_map:
        link_ip_map[uuid].discard(ip)
        if not link_ip_map[uuid]:
            link_ip_map.pop(uuid, None)

async def close_websocket_connection(conn_id: str, code: int = 1000, reason: str = ""):
    ws = connection_sockets.pop(conn_id, None)
    if ws:
        try:
            await ws.close(code=code, reason=reason)
        except:
            pass
    info = connections.pop(conn_id, None)
    if info:
        uuid = info.get("uuid")
        ip = info.get("ip")
        if uuid and ip:
            has_other = any(c.get("uuid") == uuid and c.get("ip") == ip for cid, c in connections.items() if cid != conn_id)
            if not has_other:
                remove_ip_from_link(uuid, ip)

# ---------- عملیات مصرف ترافیک (اتمی) ----------
async def consume_traffic(db: AsyncSession, user_id: int, inbound_id: int, bytes_used: int) -> bool:
    stmt_user = select(User).where(User.id == user_id).with_for_update()
    result = await db.execute(stmt_user)
    user = result.scalar_one_or_none()
    if not user or not user.is_active or is_expired(user.expiry_date):
        return False

    stmt_inbound = select(Inbound).where(Inbound.id == inbound_id).with_for_update()
    result = await db.execute(stmt_inbound)
    inbound = result.scalar_one_or_none()
    if not inbound or not inbound.is_active or is_expired(inbound.expiry_date):
        return False

    if user.traffic_limit > 0 and user.traffic_used + bytes_used > user.traffic_limit:
        if user.telegram_chat_id:
            asyncio.create_task(send_telegram_message(user.telegram_chat_id, f"⚠️ Traffic limit exceeded for user {user.username}"))
        return False
    if inbound.traffic_limit > 0 and inbound.traffic_used + bytes_used > inbound.traffic_limit:
        return False

    user.traffic_used += bytes_used
    inbound.traffic_used += bytes_used
    await db.commit()
    return True

# ---------- اعلان تلگرام ----------
async def send_telegram_message(chat_id: str, text: str):
    if not settings.TELEGRAM_BOT_TOKEN or not chat_id:
        return
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json={"chat_id": chat_id, "text": text})
    except Exception as e:
        logger.error(f"Telegram send error: {e}")

# ---------- بکاپ خودکار ----------
async def auto_backup(db: AsyncSession):
    while True:
        await asyncio.sleep(settings.BACKUP_INTERVAL_HOURS * 3600)
        try:
            users = (await db.execute(select(User))).scalars().all()
            inbounds = (await db.execute(select(Inbound))).scalars().all()
            settings_objs = (await db.execute(select(Setting))).scalars().all()
            data = {
                "users": [{"id": u.id, "username": u.username, "password_hash": u.password_hash, "email": u.email,
                           "role": u.role, "traffic_limit": u.traffic_limit, "traffic_used": u.traffic_used,
                           "expiry_date": u.expiry_date.isoformat() if u.expiry_date else None,
                           "is_active": u.is_active, "created_at": u.created_at.isoformat()} for u in users],
                "inbounds": [{"id": ib.id, "user_id": ib.user_id, "protocol": ib.protocol, "uuid": ib.uuid,
                              "remark": ib.remark, "traffic_limit": ib.traffic_limit, "traffic_used": ib.traffic_used,
                              "max_connections": ib.max_connections,
                              "expiry_date": ib.expiry_date.isoformat() if ib.expiry_date else None,
                              "is_active": ib.is_active, "settings": ib.settings} for ib in inbounds],
                "settings": [{"key": s.key, "value": s.value} for s in settings_objs]
            }
            with open(f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json", "w") as f:
                json.dump(data, f)
            logger.info("Auto backup completed")
        except Exception as e:
            logger.error(f"Auto backup error: {e}")

# ---------- WebSocket Handler ----------
RELAY_BUF = 64 * 1024

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, db: AsyncSession, user_id: int, inbound_id: int):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            size = len(data)
            if not await consume_traffic(db, user_id, inbound_id, size):
                await websocket.close(code=1008, reason="Quota exceeded")
                break
            stats["total_bytes"] += size
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            writer.write(data)
            await writer.drain()
    except WebSocketDisconnect:
        pass
    finally:
        try:
            writer.write_eof()
        except:
            pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, db: AsyncSession, user_id: int, inbound_id: int):
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            size = len(data)
            if not await consume_traffic(db, user_id, inbound_id, size):
                await websocket.close(code=1008, reason="Quota exceeded")
                break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await websocket.send_bytes(data)
    except:
        pass

# ========== FastAPI ==========
app = FastAPI(title=settings.APP_NAME, version=settings.VERSION, docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Too many requests"})

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: AsyncSession = Depends(get_db)):
    token = credentials.credentials
    payload = decode_token(token)
    if payload.get("refresh"):
        raise HTTPException(status_code=401, detail="Refresh token not allowed")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    stmt = select(User).where(User.id == int(user_id))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

async def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return current_user

# ---------- Routes ----------
@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse(url="/login")

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

def uptime():
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

# ---------- Auth ----------
@app.post("/api/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, login_data: LoginRequest, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.username == login_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    if is_expired(user.expiry_date):
        raise HTTPException(status_code=403, detail="Account expired")

    user.last_login = datetime.utcnow()
    await db.commit()

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id)})

    response = JSONResponse({"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"})
    response.set_cookie(
        key=settings.SESSION_COOKIE,
        value=access_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.JWT_EXPIRE_MINUTES * 60
    )
    return response

@app.post("/api/auth/refresh")
async def refresh_token(refresh_data: RefreshRequest):
    payload = decode_token(refresh_data.refresh_token)
    if not payload.get("refresh"):
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    new_access = create_access_token({"sub": user_id})
    return {"access_token": new_access}

@app.post("/api/auth/logout")
async def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(settings.SESSION_COOKIE)
    return response

# ---------- Users ----------
@app.get("/api/users")
async def list_users(admin: User = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(User)
    result = await db.execute(stmt)
    users = result.scalars().all()
    return [{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "traffic_limit": u.traffic_limit,
        "traffic_used": u.traffic_used,
        "expiry_date": u.expiry_date.isoformat() if u.expiry_date else None,
        "is_active": u.is_active,
        "rate_limit_override": u.rate_limit_override,
        "telegram_chat_id": u.telegram_chat_id,
        "created_at": u.created_at.isoformat(),
        "last_login": u.last_login.isoformat() if u.last_login else None,
    } for u in users]

@app.post("/api/users")
async def create_user(user_data: UserCreate, admin: User = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.username == user_data.username)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed = hash_password(user_data.password)
    new_user = User(
        username=user_data.username,
        password_hash=hashed,
        email=user_data.email,
        role=user_data.role,
        traffic_limit=user_data.traffic_limit,
        expiry_date=user_data.expiry_date,
        rate_limit_override=user_data.rate_limit_override,
        telegram_chat_id=user_data.telegram_chat_id,
        is_active=True
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"id": new_user.id, "username": new_user.username, "role": new_user.role}

@app.put("/api/users/{user_id}")
async def update_user(user_id: int, user_data: UserUpdate, admin: User = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_data.username is not None:
        stmt2 = select(User).where(User.username == user_data.username, User.id != user_id)
        if (await db.execute(stmt2)).scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Username already exists")
        user.username = user_data.username
    if user_data.email is not None:
        user.email = user_data.email
    if user_data.role is not None:
        user.role = user_data.role
    if user_data.traffic_limit is not None:
        user.traffic_limit = user_data.traffic_limit
    if user_data.expiry_date is not None:
        user.expiry_date = user_data.expiry_date
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    if user_data.rate_limit_override is not None:
        user.rate_limit_override = user_data.rate_limit_override
    if user_data.telegram_chat_id is not None:
        user.telegram_chat_id = user_data.telegram_chat_id
    if user_data.password:
        user.password_hash = hash_password(user_data.password)

    await db.commit()
    return {"ok": True}

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, admin: User = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user)
    await db.commit()
    return {"ok": True}

# ---------- Inbounds ----------
@app.get("/api/inbounds")
async def list_inbounds(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if current_user.role == "admin":
        stmt = select(Inbound)
    else:
        stmt = select(Inbound).where(Inbound.user_id == current_user.id)
    result = await db.execute(stmt)
    inbounds = result.scalars().all()
    return [{
        "id": ib.id,
        "user_id": ib.user_id,
        "protocol": ib.protocol,
        "uuid": ib.uuid,
        "remark": ib.remark,
        "traffic_limit": ib.traffic_limit,
        "traffic_used": ib.traffic_used,
        "max_connections": ib.max_connections,
        "expiry_date": ib.expiry_date.isoformat() if ib.expiry_date else None,
        "is_active": ib.is_active,
        "settings": ib.settings,
        "created_at": ib.created_at.isoformat(),
        "current_connections": count_connections_for_link(ib.uuid),
        "links": generate_all_links(ib)
    } for ib in inbounds]

@app.post("/api/inbounds")
async def create_inbound(inbound_data: InboundCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    user_id = current_user.id
    if current_user.role == "admin" and inbound_data.settings and "user_id" in inbound_data.settings:
        user_id = inbound_data.settings["user_id"]

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    uuid = generate_uuid()
    expiry = None
    if inbound_data.expiry_days:
        expiry = datetime.utcnow() + timedelta(days=inbound_data.expiry_days)

    new_inbound = Inbound(
        user_id=user_id,
        protocol=inbound_data.protocol,
        uuid=uuid,
        remark=inbound_data.remark,
        traffic_limit=inbound_data.traffic_limit,
        max_connections=inbound_data.max_connections,
        expiry_date=expiry,
        is_active=True,
        settings=inbound_data.settings or {}
    )
    db.add(new_inbound)
    await db.commit()
    await db.refresh(new_inbound)
    return {
        "id": new_inbound.id,
        "uuid": new_inbound.uuid,
        "remark": new_inbound.remark,
        "protocol": new_inbound.protocol,
        "traffic_limit": new_inbound.traffic_limit,
        "max_connections": new_inbound.max_connections,
        "expiry_date": new_inbound.expiry_date.isoformat() if new_inbound.expiry_date else None,
        "links": generate_all_links(new_inbound)
    }

@app.put("/api/inbounds/{inbound_id}")
async def update_inbound(inbound_id: int, inbound_data: InboundUpdate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    stmt = select(Inbound).where(Inbound.id == inbound_id)
    result = await db.execute(stmt)
    inbound = result.scalar_one_or_none()
    if not inbound:
        raise HTTPException(status_code=404, detail="Inbound not found")
    if current_user.role != "admin" and inbound.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not allowed")

    if inbound_data.remark is not None:
        inbound.remark = inbound_data.remark
    if inbound_data.protocol is not None:
        inbound.protocol = inbound_data.protocol
    if inbound_data.traffic_limit is not None:
        inbound.traffic_limit = inbound_data.traffic_limit
    if inbound_data.max_connections is not None:
        inbound.max_connections = inbound_data.max_connections
    if inbound_data.expiry_date is not None:
        inbound.expiry_date = inbound_data.expiry_date
    if inbound_data.is_active is not None:
        inbound.is_active = inbound_data.is_active
    if inbound_data.settings is not None:
        inbound.settings = inbound_data.settings
    if inbound_data.reset_usage:
        inbound.traffic_used = 0

    await db.commit()
    return {"ok": True}

@app.delete("/api/inbounds/{inbound_id}")
async def delete_inbound(inbound_id: int, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    stmt = select(Inbound).where(Inbound.id == inbound_id)
    result = await db.execute(stmt)
    inbound = result.scalar_one_or_none()
    if not inbound:
        raise HTTPException(status_code=404, detail="Inbound not found")
    if current_user.role != "admin" and inbound.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not allowed")

    await close_connections_for_link(inbound.uuid)
    await db.delete(inbound)
    await db.commit()
    return {"ok": True}

async def close_connections_for_link(uuid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uuid]
    for cid in to_close:
        await close_websocket_connection(cid)

# ---------- Traffic & Stats ----------
@app.get("/api/traffic")
async def get_traffic(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if current_user.role == "admin":
        stmt = select(TrafficLog)
    else:
        stmt = select(TrafficLog).where(TrafficLog.user_id == current_user.id)
    result = await db.execute(stmt.order_by(TrafficLog.timestamp.desc()).limit(100))
    logs = result.scalars().all()
    return [{
        "id": log.id,
        "user_id": log.user_id,
        "inbound_id": log.inbound_id,
        "bytes_sent": log.bytes_sent,
        "bytes_received": log.bytes_received,
        "timestamp": log.timestamp.isoformat()
    } for log in logs]

@app.get("/api/stats")
async def get_stats(current_user: User = Depends(get_current_user)):
    cache_key = f"stats_{current_user.id}"
    if cache_key in cache and time.time() - cache[cache_key]["time"] < settings.CACHE_TTL_SECONDS:
        return cache[cache_key]["data"]
    data = {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1<<20), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.utcnow().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }
    cache[cache_key] = {"data": data, "time": time.time()}
    return data

# ---------- Settings ----------
@app.get("/api/settings")
async def get_settings(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    stmt = select(Setting)
    result = await db.execute(stmt)
    return {s.key: s.value for s in result.scalars().all()}

@app.post("/api/settings")
async def update_settings(settings_data: dict, admin: User = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    for key, value in settings_data.items():
        stmt = select(Setting).where(Setting.key == key)
        result = await db.execute(stmt)
        setting = result.scalar_one_or_none()
        if setting:
            setting.value = str(value)
        else:
            new_setting = Setting(key=key, value=str(value))
            db.add(new_setting)
    await db.commit()
    return {"ok": True}

# ---------- Backup & Restore ----------
@app.get("/api/backup")
async def backup(admin: User = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    users = (await db.execute(select(User))).scalars().all()
    inbounds = (await db.execute(select(Inbound))).scalars().all()
    settings_objs = (await db.execute(select(Setting))).scalars().all()
    data = {
        "users": [{"id": u.id, "username": u.username, "password_hash": u.password_hash, "email": u.email,
                   "role": u.role, "traffic_limit": u.traffic_limit, "traffic_used": u.traffic_used,
                   "expiry_date": u.expiry_date.isoformat() if u.expiry_date else None,
                   "is_active": u.is_active, "created_at": u.created_at.isoformat()} for u in users],
        "inbounds": [{"id": ib.id, "user_id": ib.user_id, "protocol": ib.protocol, "uuid": ib.uuid,
                      "remark": ib.remark, "traffic_limit": ib.traffic_limit, "traffic_used": ib.traffic_used,
                      "max_connections": ib.max_connections,
                      "expiry_date": ib.expiry_date.isoformat() if ib.expiry_date else None,
                      "is_active": ib.is_active, "settings": ib.settings} for ib in inbounds],
        "settings": [{"key": s.key, "value": s.value} for s in settings_objs]
    }
    return JSONResponse(content=data)

@app.post("/api/restore")
async def restore(request: Request, admin: User = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    data = await request.json()
    await db.execute(delete(TrafficLog))
    await db.execute(delete(Inbound))
    await db.execute(delete(User))
    await db.execute(delete(Setting))
    await db.commit()

    for u_data in data.get("users", []):
        user = User(
            id=u_data["id"],
            username=u_data["username"],
            password_hash=u_data["password_hash"],
            email=u_data["email"],
            role=u_data["role"],
            traffic_limit=u_data["traffic_limit"],
            traffic_used=u_data["traffic_used"],
            expiry_date=datetime.fromisoformat(u_data["expiry_date"]) if u_data["expiry_date"] else None,
            is_active=u_data["is_active"],
            created_at=datetime.fromisoformat(u_data["created_at"])
        )
        db.add(user)
    await db.commit()

    for ib_data in data.get("inbounds", []):
        inbound = Inbound(
            id=ib_data["id"],
            user_id=ib_data["user_id"],
            protocol=ib_data["protocol"],
            uuid=ib_data["uuid"],
            remark=ib_data["remark"],
            traffic_limit=ib_data["traffic_limit"],
            traffic_used=ib_data["traffic_used"],
            max_connections=ib_data["max_connections"],
            expiry_date=datetime.fromisoformat(ib_data["expiry_date"]) if ib_data["expiry_date"] else None,
            is_active=ib_data["is_active"],
            settings=ib_data["settings"],
            created_at=datetime.fromisoformat(ib_data["created_at"])
        )
        db.add(inbound)
    await db.commit()

    for s_data in data.get("settings", []):
        setting = Setting(key=s_data["key"], value=s_data["value"])
        db.add(setting)
    await db.commit()
    return {"ok": True}

# ---------- WebSocket برای آمار لحظه‌ای ----------
@app.websocket("/ws/stats")
async def stats_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = {
                "connections": len(connections),
                "total_bytes": stats["total_bytes"],
                "total_requests": stats["total_requests"],
                "uptime": uptime(),
                "timestamp": datetime.utcnow().isoformat()
            }
            await websocket.send_text(json.dumps(data))
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass

# ---------- WebSocket Tunnel ----------
@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str, db: AsyncSession = Depends(get_db)):
    await websocket.accept()
    conn_id = None
    client_ip = get_client_ip(websocket)

    stmt = select(Inbound).where(Inbound.uuid == uuid, Inbound.is_active == True)
    result = await db.execute(stmt)
    inbound = result.scalar_one_or_none()
    if not inbound or is_expired(inbound.expiry_date):
        await websocket.close(code=1008, reason="Inbound not found or disabled")
        return

    user = await db.get(User, inbound.user_id)
    if not user or not user.is_active or is_expired(user.expiry_date):
        await websocket.close(code=1008, reason="User disabled or expired")
        return

    max_conn = inbound.max_connections or 0
    if max_conn > 0:
        current = count_connections_for_link(uuid)
        if client_ip not in link_ip_map.get(uuid, set()):
            if current >= max_conn:
                await websocket.close(code=1008, reason="Connection limit reached")
                return

    try:
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        protocol = inbound.protocol
        if protocol == "vless":
            command, address, port, initial_payload = await parse_vless_header(first_chunk)
        elif protocol == "vmess":
            command, address, port, initial_payload = await parse_vmess_header(first_chunk)
        elif protocol == "trojan":
            command, address, port, initial_payload = await parse_trojan_header(first_chunk)
        elif protocol == "shadowsocks":
            address, port, initial_payload = await parse_shadowsocks_header(first_chunk)
            command = 0
        else:
            await websocket.close(code=1008, reason="Unsupported protocol")
            return

        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {
            "uuid": uuid,
            "user_id": user.id,
            "inbound_id": inbound.id,
            "ip": client_ip,
            "bytes": 0,
            "start_time": datetime.utcnow().isoformat()
        }
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)

        size = len(first_chunk)
        if not await consume_traffic(db, user.id, inbound.id, size):
            await websocket.close(code=1008, reason="Quota exceeded")
            return
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size

        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            if not await consume_traffic(db, user.id, inbound.id, p_size):
                await websocket.close(code=1008, reason="Quota exceeded")
                return
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            writer.write(initial_payload)
            await writer.drain()

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, db, user.id, inbound.id))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, db, user.id, inbound.id))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        await websocket.close(code=1000, reason="Timeout")
    except Exception as e:
        stats["total_errors"] += 1
        error_logs.append({"error": str(e), "time": datetime.utcnow().isoformat()})
        logger.error(f"WebSocket error: {e}")
    finally:
        if conn_id:
            await close_websocket_connection(conn_id)

# ---------- WebSocket برای اعلان‌ها ----------
@app.websocket("/ws/notifications")
async def notifications_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await asyncio.sleep(10)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        pass

# ---------- صفحات HTML ----------
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REN - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', system-ui, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #0a0a0a; color: #fff; }
        .card { background: #141414; border: 1px solid rgba(255,255,255,0.06); border-radius: 24px; padding: 40px; max-width: 400px; width: 100%; }
        h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
        .sub { color: rgba(255,255,255,0.5); font-size: 14px; margin-bottom: 24px; }
        input { width: 100%; padding: 12px 16px; background: #1c1c1c; border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; color: #fff; font-size: 14px; outline: none; margin-bottom: 16px; }
        input:focus { border-color: #dc2626; }
        button { width: 100%; padding: 12px; background: #dc2626; border: none; border-radius: 12px; color: #fff; font-weight: 600; font-size: 16px; cursor: pointer; transition: background .2s; }
        button:hover { background: #b91c1c; }
        .error { color: #ef4444; font-size: 14px; margin-top: 12px; display: none; }
    </style>
</head>
<body>
    <div class="card">
        <h1>REN</h1>
        <div class="sub">Gateway v3.0</div>
        <form id="loginForm">
            <input type="text" id="username" placeholder="Username" required>
            <input type="password" id="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
            <div class="error" id="errorMsg"></div>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const error = document.getElementById('errorMsg');
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || 'Login failed');
                }
                window.location.href = '/dashboard';
            } catch (err) {
                error.textContent = err.message;
                error.style.display = 'block';
            }
        });
    </script>
</body>
</html>
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REN - Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', system-ui, sans-serif; background: #0a0a0a; color: #fff; display: flex; min-height: 100vh; }
        .sidebar { width: 220px; background: #0f0f0f; border-right: 1px solid rgba(255,255,255,0.06); padding: 20px; }
        .sidebar h2 { font-size: 18px; margin-bottom: 24px; }
        .sidebar nav a { display: block; padding: 8px 12px; margin: 4px 0; border-radius: 8px; color: rgba(255,255,255,0.6); text-decoration: none; transition: .2s; }
        .sidebar nav a:hover, .sidebar nav a.active { background: rgba(220,38,38,0.1); color: #dc2626; }
        .main { flex: 1; padding: 24px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
        .stat { background: #141414; border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; padding: 16px; }
        .stat .label { font-size: 12px; color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 0.04em; }
        .stat .value { font-size: 24px; font-weight: 700; margin-top: 4px; }
        .card { background: #141414; border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; padding: 16px; margin-bottom: 16px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .card-title { font-weight: 600; }
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.04); }
        th { color: rgba(255,255,255,0.4); font-weight: 500; font-size: 12px; text-transform: uppercase; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
        .badge-active { background: rgba(34,197,94,0.2); color: #22c55e; }
        .badge-inactive { background: rgba(239,68,68,0.2); color: #ef4444; }
        .btn { padding: 6px 12px; border-radius: 6px; border: none; cursor: pointer; font-size: 12px; font-weight: 500; background: #2a2a2a; color: #fff; }
        .btn-primary { background: #dc2626; }
        .btn-primary:hover { background: #b91c1c; }
        .btn-sm { padding: 4px 8px; font-size: 11px; }
        .hidden { display: none; }
        .flex { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        .mb-2 { margin-bottom: 8px; }
        .mt-2 { margin-top: 8px; }
        input, select { background: #1c1c1c; border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 6px 10px; color: #fff; font-size: 13px; outline: none; }
        input:focus, select:focus { border-color: #dc2626; }
        .modal { position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: none; align-items: center; justify-content: center; z-index: 100; }
        .modal-content { background: #141414; border: 1px solid rgba(255,255,255,0.06); border-radius: 16px; padding: 24px; max-width: 500px; width: 100%; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .modal-close { background: none; border: none; color: rgba(255,255,255,0.4); font-size: 20px; cursor: pointer; }
        .modal.show { display: flex; }
        @media (max-width: 768px) {
            .sidebar { display: none; }
            .stats { grid-template-columns: 1fr 1fr; }
        }
    </style>
</head>
<body>
    <aside class="sidebar">
        <h2>REN</h2>
        <nav>
            <a href="#" class="active" data-page="dashboard">Dashboard</a>
            <a href="#" data-page="inbounds">Inbounds</a>
            <a href="#" data-page="users">Users</a>
            <a href="#" data-page="settings">Settings</a>
        </nav>
        <div style="margin-top: 24px;">
            <button onclick="logout()" style="background:none;border:none;color:rgba(255,255,255,0.4);cursor:pointer;">Logout</button>
        </div>
    </aside>
    <main class="main">
        <div id="page-dashboard">
            <h1 style="margin-bottom:16px;">Dashboard</h1>
            <div class="stats">
                <div class="stat"><div class="label">Traffic</div><div class="value" id="totalTraffic">--</div></div>
                <div class="stat"><div class="label">Inbounds</div><div class="value" id="totalInbounds">--</div></div>
                <div class="stat"><div class="label">Connections</div><div class="value" id="activeConnections">--</div></div>
                <div class="stat"><div class="label">Uptime</div><div class="value" id="uptime">--</div></div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Traffic Chart (Hourly)</span></div>
                <canvas id="trafficChart" height="150"></canvas>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">System</span></div>
                <div>CPU: <span id="cpu">--</span>%</div>
                <div>Memory: <span id="memory">--</span>%</div>
            </div>
        </div>
        <div id="page-inbounds" class="hidden">
            <div class="flex mb-2">
                <h1 style="flex:1;">Inbounds</h1>
                <button class="btn btn-primary" onclick="showAddInbound()">+ Add</button>
            </div>
            <div class="card">
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Remark</th><th>Protocol</th><th>Traffic</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody id="inboundTableBody"></tbody>
                    </table>
                </div>
            </div>
        </div>
        <div id="page-users" class="hidden">
            <div class="flex mb-2">
                <h1 style="flex:1;">Users</h1>
                <button class="btn btn-primary" onclick="showAddUser()">+ Add User</button>
            </div>
            <div class="card">
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Username</th><th>Role</th><th>Traffic Used</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody id="userTableBody"></tbody>
                    </table>
                </div>
            </div>
        </div>
        <div id="page-settings" class="hidden">
            <h1>Settings</h1>
            <div class="card">
                <div class="form-group">
                    <label>Custom Domain</label>
                    <input id="customDomain" placeholder="example.com" style="width:100%;">
                    <button class="btn btn-primary mt-2" onclick="saveSetting('domain', document.getElementById('customDomain').value)">Save</button>
                </div>
                <div class="form-group mt-2">
                    <button class="btn btn-primary" onclick="backup()">Download Backup</button>
                    <button class="btn btn-primary" onclick="document.getElementById('restoreInput').click()">Restore Backup</button>
                    <input type="file" id="restoreInput" style="display:none" accept=".json" onchange="restore(event)">
                </div>
            </div>
        </div>
    </main>

    <div class="modal" id="inboundModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="inboundModalTitle">Add Inbound</h3>
                <button class="modal-close" onclick="closeModal('inboundModal')">&times;</button>
            </div>
            <form id="inboundForm">
                <input type="hidden" id="editInboundId">
                <div class="form-group">
                    <label>Remark</label>
                    <input id="inboundRemark" placeholder="My Inbound" required>
                </div>
                <div class="form-group">
                    <label>Protocol</label>
                    <select id="inboundProtocol">
                        <option value="vless">VLESS</option>
                        <option value="vmess">VMess</option>
                        <option value="trojan">Trojan</option>
                        <option value="shadowsocks">Shadowsocks</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Traffic Limit (GB, 0=unlimited)</label>
                    <input id="inboundTrafficLimit" type="number" value="0" min="0" step="0.5">
                </div>
                <div class="form-group">
                    <label>Max Connections</label>
                    <input id="inboundMaxConn" type="number" value="0" min="0">
                </div>
                <div class="form-group">
                    <label>Expiry Days (0=never)</label>
                    <input id="inboundExpiry" type="number" value="0" min="0">
                </div>
                <button type="submit" class="btn btn-primary" style="width:100%;">Save</button>
            </form>
        </div>
    </div>

    <div class="modal" id="userModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="userModalTitle">Add User</h3>
                <button class="modal-close" onclick="closeModal('userModal')">&times;</button>
            </div>
            <form id="userForm">
                <input type="hidden" id="editUserId">
                <div class="form-group">
                    <label>Username</label>
                    <input id="userUsername" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input id="userPassword" type="password">
                </div>
                <div class="form-group">
                    <label>Role</label>
                    <select id="userRole"><option value="user">User</option><option value="admin">Admin</option></select>
                </div>
                <div class="form-group">
                    <label>Traffic Limit (GB)</label>
                    <input id="userTrafficLimit" type="number" value="0" min="0">
                </div>
                <button type="submit" class="btn btn-primary" style="width:100%;">Save</button>
            </form>
        </div>
    </div>

    <script>
        let allInbounds = [], allUsers = [];
        let trafficChart = null;
        const domain = window.location.host;

        document.querySelectorAll('.sidebar nav a').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                document.querySelectorAll('.sidebar nav a').forEach(a => a.classList.remove('active'));
                this.classList.add('active');
                const page = this.dataset.page;
                document.querySelectorAll('.main > div').forEach(div => div.classList.add('hidden'));
                document.getElementById('page-' + page).classList.remove('hidden');
                if (page === 'inbounds') loadInbounds();
                if (page === 'users') loadUsers();
            });
        });

        async function loadStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('totalTraffic').textContent = data.total_traffic_mb + ' MB';
                document.getElementById('activeConnections').textContent = data.active_connections;
                document.getElementById('uptime').textContent = data.uptime;
                document.getElementById('cpu').textContent = data.cpu_percent || 0;
                document.getElementById('memory').textContent = data.memory_percent || 0;
                updateChart(data.hourly_traffic || {});
                const inbRes = await fetch('/api/inbounds');
                const inbData = await inbRes.json();
                document.getElementById('totalInbounds').textContent = inbData.length;
                allInbounds = inbData;
            } catch(e) {}
        }

        function updateChart(hourly) {
            const ctx = document.getElementById('trafficChart').getContext('2d');
            const sorted = Object.entries(hourly).sort((a,b) => a[0].localeCompare(b[0])).slice(-12);
            const labels = sorted.map(e => e[0]);
            const data = sorted.map(e => Math.round(e[1] / (1<<20)));
            if (trafficChart) {
                trafficChart.data.labels = labels;
                trafficChart.data.datasets[0].data = data;
                trafficChart.update();
            } else {
                trafficChart = new Chart(ctx, {
                    type: 'bar',
                    data: { labels, datasets: [{ label: 'MB', data, backgroundColor: 'rgba(220,38,38,0.7)', borderColor: '#dc2626', borderWidth: 1 }] },
                    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
                });
            }
        }

        async function loadInbounds() {
            try {
                const res = await fetch('/api/inbounds');
                const data = await res.json();
                allInbounds = data;
                const tbody = document.getElementById('inboundTableBody');
                tbody.innerHTML = data.map(ib => `
                    <tr>
                        <td>${ib.remark}</td>
                        <td><span class="badge badge-active">${ib.protocol}</span></td>
                        <td>${fmtBytes(ib.traffic_used)} / ${ib.traffic_limit ? fmtBytes(ib.traffic_limit) : '∞'}</td>
                        <td><span class="badge ${ib.is_active ? 'badge-active' : 'badge-inactive'}">${ib.is_active ? 'Active' : 'Disabled'}</span></td>
                        <td>
                            <button class="btn btn-sm" onclick="editInbound(${ib.id})">Edit</button>
                            <button class="btn btn-sm" onclick="toggleInbound(${ib.id}, ${!ib.is_active})">${ib.is_active ? 'Disable' : 'Enable'}</button>
                            <button class="btn btn-sm" onclick="deleteInbound(${ib.id})" style="background:#dc2626;">Delete</button>
                            <button class="btn btn-sm" onclick="copyLink('${ib.links[0] || ''}')">Copy Link</button>
                        </td>
                    </tr>
                `).join('');
            } catch(e) {}
        }

        async function toggleInbound(id, active) {
            try {
                await fetch(`/api/inbounds/${id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ is_active: active })
                });
                loadInbounds();
            } catch(e) {}
        }

        async function deleteInbound(id) {
            if (!confirm('Delete this inbound?')) return;
            try {
                await fetch(`/api/inbounds/${id}`, { method: 'DELETE' });
                loadInbounds();
            } catch(e) {}
        }

        function showAddInbound() {
            document.getElementById('inboundModalTitle').textContent = 'Add Inbound';
            document.getElementById('editInboundId').value = '';
            document.getElementById('inboundRemark').value = '';
            document.getElementById('inboundProtocol').value = 'vless';
            document.getElementById('inboundTrafficLimit').value = '0';
            document.getElementById('inboundMaxConn').value = '0';
            document.getElementById('inboundExpiry').value = '0';
            document.getElementById('inboundModal').classList.add('show');
        }

        function editInbound(id) {
            const ib = allInbounds.find(x => x.id === id);
            if (!ib) return;
            document.getElementById('inboundModalTitle').textContent = 'Edit Inbound';
            document.getElementById('editInboundId').value = ib.id;
            document.getElementById('inboundRemark').value = ib.remark;
            document.getElementById('inboundProtocol').value = ib.protocol;
            document.getElementById('inboundTrafficLimit').value = ib.traffic_limit / (1<<30) || 0;
            document.getElementById('inboundMaxConn').value = ib.max_connections;
            document.getElementById('inboundExpiry').value = ib.expiry_date ? Math.ceil((new Date(ib.expiry_date) - new Date()) / (86400000)) : 0;
            document.getElementById('inboundModal').classList.add('show');
        }

        document.getElementById('inboundForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const id = document.getElementById('editInboundId').value;
            const data = {
                remark: document.getElementById('inboundRemark').value,
                protocol: document.getElementById('inboundProtocol').value,
                traffic_limit: parseFloat(document.getElementById('inboundTrafficLimit').value) * (1<<30),
                max_connections: parseInt(document.getElementById('inboundMaxConn').value) || 0,
                expiry_days: parseInt(document.getElementById('inboundExpiry').value) || 0
            };
            try {
                const url = id ? `/api/inbounds/${id}` : '/api/inbounds';
                const method = id ? 'PUT' : 'POST';
                const res = await fetch(url, {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (res.ok) {
                    closeModal('inboundModal');
                    loadInbounds();
                } else {
                    alert('Error');
                }
            } catch(e) { alert('Error'); }
        });

        async function loadUsers() {
            try {
                const res = await fetch('/api/users');
                const data = await res.json();
                allUsers = data;
                const tbody = document.getElementById('userTableBody');
                tbody.innerHTML = data.map(u => `
                    <tr>
                        <td>${u.username}</td>
                        <td>${u.role}</td>
                        <td>${fmtBytes(u.traffic_used)} / ${u.traffic_limit ? fmtBytes(u.traffic_limit) : '∞'}</td>
                        <td><span class="badge ${u.is_active ? 'badge-active' : 'badge-inactive'}">${u.is_active ? 'Active' : 'Inactive'}</span></td>
                        <td>
                            <button class="btn btn-sm" onclick="editUser(${u.id})">Edit</button>
                            <button class="btn btn-sm" onclick="deleteUser(${u.id})" style="background:#dc2626;">Delete</button>
                        </td>
                    </tr>
                `).join('');
            } catch(e) {}
        }

        function showAddUser() {
            document.getElementById('userModalTitle').textContent = 'Add User';
            document.getElementById('editUserId').value = '';
            document.getElementById('userUsername').value = '';
            document.getElementById('userPassword').value = '';
            document.getElementById('userRole').value = 'user';
            document.getElementById('userTrafficLimit').value = '0';
            document.getElementById('userModal').classList.add('show');
        }

        function editUser(id) {
            const u = allUsers.find(x => x.id === id);
            if (!u) return;
            document.getElementById('userModalTitle').textContent = 'Edit User';
            document.getElementById('editUserId').value = u.id;
            document.getElementById('userUsername').value = u.username;
            document.getElementById('userPassword').value = '';
            document.getElementById('userRole').value = u.role;
            document.getElementById('userTrafficLimit').value = u.traffic_limit / (1<<30) || 0;
            document.getElementById('userModal').classList.add('show');
        }

        async function deleteUser(id) {
            if (!confirm('Delete this user?')) return;
            try {
                await fetch(`/api/users/${id}`, { method: 'DELETE' });
                loadUsers();
            } catch(e) {}
        }

        document.getElementById('userForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const id = document.getElementById('editUserId').value;
            const data = {
                username: document.getElementById('userUsername').value,
                password: document.getElementById('userPassword').value,
                role: document.getElementById('userRole').value,
                traffic_limit: parseFloat(document.getElementById('userTrafficLimit').value) * (1<<30)
            };
            try {
                const url = id ? `/api/users/${id}` : '/api/users';
                const method = id ? 'PUT' : 'POST';
                const res = await fetch(url, {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (res.ok) {
                    closeModal('userModal');
                    loadUsers();
                } else {
                    alert('Error');
                }
            } catch(e) { alert('Error'); }
        });

        async function saveSetting(key, value) {
            try {
                await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ [key]: value })
                });
                alert('Saved');
            } catch(e) { alert('Error'); }
        }

        async function backup() {
            try {
                const res = await fetch('/api/backup');
                const blob = await res.blob();
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'ren_backup.json';
                a.click();
            } catch(e) { alert('Backup failed'); }
        }

        async function restore(event) {
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    const data = JSON.parse(e.target.result);
                    await fetch('/api/restore', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    alert('Restored');
                    location.reload();
                } catch(err) { alert('Restore failed'); }
            };
            reader.readAsText(file);
        }

        function fmtBytes(b) {
            if (b >= 1<<30) return (b/(1<<30)).toFixed(2) + ' GB';
            if (b >= 1<<20) return (b/(1<<20)).toFixed(2) + ' MB';
            if (b >= 1<<10) return (b/(1<<10)).toFixed(2) + ' KB';
            return b + ' B';
        }

        function copyLink(link) {
            navigator.clipboard.writeText(link).then(() => alert('Copied!')).catch(() => {});
        }

        function closeModal(id) {
            document.getElementById(id).classList.remove('show');
        }

        function logout() {
            fetch('/api/auth/logout', { method: 'POST' }).then(() => window.location.href = '/login');
        }

        loadStats();
        loadInbounds();
        loadUsers();
        setInterval(loadStats, 10000);
    </script>
</body>
</html>
"""

# ---------- Pages ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(settings.SESSION_COOKIE)
    if not token:
        return RedirectResponse(url="/login")
    try:
        decode_token(token)
        return HTMLResponse(content=DASHBOARD_HTML)
    except:
        response = RedirectResponse(url="/login")
        response.delete_cookie(settings.SESSION_COOKIE)
        return response

# ---------- Startup ----------
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        stmt = select(User).where(User.username == "admin")
        result = await db.execute(stmt)
        admin = result.scalar_one_or_none()
        if not admin:
            hashed = hash_password(settings.ADMIN_PASSWORD)
            admin = User(
                username="admin",
                password_hash=hashed,
                role="admin",
                is_active=True,
                created_at=datetime.utcnow()
            )
            db.add(admin)
            await db.commit()
            logger.info("Admin user created with default password")

@app.on_event("startup")
async def startup_event():
    await init_db()
    asyncio.create_task(auto_backup(AsyncSessionLocal()))
    logger.info(f"REN Gateway v{settings.VERSION} started on port {settings.PORT}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down...")

# ---------- Run ----------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=settings.PORT)
