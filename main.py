# license_server/main.py
# =========================================================
# FIGAS OPTIMIZER — LICENSE SERVER
# Suporta: MENSAL (30 dias) e VITALÍCIO (null)
# Associação a PC e transferência a cada 30 dias
# =========================================================

import base64
import hashlib
import json
import os
import secrets
import sqlite3

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(
    os.getenv("FIGAS_LICENSE_DB", str(BASE_DIR / "licenses.db"))
)

ADMIN_TOKEN = os.getenv("FIGAS_ADMIN_TOKEN", "")
TRANSFER_DAYS = 30
TOKEN_DAYS = 30

def _signing_key():
    """FIGAS_SIGNING_KEY = 32 bytes em base64"""
    raw = os.getenv("FIGAS_SIGNING_KEY", "").strip()
    if not raw:
        raise HTTPException(status_code=503, detail="Servidor sem chave de assinatura configurada.")
    # Corrige padding e aceita urlsafe ou standard
    raw_padded = raw + "=" * (-len(raw) % 4)
    try:
        key_bytes = base64.urlsafe_b64decode(raw_padded)
    except:
        key_bytes = base64.b64decode(raw_padded)
    return Ed25519PrivateKey.from_private_bytes(key_bytes)

def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def issue_token(device_id: str, lic_expires_at) -> str:
    """Token que o cliente verifica offline"""
    now = int(utc_now().timestamp())
    payload = {
        "v": 1,
        "tier": "pro",
        "dev": hashlib.sha256(device_id.strip().encode("utf-8")).hexdigest()[:32],
        "iat": now,
        "exp": now + TOKEN_DAYS * 86400,
        "lic_exp": lic_expires_at,  # None = vitalício
    }
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _signing_key().sign(body.encode("ascii"))
    return f"{body}.{_b64e(signature)}"

def utc_now():
    return datetime.now(timezone.utc)

def parse_datetime(value: str):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result

def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def get_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection

def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT NOT NULL UNIQUE,
                tier TEXT NOT NULL DEFAULT 'pro',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                device_id TEXT,
                last_transfer_at TEXT
            )
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(licenses)").fetchall()}
        if "device_id" not in columns:
            db.execute("ALTER TABLE licenses ADD COLUMN device_id TEXT")
        if "last_transfer_at" not in columns:
            db.execute("ALTER TABLE licenses ADD COLUMN last_transfer_at TEXT")

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield

app = FastAPI(title="Figas Optimizer License Server", version="2.0.0", lifespan=lifespan)

class DeviceLicenseRequest(BaseModel):
    license_key: str = Field(min_length=1, max_length=200)
    device_id: str = Field(min_length=16, max_length=200)

class CreateLicenseRequest(BaseModel):
    # None = VITALÍCIO, 30 = MENSAL, 7 = TRIAL
    duration_days: Optional[int] = Field(default=None, ge=1, le=3650)

def require_admin(token: Optional[str]):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="Token administrativo não configurado.")
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Token administrativo inválido.")

def find_license(key: str):
    with get_connection() as db:
        return db.execute("SELECT * FROM licenses WHERE key_hash = ?", (hash_value(key.strip()),)).fetchone()

def is_license_active(row):
    if row is None or row["status"] != "active":
        return False
    if row["tier"] != "pro":
        return False
    expires_at = row["expires_at"]
    if expires_at and parse_datetime(expires_at) <= utc_now():
        return False
    return True

def license_response(row, device_id):
    return {
        "valid": True,
        "tier": "pro",
        "expires_at": row["expires_at"],
        "token": issue_token(device_id, row["expires_at"]),
        "message": "Licença PRO válida."
    }

@app.get("/health")
def health():
    return {"status": "ok", "service": "figas-license-server"}

@app.post("/licenses/activate")
def activate_license(payload: DeviceLicenseRequest):
    key = payload.license_key.strip()
    device = hash_value(payload.device_id.strip())
    row = find_license(key)
    if not is_license_active(row):
        raise HTTPException(status_code=403, detail="Licença inválida, expirada ou revogada.")
    now = utc_now()
    current_device = row["device_id"]
    last_transfer = row["last_transfer_at"]

    if not current_device:
        with get_connection() as db:
            cursor = db.execute("UPDATE licenses SET device_id = ?, last_transfer_at = ? WHERE id = ? AND device_id IS NULL", (device, now.isoformat(), row["id"]))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=409, detail="A licença foi alterada. Tenta novamente.")
        return {"success": True, "tier": "pro", "expires_at": row["expires_at"], "token": issue_token(payload.device_id, row["expires_at"]), "message": "Licença associada a este PC."}

    if secrets.compare_digest(current_device, device):
        return {"success": True, "tier": "pro", "expires_at": row["expires_at"], "token": issue_token(payload.device_id, row["expires_at"]), "message": "Este PC já está autorizado."}

    if last_transfer:
        next_transfer = parse_datetime(last_transfer) + timedelta(days=TRANSFER_DAYS)
        if now < next_transfer:
            raise HTTPException(status_code=409, detail={"message": "A licença está associada a outro PC. A transferência ainda não está disponível.", "next_transfer_at": next_transfer.isoformat()})

    with get_connection() as db:
        cursor = db.execute("UPDATE licenses SET device_id = ?, last_transfer_at = ? WHERE id = ? AND device_id = ?", (device, now.isoformat(), row["id"], current_device))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=409, detail="A licença foi alterada. Tenta novamente.")
    return {"success": True, "tier": "pro", "expires_at": row["expires_at"], "token": issue_token(payload.device_id, row["expires_at"]), "message": "Licença transferida para este PC."}

@app.post("/licenses/validate")
def validate_license(payload: DeviceLicenseRequest):
    row = find_license(payload.license_key.strip())
    if not is_license_active(row):
        return {"valid": False, "tier": "basic", "expires_at": None, "message": "Licença inválida, expirada ou revogada."}
    device = hash_value(payload.device_id.strip())
    current_device = row["device_id"]
    if not current_device or not secrets.compare_digest(current_device, device):
        return {"valid": False, "tier": "basic", "expires_at": row["expires_at"], "message": "Esta licença não está ativada neste PC."}
    return license_response(row, payload.device_id)

@app.post("/admin/licenses", status_code=201)
def create_license(payload: CreateLicenseRequest, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    
    is_lifetime = payload.duration_days is None
    prefix = "FIGAS-LIFE-" if is_lifetime else "FIGAS-MONTH-"
    key = prefix + secrets.token_hex(16).upper()
    created = utc_now().replace(microsecond=0)
    expires = None
    if not is_lifetime:
        expires = (created + timedelta(days=payload.duration_days)).isoformat()

    with get_connection() as db:
        db.execute("INSERT INTO licenses (key_hash, tier, status, created_at, expires_at) VALUES (?, 'pro', 'active', ?, ?)", (hash_value(key), created.isoformat(), expires))

    return {
        "license_key": key,
        "type": "VITALÍCIO" if is_lifetime else f"MENSAL {payload.duration_days} dias",
        "tier": "pro",
        "status": "active",
        "created_at": created.isoformat(),
        "expires_at": expires
    }

@app.post("/admin/licenses/{license_key}/revoke")
def revoke_license(license_key: str, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    with get_connection() as db:
        cursor = db.execute("UPDATE licenses SET status = 'revoked' WHERE key_hash = ?", (hash_value(license_key.strip()),))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Licença não encontrada.")
    return {"success": True, "message": "Licença revogada."}
