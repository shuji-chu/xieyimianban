from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uuid
import subprocess
import db
import os
import re
import io
import json
import hmac
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from PIL import Image, ImageOps, UnidentifiedImageError

app = FastAPI(title="xieyimianban 面板后端")
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "https://shuji-chu.github.io").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=False, allow_methods=["GET", "POST", "PUT", "OPTIONS"], allow_headers=["Authorization", "Content-Type", "Accept"])

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response

# Server configuration is supplied through deployment environment variables.
NODE_IP = os.getenv("NODE_IP", "").strip()
XRAY_API_PORT = os.getenv("XRAY_API_PORT", "10085").strip()
NODE_API_TOKEN = os.getenv("NODE_API_TOKEN", "").strip()

# S3-compatible object storage (Alibaba OSS S3 endpoint or Cloudflare R2).
S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL", "").strip()
S3_REGION = os.getenv("S3_REGION", "us-east-1").strip()
S3_BUCKET = os.getenv("S3_BUCKET", "").strip()
S3_ACCESS_KEY_ID = os.getenv("S3_ACCESS_KEY_ID", "").strip()
S3_SECRET_ACCESS_KEY = os.getenv("S3_SECRET_ACCESS_KEY", "").strip()
MEDIA_PUBLIC_BASE_URL = os.getenv("MEDIA_PUBLIC_BASE_URL", "").strip().rstrip("/")
HOME_BANNERS_OBJECT_KEY = os.getenv("HOME_BANNERS_OBJECT_KEY", "site-config/home-banners.json").strip()
ADMIN_AUTH_VERIFY_URL = os.getenv("ADMIN_AUTH_VERIFY_URL", "").strip()
USER_API_BASE = os.getenv("USER_API_BASE", "https://web.lynli.me/api/v1").strip().rstrip("/")

@app.on_event("startup")
def startup():
    db.init_db()

class UserCreate(BaseModel):
    email: str
    protocol: str = "vless"

@app.post("/api/create")
def create_node(user: UserCreate, request: Request):
    # Fail closed: never expose a node-creation operation without a server-side secret.
    supplied = request.headers.get("authorization", "")
    supplied = supplied[7:].strip() if supplied.lower().startswith("bearer ") else ""
    if not NODE_API_TOKEN or not supplied or not hmac.compare_digest(supplied, NODE_API_TOKEN):
        raise HTTPException(status_code=401, detail="Authentication required")
    if not NODE_IP or not re.fullmatch(r"[A-Za-z0-9.:-]+", NODE_IP):
        raise HTTPException(status_code=503, detail="Node API is not configured")
    if not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", user.email or "") or len(user.email) > 254:
        raise HTTPException(status_code=400, detail="Invalid email address")
    if user.protocol not in {"vless", "vmess", "trojan", "shadowsocks"}:
        raise HTTPException(status_code=400, detail="Unsupported protocol")
    new_uuid = str(uuid.uuid4())
    
    if not db.add_user_to_db(user.email, new_uuid, user.protocol):
        raise HTTPException(status_code=400, detail="用户已存在")

    if user.protocol == "vless":
        cmd = [
            "xray", "api", "adi",
            f"--server={NODE_IP}:{XRAY_API_PORT}",
            f'inbounds[0].settings.clients=[{{"id":"{new_uuid}", "email":"{user.email}"}}]'
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=12)
            return {"status": "success", "uuid": new_uuid}
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="Node API timed out")
        except subprocess.CalledProcessError:
            # Do not return command output or infrastructure details to callers.
            raise HTTPException(status_code=502, detail="Node API rejected the request")
    
    return {"status": "pending"}

@app.get("/api/v1/user/orders")
async def proxy_user_orders(request: Request, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=100)):
    # The upstream must scope results to the identity represented by this Bearer token.
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if len(token) < 8:
        raise HTTPException(status_code=401, detail="Login required")
    parsed = urlparse(USER_API_BASE)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(status_code=503, detail="USER_API_BASE must be an HTTPS API base")
    async with httpx.AsyncClient(timeout=12, follow_redirects=False) as client:
        last_status = 404
        for path in ("/user/order/fetch", "/user/order/list", "/user/orders"):
            try:
                response = await client.get(
                    USER_API_BASE + path,
                    headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
                    params={"page": page, "page_size": page_size, "limit": page_size},
                )
            except httpx.HTTPError:
                raise HTTPException(status_code=502, detail="Order service unavailable")
            if response.status_code in (401, 403):
                raise HTTPException(status_code=401, detail="Login expired or unauthorized")
            if response.status_code in (404, 405):
                last_status = response.status_code
                continue
            if not response.is_success:
                raise HTTPException(status_code=502, detail="Order service returned HTTP " + str(response.status_code))
            try:
                body = response.json()
                return JSONResponse(content=body, headers={"Cache-Control": "private, no-store, max-age=0", "Vary": "Authorization", "X-Content-Type-Options": "nosniff"})
            except ValueError:
                raise HTTPException(status_code=502, detail="Order service returned invalid JSON")
    raise HTTPException(status_code=502, detail="Upstream order history endpoint is not available (last HTTP " + str(last_status) + ")")

def object_store():
    if not all((S3_ENDPOINT_URL, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, MEDIA_PUBLIC_BASE_URL)):
        raise HTTPException(status_code=503, detail="Object storage is not configured")
    parsed = urlparse(S3_ENDPOINT_URL)
    media_url = urlparse(MEDIA_PUBLIC_BASE_URL)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(status_code=503, detail="S3_ENDPOINT_URL must be a valid HTTPS endpoint")
    if media_url.scheme != "https" or not media_url.netloc:
        raise HTTPException(status_code=503, detail="MEDIA_PUBLIC_BASE_URL must be a valid HTTPS URL")
    return boto3.client(
        "s3", endpoint_url=S3_ENDPOINT_URL, region_name=S3_REGION,
        aws_access_key_id=S3_ACCESS_KEY_ID, aws_secret_access_key=S3_SECRET_ACCESS_KEY,
    )

async def require_admin(request: Request):
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if len(token) < 8:
        raise HTTPException(status_code=401, detail="Administrator authentication required")
    if not ADMIN_AUTH_VERIFY_URL:
        raise HTTPException(status_code=503, detail="ADMIN_AUTH_VERIFY_URL is not configured")
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            response = await client.get(ADMIN_AUTH_VERIFY_URL, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Administrator identity provider unavailable")
    if response.status_code in (401, 403):
        raise HTTPException(status_code=401, detail="Administrator authentication failed")
    if not response.is_success:
        raise HTTPException(status_code=502, detail="Administrator identity provider returned an error")
    return token

def banner_config_key():
    if not re.fullmatch(r"[A-Za-z0-9_./-]{1,180}", HOME_BANNERS_OBJECT_KEY) or ".." in HOME_BANNERS_OBJECT_KEY.split("/"):
        raise HTTPException(status_code=500, detail="Invalid banner object key configuration")
    return HOME_BANNERS_OBJECT_KEY

def read_banners():
    client = object_store()
    try:
        response = client.get_object(Bucket=S3_BUCKET, Key=banner_config_key())
        payload = json.loads(response["Body"].read(512 * 1024 + 1).decode("utf-8"))
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code in {"NoSuchKey", "404", "NotFound"}:
            return []
        raise HTTPException(status_code=502, detail="Unable to read banner configuration")
    except (BotoCoreError, UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=502, detail="Banner configuration storage error")
    if not isinstance(payload, list):
        raise HTTPException(status_code=502, detail="Stored banner configuration is invalid")
    return payload[:30]

@app.get("/api/v1/public/home-banners")
async def public_home_banners():
    return JSONResponse(content={"success": True, "data": [b for b in read_banners() if isinstance(b, dict) and b.get("enabled") is True]}, headers={"Cache-Control": "no-store, max-age=0", "X-Content-Type-Options": "nosniff"})

@app.get("/api/v1/admin/home-banners")
async def admin_get_home_banners(request: Request):
    await require_admin(request)
    return {"success": True, "data": read_banners()}

class BannerConfig(BaseModel):
    banners: list[dict] = Field(max_length=30)

@app.put("/api/v1/admin/home-banners")
async def admin_save_home_banners(payload: BannerConfig, request: Request):
    await require_admin(request)
    clean = []
    allowed = {"id", "title", "subtitle", "image", "link", "button", "sort", "enabled", "theme", "newtab", "updated_at"}
    for row in payload.banners:
        if not isinstance(row, dict):
            raise HTTPException(status_code=400, detail="Each banner must be an object")
        title = str(row.get("title", "")).strip()
        subtitle = str(row.get("subtitle", "")).strip()
        image = str(row.get("image", "")).strip()
        link = str(row.get("link", "")).strip()
        parsed_image, parsed_link = urlparse(image), urlparse(link)
        if not title or len(title) > 80 or len(subtitle) > 180:
            raise HTTPException(status_code=400, detail="Banner title or subtitle length is invalid")
        if parsed_image.scheme != "https" or not parsed_image.netloc or len(image) > 2048:
            raise HTTPException(status_code=400, detail="Banner image must be an HTTPS URL")
        if len(link) > 2048 or link.lower().startswith(("javascript:", "data:", "vbscript:")):
            raise HTTPException(status_code=400, detail="Banner link is invalid")
        if parsed_link.scheme and parsed_link.scheme not in {"http", "https"}:
            raise HTTPException(status_code=400, detail="Only HTTP(S) or relative banner links are allowed")
        try:
            sort_order = int(row.get("sort") or 0)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Banner sort must be an integer")
        clean.append({
            "id": str(row.get("id") or uuid.uuid4().hex)[:100],
            "title": title, "subtitle": subtitle, "image": image, "link": link,
            "button": str(row.get("button") or "立即查看")[:24],
            "sort": max(0, min(100000, sort_order)),
            "enabled": row.get("enabled") is True,
            "theme": "light" if row.get("theme") == "light" else "dark",
            "newtab": row.get("newtab") is True,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
    clean.sort(key=lambda x: x["sort"])
    raw = json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > 512 * 1024:
        raise HTTPException(status_code=413, detail="Banner configuration is too large")
    client = object_store()
    try:
        client.put_object(Bucket=S3_BUCKET, Key=banner_config_key(), Body=raw, ContentType="application/json; charset=utf-8", CacheControl="no-store")
    except (BotoCoreError, ClientError):
        raise HTTPException(status_code=502, detail="Unable to save banner configuration")
    return {"success": True, "count": len(clean), "data": clean}

TELEGRAM_BOTS_OBJECT_KEY = os.getenv("TELEGRAM_BOTS_OBJECT_KEY", "site-config/telegram-bots.json")

def telegram_bots_key():
    if not re.fullmatch(r"[A-Za-z0-9_./-]{1,180}", TELEGRAM_BOTS_OBJECT_KEY) or ".." in TELEGRAM_BOTS_OBJECT_KEY.split("/"):
        raise HTTPException(status_code=500, detail="Invalid Telegram bot configuration key")
    return TELEGRAM_BOTS_OBJECT_KEY

def read_telegram_bots():
    client = object_store()
    try:
        response = client.get_object(Bucket=S3_BUCKET, Key=telegram_bots_key())
        payload = json.loads(response["Body"].read(128 * 1024 + 1).decode("utf-8"))
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code in {"NoSuchKey", "404", "NotFound"}:
            return []
        raise HTTPException(status_code=502, detail="Unable to read Telegram bot configuration")
    except (BotoCoreError, UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=502, detail="Telegram bot configuration storage error")
    if not isinstance(payload, list):
        raise HTTPException(status_code=502, detail="Stored Telegram bot configuration is invalid")
    return payload[:20]

@app.get("/api/v1/public/telegram-bots")
async def public_telegram_bots():
    bots = []
    for row in read_telegram_bots():
        if not isinstance(row, dict) or row.get("enabled") is not True:
            continue
        username = str(row.get("username") or "").strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", username):
            continue
        bots.append({
            "id": str(row.get("id") or "")[:40],
            "name": str(row.get("name") or "Telegram 机器人")[:48],
            "username": username,
            "subtitle": str(row.get("subtitle") or "")[:100],
            "description": str(row.get("description") or "")[:500],
            "button": str(row.get("button") or "打开 Telegram")[:40],
            "sort": int(row.get("sort") or 0),
            "enabled": True,
        })
    bots.sort(key=lambda item: item["sort"])
    return JSONResponse(content={"success": True, "data": bots}, headers={"Cache-Control": "no-store, max-age=0", "X-Content-Type-Options": "nosniff"})

@app.get("/api/v1/admin/telegram-bots")
async def admin_get_telegram_bots(request: Request):
    await require_admin(request)
    return {"success": True, "data": read_telegram_bots()}

class TelegramBotConfig(BaseModel):
    bots: list[dict] = Field(max_length=20)

@app.put("/api/v1/admin/telegram-bots")
async def admin_save_telegram_bots(payload: TelegramBotConfig, request: Request):
    await require_admin(request)
    clean = []
    seen = set()
    for row in payload.bots:
        if not isinstance(row, dict):
            raise HTTPException(status_code=400, detail="Each bot must be an object")
        bot_id = str(row.get("id") or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9_-]{1,40}", bot_id) or bot_id in seen:
            raise HTTPException(status_code=400, detail="Telegram bot IDs must be unique valid identifiers")
        seen.add(bot_id)
        username = str(row.get("username") or "").strip().lstrip("@")
        if username and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", username):
            raise HTTPException(status_code=400, detail="Telegram username format is invalid")
        try:
            sort_order = int(row.get("sort") or 0)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Bot sort must be an integer")
        clean.append({
            "id": bot_id,
            "name": str(row.get("name") or bot_id)[:48],
            "username": username,
            "subtitle": str(row.get("subtitle") or "")[:100],
            "description": str(row.get("description") or "")[:500],
            "button": str(row.get("button") or "打开 Telegram")[:40],
            "sort": max(0, min(100000, sort_order)),
            "enabled": row.get("enabled") is True,
        })
    clean.sort(key=lambda item: item["sort"])
    raw = json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    client = object_store()
    try:
        client.put_object(Bucket=S3_BUCKET, Key=telegram_bots_key(), Body=raw, ContentType="application/json; charset=utf-8", CacheControl="no-store")
    except (BotoCoreError, ClientError):
        raise HTTPException(status_code=502, detail="Unable to save Telegram bot configuration")
    return {"success": True, "count": len(clean), "data": clean}

ACCOUNT_CARD_OVERRIDES_OBJECT_KEY = os.getenv("ACCOUNT_CARD_OVERRIDES_OBJECT_KEY", "site-config/account-card-overrides.json")

def account_card_overrides_key():
    if not re.fullmatch(r"[A-Za-z0-9_./-]{1,180}", ACCOUNT_CARD_OVERRIDES_OBJECT_KEY) or ".." in ACCOUNT_CARD_OVERRIDES_OBJECT_KEY.split("/"):
        raise HTTPException(status_code=500, detail="Invalid account card override key")
    return ACCOUNT_CARD_OVERRIDES_OBJECT_KEY

def read_account_card_overrides():
    client = object_store()
    try:
        response = client.get_object(Bucket=S3_BUCKET, Key=account_card_overrides_key())
        payload = json.loads(response["Body"].read(1024 * 1024 + 1).decode("utf-8"))
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code in {"NoSuchKey", "404", "NotFound"}:
            return []
        raise HTTPException(status_code=502, detail="Unable to read account card configuration")
    except (BotoCoreError, UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=502, detail="Account card configuration storage error")
    if not isinstance(payload, list):
        raise HTTPException(status_code=502, detail="Stored account card configuration is invalid")
    return payload[:500]

def clean_account_card_overrides(rows):
    clean = []
    seen = set()
    allowed_categories = {"Facebook", "Instagram", "TikTok", "X / Twitter", "Telegram", "Google / Gmail", "WhatsApp", "Discord", "YouTube", "Reddit", "其他账号", "海外账号资源"}
    for row in rows:
        if not isinstance(row, dict):
            raise HTTPException(status_code=400, detail="Each account card override must be an object")
        product_id = str(row.get("id") or "").strip()[:100]
        if not product_id or product_id in seen:
            raise HTTPException(status_code=400, detail="Account card IDs must be unique and non-empty")
        seen.add(product_id)
        category = str(row.get("account_category") or "海外账号资源").strip()
        if category not in allowed_categories:
            category = "其他账号"
        image_url = str(row.get("image_url") or "").strip()
        if image_url:
            parsed = urlparse(image_url)
            if parsed.scheme != "https" or not parsed.netloc or any(ch in image_url for ch in '\r\n"<>'):
                raise HTTPException(status_code=400, detail="Account card image must be a valid HTTPS URL")
            image_url = image_url[:2048]
        clean.append({
            "id": product_id,
            "category": "账号服务",
            "product_type": "account",
            "account_category": category,
            "platform": category,
            "image_url": image_url,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
    return clean

@app.get("/api/v1/public/catalog/account-overrides")
async def public_account_card_overrides():
    return JSONResponse(content={"success": True, "data": clean_account_card_overrides(read_account_card_overrides())}, headers={"Cache-Control": "no-store, max-age=0", "X-Content-Type-Options": "nosniff"})

@app.get("/api/v1/admin/catalog/account-overrides")
async def admin_get_account_card_overrides(request: Request):
    await require_admin(request)
    return {"success": True, "data": clean_account_card_overrides(read_account_card_overrides())}

class AccountCardOverrides(BaseModel):
    overrides: list[dict] = Field(max_length=500)

@app.put("/api/v1/admin/catalog/account-overrides")
async def admin_save_account_card_overrides(payload: AccountCardOverrides, request: Request):
    await require_admin(request)
    clean = clean_account_card_overrides(payload.overrides)
    raw = json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="Account card configuration is too large")
    client = object_store()
    try:
        client.put_object(Bucket=S3_BUCKET, Key=account_card_overrides_key(), Body=raw, ContentType="application/json; charset=utf-8", CacheControl="no-store")
    except (BotoCoreError, ClientError):
        raise HTTPException(status_code=502, detail="Unable to save account card configuration")
    return {"success": True, "count": len(clean), "data": clean}

@app.post("/api/v1/admin/media/upload")
async def admin_upload_media(request: Request, file: UploadFile = File(...)):
    await require_admin(request)
    if file.content_type not in {"image/jpeg", "image/png", "image/webp", "image/gif"}:
        raise HTTPException(status_code=415, detail="Only JPEG, PNG, WebP, or GIF images are accepted")
    raw = await file.read(8 * 1024 * 1024 + 1)
    if not raw or len(raw) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Image must be smaller than 8 MB")
    try:
        with Image.open(io.BytesIO(raw)) as source:
            if source.width < 1 or source.height < 1 or source.width * source.height > 24_000_000:
                raise HTTPException(status_code=413, detail="Image dimensions are too large")
            source.seek(0)
            image = ImageOps.exif_transpose(source).convert("RGB")
            image.thumbnail((1600, 1000), Image.Resampling.LANCZOS)
            output = io.BytesIO()
            image.save(output, format="WEBP", quality=82, method=6)
            output.seek(0)
    except HTTPException:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise HTTPException(status_code=400, detail="Invalid or unsupported image")
    key = "banners/" + uuid.uuid4().hex + ".webp"
    client = object_store()
    encoded = output.getvalue()
    try:
        client.put_object(Bucket=S3_BUCKET, Key=key, Body=encoded, ContentType="image/webp", CacheControl="public, max-age=31536000, immutable")
    except (BotoCoreError, ClientError):
        raise HTTPException(status_code=502, detail="Image upload to object storage failed")
    return {"success": True, "data": {"url": MEDIA_PUBLIC_BASE_URL + "/" + key, "key": key, "content_type": "image/webp", "size": len(encoded)}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
