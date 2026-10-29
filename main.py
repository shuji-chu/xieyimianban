from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
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

# ⚠️ 记得这里改成你节点机的真实 IP
NODE_IP = "1.2.3.4" 
XRAY_API_PORT = "10085"

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
    if not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+", user.email or "") or len(user.email) > 254:
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
    return {"success": True, "data": [b for b in read_banners() if isinstance(b, dict) and b.get("enabled") is True]}

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
