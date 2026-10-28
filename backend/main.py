from __future__ import annotations
import ipaddress, os, re
from typing import Any
import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError

app = FastAPI(title="SOSKS5 Admin API", version="1.0.0")
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "https://shuji-chu.github.io").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "OPTIONS"], allow_headers=["Authorization", "Content-Type", "Accept"])
DATABASE_URL = os.getenv("DATABASE_URL", "")
INVENTORY_TABLE = os.getenv("INVENTORY_TABLE", "inventory")
UPSTREAM_ADMIN_URL = os.getenv("UPSTREAM_ADMIN_URL", "https://api.lynli.me/api/admin").rstrip("/")
BOTS_STATUS_URL = os.getenv("BOTS_STATUS_URL", "").strip()
engine = create_engine(DATABASE_URL, pool_pre_ping=True) if DATABASE_URL else None
DOMAINS = ("inbox.ru", "list.ru", "bk.ru", "mail.ru")
BOT_NAMES = ("signbot", "mivrabot", "qingtian_bot")

def auth_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer ") or len(header.split(" ", 1)[1].strip()) < 8:
        raise HTTPException(401, "Missing bearer token")
    return header.split(" ", 1)[1].strip()

def classify(email: str) -> str:
    host = email.rsplit("@", 1)[-1].lower()
    return "@" + host if host in DOMAINS else "其他"

def table_identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise HTTPException(500, "Invalid INVENTORY_TABLE configuration")
    return value

async def upstream(path: str, token: str):
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            response = await client.get(UPSTREAM_ADMIN_URL + path, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise HTTPException(502, "Upstream API unavailable: " + type(exc).__name__)
    if response.status_code == 401:
        raise HTTPException(401, "Authentication expired")
    if response.status_code >= 400:
        raise HTTPException(502, "Upstream returned HTTP " + str(response.status_code))
    try:
        return response.json()
    except ValueError:
        raise HTTPException(502, "Upstream returned invalid JSON")

def extract_items(payload: Any, keys: tuple[str, ...]) -> list[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in keys:
            if isinstance(payload.get(key), list):
                return payload[key]
        data = payload.get("data")
        if isinstance(data, dict):
            for key in keys:
                if isinstance(data.get(key), list):
                    return data[key]
    return []

@app.get("/health")
async def health():
    return {"ok": True, "service": "sosks5-admin-api"}

@app.get("/api/admin/inventory")
async def inventory(request: Request, limit: int = Query(500, ge=1, le=1000), domain: str | None = None):
    token = auth_token(request)
    if engine is None:
        payload = await upstream("/inventory?limit=" + str(limit), token)
        items = extract_items(payload, ("items", "inventory", "results", "data", "records"))
        for item in items:
            item["email_domain"] = classify(str(item.get("email") or item.get("email_account") or item.get("account") or item.get("login") or ""))
        counts = {"@" + d: sum(1 for item in items if item["email_domain"] == "@" + d) for d in DOMAINS}
        if domain:
            if domain.lower() not in counts:
                raise HTTPException(400, "Unsupported domain")
            items = [item for item in items if item["email_domain"] == domain.lower()]
        return {"items": items[:limit], "total": len(items), "domain_counts": counts, "source": "upstream"}
    table = table_identifier(INVENTORY_TABLE)
    try:
        columns = {col["name"].lower(): col["name"] for col in inspect(engine).get_columns(table)}
        email_col = next((columns[k] for k in ("email", "email_account", "email_address", "account", "login") if k in columns), None)
        if not email_col:
            raise HTTPException(500, "Inventory table has no email column")
        with engine.connect() as conn:
            total = conn.execute(text('SELECT COUNT(*) FROM "' + table + '"')).scalar_one()
            counts = {d: conn.execute(text('SELECT COUNT(*) FROM "' + table + '" WHERE LOWER("' + email_col + '") LIKE :pattern'), {"pattern": "%@" + d}).scalar_one() for d in DOMAINS}
            where, params = "", {"limit": limit}
            if domain:
                d = domain.lower().lstrip("@")
                if d not in DOMAINS:
                    raise HTTPException(400, "Unsupported domain")
                where = ' WHERE LOWER("' + email_col + '") LIKE :pattern'
                params["pattern"] = "%@" + d
            rows = conn.execute(text('SELECT * FROM "' + table + '"' + where + ' LIMIT :limit'), params).mappings().all()
        items = []
        for row in rows:
            item = dict(row)
            item["email_domain"] = classify(str(item.get(email_col) or ""))
            items.append(item)
        return {"items": items, "total": int(total), "returned": len(items), "domain_counts": {"@" + d: int(counts[d]) for d in DOMAINS}, "source": "database"}
    except SQLAlchemyError as exc:
        raise HTTPException(503, "Inventory database error: " + type(exc).__name__)

@app.get("/api/admin/nodes")
async def nodes(request: Request):
    payload = await upstream("/nodes", auth_token(request))
    items = extract_items(payload, ("items", "nodes", "results", "data", "records"))
    for item in items:
        protocol = str(item.get("protocol") or item.get("type") or item.get("proto") or "").lower()
        item["protocol_display"] = {"tg": "MTProto", "mtproto": "MTProto", "hy2": "Hysteria2", "hysteria2": "Hysteria2"}.get(protocol, protocol.upper() or "未知")
    return {"nodes": items, "total": len(items)}

@app.get("/api/admin/ip-lookup")
async def ip_lookup(request: Request, ip: str = Query(..., min_length=3, max_length=45)):
    auth_token(request)
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    if not address.is_global:
        raise HTTPException(400, "Only public IP addresses are allowed")
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.get("http://ip-api.com/json/" + str(address), params={"fields": "status,message,country,regionName,city,isp,org,lat,lon,query"})
            data = response.json()
        except (httpx.HTTPError, ValueError):
            raise HTTPException(502, "IP geolocation provider unavailable")
    if data.get("status") != "success":
        raise HTTPException(502, data.get("message", "IP lookup failed"))
    return {key: data.get(key) for key in ("query", "country", "regionName", "city", "isp", "org", "lat", "lon")}

@app.get("/api/admin/bots")
async def bots(request: Request):
    token = auth_token(request)
    source = {}
    if BOTS_STATUS_URL:
        async with httpx.AsyncClient(timeout=8) as client:
            try:
                response = await client.get(BOTS_STATUS_URL, headers={"Authorization": "Bearer " + token})
                if response.status_code == 401:
                    raise HTTPException(401, "Bot status source rejected authentication")
                if response.is_success:
                    source = response.json()
            except httpx.HTTPError:
                source = {}
    raw = source.get("bots", {}) if isinstance(source, dict) else {}
    result = []
    for name in BOT_NAMES:
        item = raw.get(name, {}) if isinstance(raw, dict) else {}
        result.append({"name": name, "status": item.get("status", "unknown"), "status_label": item.get("status_label", "未知 / 未接入真实状态源"), "today_checkins": item.get("today_checkins"), "today_orders": item.get("today_orders")})
    return {"bots": result, "data_source": "configured" if BOTS_STATUS_URL and source else "placeholder"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8001")))
