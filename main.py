import asyncio
import time
import random
import os
from datetime import datetime
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
import httpx
from contextlib import asynccontextmanager

# ──────────────────────────────────────────────
# Pydantic models for POST / GET endpoints
# ──────────────────────────────────────────────

class ProxyRequest(BaseModel):
    url: Optional[str] = None
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[Dict[str, Any]] = None
    country: Optional[str] = None  # optional country filter


class ProxyDetails(BaseModel):
    status: str
    message: str
    proxy_ip: Optional[str] = None
    proxy_port: Optional[int] = None
    proxy_user: Optional[str] = None
    proxy_pass: Optional[str] = None
    country: Optional[str] = None
    server_name: Optional[str] = None
    expires: Optional[str] = None


# ──────────────────────────────────────────────
# Global state
# ──────────────────────────────────────────────

state = {
    "anon_token": None,
    "anon_token_expiry": 0,
    "access_token": None,
    "access_token_expiry": 0,
    "proxy_credentials": [],  # List of {ip, port, user, pass, expiry, country, server_name}
    "countries_data": None,
    "last_refresh": 0,
}

HEADERS_BASE = {
    "accept": "*/*",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": "chrome-extension://eppiocemhmnlbhjplcgkofciiegomcon",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
}

REFRESH_BUFFER_MS = 5 * 60 * 1000  # 5 minutes in milliseconds


# ──────────────────────────────────────────────
# Token & credential helpers
# ──────────────────────────────────────────────

async def get_anonymous_token(client: httpx.AsyncClient) -> dict:
    """Step 1: Get anonymous registration token"""
    url = "https://api-pro.falais.com/rest/v1/registrations/clientApps/URBAN_VPN_BROWSER_EXTENSION/users/anonymous"
    payload = {"clientApp": {"name": "URBAN_VPN_BROWSER_EXTENSION", "browser": "CHROME"}}

    response = await client.post(url, json=payload, headers=HEADERS_BASE)
    response.raise_for_status()
    data = response.json()
    print(f"[{datetime.now()}] Got anonymous token: {data['value'][:20]}...")
    return data


async def get_access_token(client: httpx.AsyncClient, anon_token: str) -> dict:
    """Step 2: Get access token using anonymous token"""
    url = "https://api-pro.falais.com/rest/v1/security/tokens/accs"
    headers = {**HEADERS_BASE, "authorization": f"Bearer {anon_token}"}
    payload = {"type": "accs", "clientApp": {"name": "URBAN_VPN_BROWSER_EXTENSION"}}

    response = await client.post(url, json=payload, headers=headers)
    response.raise_for_status()
    data = response.json()
    print(f"[{datetime.now()}] Got access token, expires at: {datetime.fromtimestamp(data['expirationTime']/1000)}")
    return data


async def get_countries(client: httpx.AsyncClient, access_token: str) -> dict:
    """Step 3: Get available countries and servers"""
    url = "https://stats.falais.com/api/rest/v2/entrypoints/countries"
    headers = {
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "authorization": f"Bearer {access_token}",
        "user-agent": HEADERS_BASE["user-agent"],
        "x-client-app": "URBAN_VPN_BROWSER_EXTENSION",
    }

    response = await client.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    print(f"[{datetime.now()}] Got {len(data['countries']['elements'])} countries")
    return data


async def get_proxy_credentials(client: httpx.AsyncClient, access_token: str, signature: str) -> dict:
    """Step 4: Get proxy credentials for a specific server"""
    url = "https://api-pro.falais.com/rest/v1/security/tokens/accs-proxy"
    headers = {**HEADERS_BASE, "authorization": f"Bearer {access_token}"}
    payload = {
        "type": "accs-proxy",
        "clientApp": {"name": "URBAN_VPN_BROWSER_EXTENSION"},
        "signature": signature,
    }

    response = await client.post(url, json=payload, headers=headers)
    response.raise_for_status()
    data = response.json()
    print(f"[{datetime.now()}] Got proxy credentials, expires at: {datetime.fromtimestamp(data['expirationTime']/1000)}")
    return data


async def refresh_tokens_and_proxies():
    """Refresh all tokens and proxy credentials"""
    global state

    async with httpx.AsyncClient(timeout=30.0) as client:
        current_time = int(time.time() * 1000)

        # Step 1: Get anonymous token if needed
        if not state["anon_token"]:
            anon_data = await get_anonymous_token(client)
            state["anon_token"] = anon_data["value"]

        # Step 2: Get access token if needed or expiring soon
        if not state["access_token"] or current_time >= (state["access_token_expiry"] - REFRESH_BUFFER_MS):
            access_data = await get_access_token(client, state["anon_token"])
            state["access_token"] = access_data["value"]
            state["access_token_expiry"] = access_data["expirationTime"]

        # Step 3: Get countries data
        countries_data = await get_countries(client, state["access_token"])
        state["countries_data"] = countries_data

        # Step 4: Get proxy credentials for all servers
        new_credentials = []

        for country in countries_data["countries"]["elements"]:
            for server in country["servers"]["elements"]:
                if server.get("signature"):
                    try:
                        proxy_data = await get_proxy_credentials(
                            client,
                            state["access_token"],
                            server["signature"],
                        )

                        ip = server["address"]["primary"]["ip"]
                        port = server["address"]["primary"]["port"]
                        credential = proxy_data["value"]
                        expiry = proxy_data["expirationTime"]

                        new_credentials.append({
                            "ip": ip,
                            "port": port,
                            "user": credential,
                            "pass": credential,
                            "expiry": expiry,
                            "country": country["code"]["iso2"],
                            "server_name": server["name"],
                        })

                        # Small delay to avoid rate limiting
                        await asyncio.sleep(0.1)

                    except Exception as e:
                        print(f"[{datetime.now()}] Error getting credentials for {server['name']}: {e}")
                        continue

        state["proxy_credentials"] = new_credentials
        state["last_refresh"] = current_time
        print(f"[{datetime.now()}] Refreshed {len(new_credentials)} proxy credentials")


async def check_and_refresh():
    """Check if credentials need refresh and do so if necessary"""
    current_time = int(time.time() * 1000)

    needs_refresh = False

    if not state["proxy_credentials"]:
        needs_refresh = True
    else:
        for cred in state["proxy_credentials"]:
            if current_time >= (cred["expiry"] - REFRESH_BUFFER_MS):
                needs_refresh = True
                break

    if state["access_token_expiry"] and current_time >= (state["access_token_expiry"] - REFRESH_BUFFER_MS):
        needs_refresh = True

    if needs_refresh:
        await refresh_tokens_and_proxies()


async def background_refresh_task():
    """Background task to periodically check and refresh credentials"""
    while True:
        try:
            await check_and_refresh()
        except Exception as e:
            print(f"[{datetime.now()}] Background refresh error: {e}")
        await asyncio.sleep(60)


# ──────────────────────────────────────────────
# Helper: pick a proxy from the pool
# ──────────────────────────────────────────────

def _pick_proxy(country: Optional[str] = None) -> dict:
    """Return a random live proxy, optionally filtered by country code."""
    current_time = int(time.time() * 1000)
    pool = [
        c for c in state["proxy_credentials"]
        if c["expiry"] > current_time
        and (country is None or c["country"] == country.upper())
    ]
    if not pool:
        raise HTTPException(
            status_code=503,
            detail="No proxy credentials available" + (f" for country {country.upper()}" if country else ""),
        )
    return random.choice(pool)


# ──────────────────────────────────────────────
# App lifespan
# ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[{datetime.now()}] Starting initial credential fetch...")
    try:
        await refresh_tokens_and_proxies()
    except Exception as e:
        print(f"[{datetime.now()}] Initial fetch error: {e}")

    task = asyncio.create_task(background_refresh_task())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    lifespan=lifespan,
    title="Urban VPN Proxy Manager",
    description="Proxy credential manager with GET/POST endpoints",
    version="2.0.0",
)


# ══════════════════════════════════════════════
#  ORIGINAL TXT ENDPOINTS  (unchanged)
# ══════════════════════════════════════════════

@app.get("/", response_class=PlainTextResponse)
async def root():
    """Health check"""
    return (
        "Urban VPN Proxy Manager is running\n\n"
        "Endpoints:\n"
        "  GET  /ips.txt                  - all proxies  ip:port:user:pass\n"
        "  GET  /ips_detailed.txt         - with country & expiry\n"
        "  GET  /ips/{country_code}.txt   - filter by country\n"
        "  GET  /status                   - JSON status\n"
        "  GET  /countries                - available countries\n"
        "  POST /refresh                  - force refresh\n"
        "  GET  /proxy/details            - random proxy details (JSON)\n"
        "  POST /proxy/details            - random proxy details (JSON, optional country filter)\n"
        "  POST /proxy/request            - make a request through a proxy\n"
    )


@app.get("/ips.txt", response_class=PlainTextResponse)
async def get_ips_txt():
    """Return all proxies in ip:port:user:pass format"""
    await check_and_refresh()
    lines = [f"{c['ip']}:{c['port']}:{c['user']}:{c['pass']}" for c in state["proxy_credentials"]]
    return "\n".join(lines)


@app.get("/ips_detailed.txt", response_class=PlainTextResponse)
async def get_ips_detailed():
    """Return all proxies with country info"""
    await check_and_refresh()
    lines = []
    for c in state["proxy_credentials"]:
        exp = datetime.fromtimestamp(c["expiry"] / 1000).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"{c['country']}|{c['server_name']}|{c['ip']}:{c['port']}:{c['user']}:{c['pass']}|expires:{exp}")
    return "\n".join(lines)


@app.get("/ips/{country_code}.txt", response_class=PlainTextResponse)
async def get_ips_by_country(country_code: str):
    """Return proxies for a specific country"""
    await check_and_refresh()
    cc = country_code.upper()
    lines = [f"{c['ip']}:{c['port']}:{c['user']}:{c['pass']}" for c in state["proxy_credentials"] if c["country"] == cc]
    return "\n".join(lines)


@app.get("/status")
async def get_status():
    """Return current status"""
    current_time = int(time.time() * 1000)

    access_remaining = None
    if state["access_token_expiry"]:
        access_remaining = round(max(0, (state["access_token_expiry"] - current_time) / 1000 / 60), 2)

    min_proxy_expiry = None
    if state["proxy_credentials"]:
        min_exp = min(c["expiry"] for c in state["proxy_credentials"])
        min_proxy_expiry = round(max(0, (min_exp - current_time) / 1000 / 60), 2)

    return {
        "total_proxies": len(state["proxy_credentials"]),
        "access_token_minutes_remaining": access_remaining,
        "min_proxy_expiry_minutes": min_proxy_expiry,
        "last_refresh": datetime.fromtimestamp(state["last_refresh"] / 1000).isoformat() if state["last_refresh"] else None,
        "countries": sorted(set(c["country"] for c in state["proxy_credentials"])),
    }


@app.post("/refresh")
async def force_refresh():
    """Force a refresh of all credentials"""
    await refresh_tokens_and_proxies()
    return {"status": "refreshed", "total_proxies": len(state["proxy_credentials"])}


@app.get("/countries")
async def get_countries_list():
    """Return list of available countries"""
    await check_and_refresh()
    countries: Dict[str, int] = {}
    for c in state["proxy_credentials"]:
        countries[c["country"]] = countries.get(c["country"], 0) + 1
    return {"countries": countries}


# ══════════════════════════════════════════════
#  NEW: GET & POST PROXY ENDPOINTS
# ══════════════════════════════════════════════

@app.get("/proxy/details", response_model=ProxyDetails)
async def get_proxy_details_get(country: Optional[str] = None):
    """
    GET a random live proxy's details.

    Query params:
      - country  (optional): ISO-2 country code, e.g. US, DE, JP
    """
    await check_and_refresh()
    proxy = _pick_proxy(country)
    exp = datetime.fromtimestamp(proxy["expiry"] / 1000).strftime("%Y-%m-%d %H:%M:%S")

    return ProxyDetails(
        status="success",
        message="Proxy details retrieved successfully",
        proxy_ip=proxy["ip"],
        proxy_port=proxy["port"],
        proxy_user=proxy["user"],
        proxy_pass=proxy["pass"],
        country=proxy["country"],
        server_name=proxy["server_name"],
        expires=exp,
    )


@app.post("/proxy/details", response_model=ProxyDetails)
async def get_proxy_details_post(request: Optional[ProxyRequest] = None):
    """
    POST to get a random live proxy's details.

    Body (all optional):
      - country: ISO-2 country code filter
    """
    await check_and_refresh()
    country = request.country if request else None
    proxy = _pick_proxy(country)
    exp = datetime.fromtimestamp(proxy["expiry"] / 1000).strftime("%Y-%m-%d %H:%M:%S")

    return ProxyDetails(
        status="success",
        message="Proxy details retrieved successfully",
        proxy_ip=proxy["ip"],
        proxy_port=proxy["port"],
        proxy_user=proxy["user"],
        proxy_pass=proxy["pass"],
        country=proxy["country"],
        server_name=proxy["server_name"],
        expires=exp,
    )


@app.post("/proxy/request")
async def proxy_request_endpoint(request: ProxyRequest):
    """
    Make an HTTP request **through** a live proxy from the pool.

    Body:
      - url      (required): target URL
      - method   (optional): GET | POST  (default GET)
      - headers  (optional): extra headers dict
      - body     (optional): JSON body for POST/PUT
      - country  (optional): route through a proxy in this country
    """
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")

    await check_and_refresh()
    proxy = _pick_proxy(request.country)

    proxy_url = f"http://{proxy['user']}:{proxy['pass']}@{proxy['ip']}:{proxy['port']}"

    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=30.0,
        ) as client:
            method = (request.method or "GET").upper()

            if method == "GET":
                response = await client.get(request.url, headers=request.headers)
            elif method == "POST":
                response = await client.post(request.url, json=request.body, headers=request.headers)
            elif method == "PUT":
                response = await client.put(request.url, json=request.body, headers=request.headers)
            elif method == "DELETE":
                response = await client.delete(request.url, headers=request.headers)
            else:
                raise HTTPException(status_code=400, detail=f"Unsupported method: {method}")

        return {
            "status": "success",
            "status_code": response.status_code,
            "proxy_used": f"{proxy['ip']}:{proxy['port']}",
            "proxy_country": proxy["country"],
            "content": response.text[:2000],
        }
    except httpx.ProxyError as e:
        raise HTTPException(status_code=502, detail=f"Proxy connection failed: {str(e)}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Request timed out through proxy")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proxy request failed: {str(e)}")


# ──────────────────────────────────────────────
# Run with: uvicorn main:app --host 0.0.0.0 --port $PORT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
