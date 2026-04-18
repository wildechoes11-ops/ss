from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import httpx
import os

app = FastAPI(
    title="Proxy API",
    description="API endpoint to get proxy details via POST request",
    version="1.0.0"
)

# Request model for POST requests
class ProxyRequest(BaseModel):
    url: Optional[str] = None
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[Dict[str, Any]] = None

# Response model for proxy details
class ProxyDetails(BaseModel):
    status: str
    message: str
    proxy_url: Optional[str] = None
    proxy_port: Optional[int] = None
    protocol: Optional[str] = None
    country: Optional[str] = None
    anonymity: Optional[str] = None

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "running",
        "message": "Proxy API is running",
        "endpoints": {
            "get_proxy_details": "POST /proxy/details",
            "health": "GET /"
        }
    }

@app.post("/proxy/details", response_model=ProxyDetails)
async def get_proxy_details(request: Optional[ProxyRequest] = None):
    """
    Get proxy details via POST request.
    
    You can optionally provide:
    - url: Target URL to test proxy with
    - method: HTTP method (GET, POST, etc.)
    - headers: Custom headers
    - body: Request body for POST/PUT requests
    """
    try:
        # Get proxy configuration from environment variables
        proxy_url = os.getenv("PROXY_URL", "http://proxy.example.com")
        proxy_port = int(os.getenv("PROXY_PORT", "8080"))
        protocol = os.getenv("PROXY_PROTOCOL", "http")
        country = os.getenv("PROXY_COUNTRY", "US")
        anonymity = os.getenv("PROXY_ANONYMITY", "elite")
        
        return ProxyDetails(
            status="success",
            message="Proxy details retrieved successfully",
            proxy_url=proxy_url,
            proxy_port=proxy_port,
            protocol=protocol,
            country=country,
            anonymity=anonymity
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving proxy details: {str(e)}"
        )

@app.post("/proxy/request")
async def proxy_request(request: ProxyRequest):
    """
    Make a request through the proxy.
    
    This endpoint demonstrates how to use the proxy to make HTTP requests.
    """
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    try:
        # Get proxy configuration
        proxy_url = os.getenv("PROXY_URL", "http://proxy.example.com")
        proxy_port = int(os.getenv("PROXY_PORT", "8080"))
        proxy_string = f"{proxy_url}:{proxy_port}"
        
        # Configure proxy for httpx
        proxies = {
            "http://": proxy_string,
            "https://": proxy_string,
        }
        
        async with httpx.AsyncClient(proxies=proxies) as client:
            if request.method.upper() == "GET":
                response = await client.get(request.url, headers=request.headers)
            elif request.method.upper() == "POST":
                response = await client.post(
                    request.url, 
                    json=request.body, 
                    headers=request.headers
                )
            else:
                raise HTTPException(status_code=400, detail=f"Unsupported method: {request.method}")
        
        return {
            "status": "success",
            "status_code": response.status_code,
            "content": response.text[:1000]  # Limit response size
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Proxy request failed: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
