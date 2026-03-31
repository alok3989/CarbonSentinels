import os
import json
import jwt
import redis.asyncio as redis
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from secure import Secure, StrictTransportSecurity, XFrameOptions, XXSSProtection
from pydantic import BaseModel, model_validator, ConfigDict
from typing import Dict, Any

app = FastAPI(title="CarbonSentinel Enterprise Core API", version="2.0.0")

# 1. Security Headers configured directly in middleware below

@app.middleware("http")
async def secure_middleware(request: Request, call_next):
    # A. Enforce Request Size Limit (2KB) to prevent JSON Bombs
    content_length = request.headers.get('content-length')
    if content_length and int(content_length) > 2048:
        return JSONResponse(status_code=413, content={"detail": "Payload Too Large. Limited to 2KB."})

    # Execute request
    response = await call_next(request)
    
    # B. Inject secure headers permanently
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# 2. CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("ALLOWED_ORIGIN", "https://carbonsentinel.com")],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# 3. Redis Connectivity (Also handles IP Bans and Rate Limits)
redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

async def rate_limit_and_ban_check(request: Request):
    client_ip = request.client.host
    try:
        # Check if permanently banned by honeypot
        is_banned = await redis_client.get(f"banned:{client_ip}")
        if is_banned:
            raise HTTPException(status_code=403, detail="Your IP is permanently banned.")

        # Rate limit check (100 req/min)
        current_count = await redis_client.incr(client_ip)
        if current_count == 1:
            await redis_client.expire(client_ip, 60)
        if current_count > 100:
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Zero-trust lockout initiated.")
    except redis.ConnectionError:
        pass # Bypass gracefully if redis offline in local dev

# 4. JWT Authentication Guard
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-signature-key-replace-in-production")
ALGORITHM = "HS256" # For enterprise, upgrade to RS256 with KMS

async def verify_jwt(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
        
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        request.state.corporate_id = payload.get("corporate_id")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")

# 5. Strict Lexical Analyzer & Deep Validation Payload Schema
class TransactionPayload(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True) # Fails if extra rogue JSON fields present
    
    corporate_id: str
    asset_id: str
    volume_tons: float
    zk_proof_data: Dict[str, Any]

    @model_validator(mode='before')
    @classmethod
    def prevent_pollution(cls, values):
        """
        Deep parsing validator to reject NoSQL/$where injections
        and Prototype pollution attempts.
        """
        raw_string = json.dumps(values)
        banned_phrases = ["$where", "__proto__", "$regex"]
        for phrase in banned_phrases:
            if phrase in raw_string:
                raise ValueError(f"Lexical Violation: Malicious structural keyword '{phrase}' detected.")
        return values

# 6. Honeypot Endpoint (Triggers permanent IP Ban)
@app.get("/api/v1/debug")
async def honeypot(request: Request):
    client_ip = request.client.host
    try:
        # Ban the IP indefinitely (handled manually or expires in 30 days)
        await redis_client.set(f"banned:{client_ip}", "1", ex=2592000)
    except:
        pass
    raise HTTPException(status_code=403, detail="Honeypot triggered. IP permanently blacklisted.")
