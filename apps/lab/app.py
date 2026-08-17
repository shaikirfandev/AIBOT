"""Intentionally Vulnerable Lab Application for end-to-end testing.

WARNING: This is a DELIBERATELY INSECURE application used ONLY for local testing.
It contains synthetic vulnerabilities (XSS, IDOR, open redirect, CORS misconfig, etc.)
for the Bug Bounty Platform to discover and validate during end-to-end tests.

NEVER deploy this to any public-facing or production environment.
All vulnerabilities below are intentional test targets.
"""
from __future__ import annotations

from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Vulnerable Lab", version="0.1.0")

# Simulated database
USERS = {
    "1": {"id": "1", "name": "admin", "email": "admin@lab.local", "role": "admin", "ssn": "123-45-6789"},
    "2": {"id": "2", "name": "user", "email": "user@lab.local", "role": "user", "ssn": "987-65-4321"},
}

POSTS = {
    "1": {"id": "1", "title": "Public Post", "author_id": "1", "content": "Hello", "private": False},
    "2": {"id": "2", "title": "Private Post", "author_id": "1", "content": "Secret", "private": True},
}


@app.get("/")
async def index():
    return HTMLResponse("<h1>Vulnerable Lab</h1><p>For testing only.</p>")


# IDOR: No authorization check on user data
@app.get("/api/users/{user_id}")
async def get_user(user_id: str):
    user = USERS.get(user_id)
    if not user:
        return JSONResponse({"error": "Not found"}, 404)
    # Excessive data exposure: returns SSN
    return user


# Missing auth: admin endpoint without authentication
@app.get("/api/admin/users")
async def admin_list_users():
    return list(USERS.values())


# Reflected XSS: echoes user input
@app.get("/search")
async def search(q: str = Query("")):
    return HTMLResponse(f"<h1>Results for: {q}</h1><p>No results found.</p>")


# Missing rate limiting on login
@app.post("/api/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    if username == "admin" and password == "admin123":
        return {"token": "fake-jwt-token-for-testing"}
    return JSONResponse({"error": "Invalid credentials"}, 401)


# CORS misconfiguration
@app.get("/api/data")
async def get_data(request: Request):
    response = JSONResponse({"data": "sensitive"})
    origin = request.headers.get("origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


# Missing security headers
@app.get("/api/profile")
async def profile():
    return {"name": "test", "email": "test@lab.local"}


# Information disclosure via error
@app.get("/api/debug")
async def debug():
    import sys
    return {
        "python_version": sys.version,
        "platform": sys.platform,
        "paths": sys.path[:3],
    }


# Open redirect
@app.get("/redirect")
async def redirect_to(url: str = Query("")):
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8888)
