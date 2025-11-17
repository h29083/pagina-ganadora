import os
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import stripe

DB_PATH = os.environ.get("FORM_AUDITOR_DB", "form_auditor.sqlite3")
STRIPE_SECRET = os.environ.get("STRIPE_SECRET", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")  # Price for $5 plan
SUCCESS_URL = os.environ.get("SUCCESS_URL", "http://localhost:5173/success?session_id={CHECKOUT_SESSION_ID}")
CANCEL_URL = os.environ.get("CANCEL_URL", "http://localhost:5173/cancel")
ADMIN_TOKEN = os.environ.get("FORM_AUDITOR_ADMIN_TOKEN", "")

stripe.api_key = STRIPE_SECRET

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="server/static"), name="static")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            api_key TEXT UNIQUE,
            credits INTEGER DEFAULT 0,
            created_at TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key)")
    conn.commit()
    return conn


def get_user_by_api_key(conn, api_key: str):
    cur = conn.execute("SELECT id, email, api_key, credits, created_at FROM users WHERE api_key=?", (api_key,))
    row = cur.fetchone()
    return row


def upsert_user_add_credits(conn, email: Optional[str], add_credits: int) -> str:
    api_key = secrets.token_urlsafe(32)
    now = datetime.utcnow().isoformat()
    if email:
        cur = conn.execute("SELECT id, api_key FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if row:
            conn.execute("UPDATE users SET credits = credits + ? WHERE id=?", (add_credits, row[0]))
            conn.commit()
            return row[1]
    conn.execute(
        "INSERT INTO users(email, api_key, credits, created_at) VALUES (?,?,?,?)",
        (email, api_key, add_credits, now),
    )
    conn.commit()
    return api_key


class UseCreditsBody(BaseModel):
    count: int
    # optional debug email to associate session if user not known yet
    email: Optional[str] = None


@app.get("/")
async def root():
    return {"service": "form-auditor-credits", "status": "ok"}


@app.get("/api/credits")
async def get_credits(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    with db() as conn:
        row = get_user_by_api_key(conn, token)
        if not row:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return {"remaining": int(row[3])}


@app.post("/api/use-credits")
async def use_credits(body: UseCreditsBody, authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    count = max(1, int(body.count))
    with db() as conn:
        row = get_user_by_api_key(conn, token)
        if not row:
            raise HTTPException(status_code=401, detail="Invalid API key")
        credits = int(row[3])
        allowed = min(credits, count)
        if allowed > 0:
            conn.execute("UPDATE users SET credits = credits - ? WHERE api_key=?", (allowed, token))
            conn.commit()
        cur2 = conn.execute("SELECT credits FROM users WHERE api_key=?", (token,))
        remaining = int(cur2.fetchone()[0])
        return {"allowed": allowed, "remaining": remaining}


class CheckoutBody(BaseModel):
    email: Optional[str] = None


@app.post("/api/checkout")
async def api_checkout(body: CheckoutBody):
    if not STRIPE_PRICE_ID or not STRIPE_SECRET:
        raise HTTPException(status_code=500, detail="Stripe no configurado (STRIPE_PRICE_ID/STRIPE_SECRET)")
    try:
        session_obj = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            success_url=SUCCESS_URL,
            cancel_url=CANCEL_URL,
            customer_email=body.email,
            metadata={"plan": "basic_5usd_200"},
        )
        return {"id": session_obj.id, "url": session_obj.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class ClaimKeyBody(BaseModel):
    session_id: str


@app.post("/api/claim-key")
async def claim_key(body: ClaimKeyBody):
    if not STRIPE_SECRET:
        raise HTTPException(status_code=500, detail="Stripe no configurado")
    try:
        sess = stripe.checkout.Session.retrieve(body.session_id)
        if not sess or sess.get("payment_status") != "paid":
            raise HTTPException(status_code=400, detail="Sesión no pagada o inválida")
        email = (sess.get("customer_details") or {}).get("email")
        if not email:
            raise HTTPException(status_code=400, detail="No se encontró email en la sesión")
        with db() as conn:
            row = conn.execute("SELECT api_key, credits FROM users WHERE email=?", (email,)).fetchone()
            if not row:
                # Si llegó aquí sin webhook, crea usuario con 200 créditos
                api_key = upsert_user_add_credits(conn, email, 200)
                credits = 200
            else:
                api_key, credits = row[0], int(row[1])
            return {"api_key": api_key, "remaining": credits, "email": email}
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/admin/grant")
async def admin_grant(request: Request):
    auth = request.headers.get("authorization")
    if not ADMIN_TOKEN or auth != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    data = await request.json()
    email = data.get("email")
    credits = int(data.get("credits", 200))
    with db() as conn:
        api_key = upsert_user_add_credits(conn, email, credits)
        return {"api_key": api_key, "credits": credits, "email": email}


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("Stripe-Signature", "")
    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    else:
        try:
            event = stripe.Event.construct_from(request.json(), stripe.api_key)
        except Exception:
            return JSONResponse({"status": "ignored"})

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        email = session.get("customer_details", {}).get("email")
        with db() as conn:
            upsert_user_add_credits(conn, email, 200)
    return {"received": True}
