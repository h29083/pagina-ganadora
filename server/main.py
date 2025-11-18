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
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

import stripe
import json
import requests

DB_PATH = os.environ.get("FORM_AUDITOR_DB", "form_auditor.sqlite3")
STRIPE_SECRET = os.environ.get("STRIPE_SECRET", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")  # Price for $5 plan
SUCCESS_URL = os.environ.get("SUCCESS_URL", "http://localhost:5173/success?session_id={CHECKOUT_SESSION_ID}")
CANCEL_URL = os.environ.get("CANCEL_URL", "http://localhost:5173/cancel")
ADMIN_TOKEN = os.environ.get("FORM_AUDITOR_ADMIN_TOKEN", "")

# Coinbase Commerce (Crypto payments)
COINBASE_COMMERCE_API_KEY = os.environ.get("COINBASE_COMMERCE_API_KEY", "")
COINBASE_COMMERCE_WEBHOOK_SECRET = os.environ.get("COINBASE_COMMERCE_WEBHOOK_SECRET", "")
CRYPTO_PRICE_USD = float(os.environ.get("CRYPTO_PRICE_USD", "5"))
CRYPTO_SUCCESS_URL = os.environ.get("CRYPTO_SUCCESS_URL", "http://localhost:8000/static/success.html")
COINBASE_COMMERCE_VERSION = "2018-03-22"

# BTCPay (self-hosted payments, no external API keys needed from your app)
BTCPAY_BUTTON_URL = os.environ.get("BTCPAY_BUTTON_URL", "")
BTCPAY_WEBHOOK_SECRET = os.environ.get("BTCPAY_WEBHOOK_SECRET", "")

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
            created_at TEXT,
            purchases INTEGER DEFAULT 0
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key)")
    # Migration: ensure purchases column exists
    try:
        conn.execute("ALTER TABLE users ADD COLUMN purchases INTEGER DEFAULT 0")
        conn.commit()
    except Exception:
        pass
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
            conn.execute("UPDATE users SET credits = credits + ?, purchases = purchases + 1 WHERE id=?", (add_credits, row[0]))
            conn.commit()
            return row[1]
    conn.execute(
        "INSERT INTO users(email, api_key, credits, created_at, purchases) VALUES (?,?,?,?,?)",
        (email, api_key, add_credits, now, 1 if add_credits > 0 else 0),
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


@app.get("/api/key-by-email")
async def key_by_email(email: Optional[str] = None):
    if not email:
        raise HTTPException(status_code=400, detail="Email requerido")
    with db() as conn:
        cur = conn.execute("SELECT api_key, credits, purchases FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if row:
            return {"api_key": row[0], "remaining": int(row[1]), "purchases": int(row[2] or 0), "email": email}
        # Crear cuenta sin créditos si no existe
        api_key = upsert_user_add_credits(conn, email, 0)
        # Newly created with zero credits implies purchases=0
        return {"api_key": api_key, "remaining": 0, "purchases": 0, "email": email}


@app.get("/api/user-info")
async def user_info(email: Optional[str] = None):
    if not email:
        raise HTTPException(status_code=400, detail="Email requerido")
    with db() as conn:
        cur = conn.execute("SELECT api_key, credits, purchases FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if not row:
            return {"email": email, "api_key": None, "remaining": 0, "purchases": 0}
        return {"email": email, "api_key": row[0], "remaining": int(row[1]), "purchases": int(row[2] or 0)}


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


@app.get("/btcpay/redirect")
async def btcpay_redirect(request: Request, email: Optional[str] = None):
    if not BTCPAY_BUTTON_URL:
        raise HTTPException(status_code=500, detail="BTCPay no configurado (BTCPAY_BUTTON_URL)")
    if not email:
        raise HTTPException(status_code=400, detail="Email requerido para comprar")
    # Regla: si el usuario ya tiene créditos > 0, no permitir nueva compra aún
    with db() as conn:
        cur = conn.execute("SELECT credits FROM users WHERE email=?", (email,))
        r = cur.fetchone()
        if r and int(r[0]) > 0:
            raise HTTPException(status_code=403, detail="Aún tienes créditos activos. Agota tus 200 envíos antes de volver a comprar.")
    # Redirecciona al Pay Button agregando buyerEmail y redirect URL para auto redirigir tras el pago
    base = str(request.base_url).rstrip('/')
    postpay = f"{base}/static/postpay.html?email={email}"
    joiner = "&" if ("?" in BTCPAY_BUTTON_URL) else "?"
    target = (
        f"{BTCPAY_BUTTON_URL}{joiner}buyerEmail={email}"
        f"&redirectAutomatically=true&redirectURL={postpay}"
    )
    return JSONResponse({"url": target})


@app.post("/btcpay/webhook")
async def btcpay_webhook(request: Request):
    raw = await request.body()
    sig_header = request.headers.get("BTCPAY-SIG", "")
    # Expected format: "sha256=<hex>"
    expected = None
    if BTCPAY_WEBHOOK_SECRET:
        digest = hmac.new(BTCPAY_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
        expected = f"sha256={digest}"
        if not hmac.compare_digest(sig_header, expected):
            raise HTTPException(status_code=400, detail="Firma BTCPay inválida")

    evt = await request.json()
    evt_type = evt.get("type") or (evt.get("event") or {}).get("type")
    data = evt.get("invoice") or (evt.get("event") or {}).get("data") or {}
    # buyerEmail puede venir en "metadata" o en el objeto buyer
    meta = data.get("metadata") or {}
    email = meta.get("buyerEmail") or meta.get("orderId") or (data.get("buyer") or {}).get("email")

    if evt_type in ("InvoiceSettled", "InvoiceProcessing", "invoice_settled", "invoice_processing"):
        if email:
            with db() as conn:
                upsert_user_add_credits(conn, email, 200)
    return {"received": True}


@app.get("/download/client")
async def download_client(email: Optional[str] = None):
    """Build a zip containing BOTi.py and an instructions file.
    If email is provided and exists, embed the API key into instructions for convenience.
    """
    import io, zipfile
    api_key = None
    with db() as conn:
        if email:
            cur = conn.execute("SELECT api_key FROM users WHERE email=?", (email,))
            r = cur.fetchone()
            if r:
                api_key = r[0]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        # Include BOTi.py
        try:
            with open("BOTi.py", "rb") as f:
                z.writestr("BOTi.py", f.read())
        except Exception:
            pass
        # Include README/instructions
        api_base = os.environ.get("API_BASE_URL", "https://pagina-ae85284c66a5.herokuapp.com")
        instructions = f"""
Form Auditor - Cliente

1) Requisitos: Python 3.10+
2) Ejecuta:
   python BOTi.py --api-url {api_base} --api-key {api_key or '<TU_API_KEY>'} --times 5 --interval 3 https://tusitio.com/form

Para ver tus créditos:
   curl -H "Authorization: Bearer {api_key or '<TU_API_KEY>'}" {api_base}/api/credits

Para recuperar tu API Key por email:
   {api_base}/api/key-by-email?email={email or '<tu_correo>'}
""".strip()
        z.writestr("LEEME.txt", instructions)
    buf.seek(0)
    headers = {
        "Content-Disposition": "attachment; filename=form_auditor_cliente.zip"
    }
    return StreamingResponse(buf, media_type="application/zip", headers=headers)


class CryptoCheckoutBody(BaseModel):
    email: Optional[str] = None


@app.post("/crypto/checkout")
async def crypto_checkout(body: CryptoCheckoutBody):
    if not COINBASE_COMMERCE_API_KEY:
        raise HTTPException(status_code=500, detail="Coinbase Commerce no configurado")
    try:
        headers = {
            "X-CC-Api-Key": COINBASE_COMMERCE_API_KEY,
            "X-CC-Version": COINBASE_COMMERCE_VERSION,
            "Content-Type": "application/json",
        }
        payload = {
            "name": "Form Auditor 200 envíos",
            "description": "Plan único: 200 envíos",
            "pricing_type": "fixed_price",
            "local_price": {"amount": str(CRYPTO_PRICE_USD), "currency": "USD"},
            "redirect_url": CRYPTO_SUCCESS_URL,
            "cancel_url": CANCEL_URL,
            "metadata": {"plan": "basic_5usd_200", "email": body.email},
        }
        r = requests.post("https://api.commerce.coinbase.com/charges", headers=headers, data=json.dumps(payload), timeout=20)
        r.raise_for_status()
        data = r.json()
        hosted_url = data.get("data", {}).get("hosted_url")
        charge_id = data.get("data", {}).get("id")
        if not hosted_url:
            raise HTTPException(status_code=400, detail="No se pudo crear el pago")
        return {"url": hosted_url, "id": charge_id}
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/crypto/webhook")
async def crypto_webhook(request: Request):
    body = await request.body()
    sig = request.headers.get("X-CC-Webhook-Signature", "")
    secret = COINBASE_COMMERCE_WEBHOOK_SECRET
    if secret:
        digest = hmac.new(key=secret.encode(), msg=body, digestmod=hashlib.sha256).hexdigest()
        if not hmac.compare_digest(digest, sig):
            raise HTTPException(status_code=400, detail="Firma inválida")
    event = await request.json()
    event_type = event.get("event", {}).get("type") or event.get("type")
    data = (event.get("event") or {}).get("data") or event.get("data", {})
    if event_type in ("charge:confirmed", "charge:resolved"):
        email = (data.get("metadata") or {}).get("email")
        if email:
            with db() as conn:
                upsert_user_add_credits(conn, email, 200)
    return {"received": True}
