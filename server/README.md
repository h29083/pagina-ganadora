# Form Auditor Credits Backend (FastAPI + Stripe)

Único plan: $5 USD → 200 envíos

## 1) Requisitos
- Python 3.10+
- Stripe account (clave secreta y webhook)

## 2) Instalación local
```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r server/requirements.txt
```

## 3) Variables de entorno
Configura estas variables (en Heroku o local):
- STRIPE_SECRET: clave secreta de Stripe (sk_test_...)
- STRIPE_WEBHOOK_SECRET: secreto del webhook
- STRIPE_PRICE_ID: price del plan $5 (pago único)
- FORM_AUDITOR_DB: ruta de la BD (opcional, por defecto form_auditor.sqlite3)
- FORM_AUDITOR_ADMIN_TOKEN: token para /admin/grant (opcional)
- SUCCESS_URL, CANCEL_URL: URLs de retorno de Checkout

## 4) Ejecutar en local
```bash
uvicorn server.main:app --reload
```

Para probar webhooks en local usa Stripe CLI:
```bash
stripe listen --forward-to localhost:8000/stripe/webhook
```

## 5) Crear el Price de $5
- En Stripe Dashboard: Products → New Product → Price: One-time 5.00 USD.
- Copia el `price_xxx` y colócalo en STRIPE_PRICE_ID.

## 6) Endpoint de Checkout
POST /api/checkout
Body JSON: `{ "email": "usuario@correo.com" }` (opcional)
- Devuelve `{ id, url }` para redirigir al pago.

## 7) Créditos y uso
- GET /api/credits  (Header: Authorization: Bearer <API_KEY>)
- POST /api/use-credits  (Header + body `{ "count": N }`) → descuenta créditos.
- Tras `checkout.session.completed`, el webhook suma 200 créditos a ese email (y crea API Key si no existe).

## 8) Despliegue en Heroku
```bash
heroku create <tu-app>
heroku buildpacks:add heroku/python
heroku config:set STRIPE_SECRET=sk_test_...
heroku config:set STRIPE_WEBHOOK_SECRET=whsec_...
heroku config:set STRIPE_PRICE_ID=price_...
heroku config:set SUCCESS_URL=https://<tu-front>/success?session_id={CHECKOUT_SESSION_ID}
heroku config:set CANCEL_URL=https://<tu-front>/cancel
heroku config:set FORM_AUDITOR_ADMIN_TOKEN=supersecreto
# Deploy
git add .
git commit -m "Deploy backend"
git push heroku HEAD:main
```
Configura en Stripe el webhook a `https://<tu-app>.herokuapp.com/stripe/webhook`.

## 9) Obtener API Key manual (para pruebas)
```bash
curl -X POST https://<tu-app>.herokuapp.com/admin/grant \
  -H "Authorization: Bearer <FORM_AUDITOR_ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"email":"usuario@correo.com","credits":200}'
```

La respuesta incluye `api_key`. Úsala en el cliente:
```bash
python form_auditor.py --api-url https://<tu-app>.herokuapp.com --api-key <API_KEY> --times 10 --interval 3 https://sitio.com/form
```
