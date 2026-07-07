# Nafath (IAM نفاذ) OIDC Integration

A minimal test setup for building and inspecting the **signed OIDC request**
that a Service Provider (SP) sends to the Saudi IAM/Nafath authorize endpoint.

- **backend/** — Laravel 10 API. Builds the RS256-signed JWT *request object*
  and returns the full `/authorize` URL. Also receives the callback.
- **frontend/** — Vue 3 (Vite). Simple console to build, inspect, and (once
  registered) launch the Nafath login.

## The OIDC request (per the IAM spec)

The SP redirects the user to:

```
https://www.iam.gov.sa/authservice/authorize?client_id=<sp>&request=<signed_jwt>
```

`request` is a JWT **signed with RS256** using the certificate provided by the
IAM integration team, containing:

| Claim           | Value                                   |
|-----------------|-----------------------------------------|
| `client_id`     | SP identifier (a URL)                   |
| `iss`           | same as `client_id`                     |
| `response_type` | `id_token`                              |
| `redirect_uri`  | where IAM returns the user claims       |
| `scope`         | `openid`                                |
| `nonce`         | random value                            |
| `ui_locales`    | `ar` or `en`                            |
| `max_age`       | time of issuance                        |
| `state`         | same as `nonce` (links req ↔ response)  |

## Run it

**1. Backend (port 8000)**

```bash
cd backend
php artisan serve
```

**2. Frontend (port 5173)** — in a second terminal

```bash
cd frontend
npm run dev
```

Open http://localhost:5173 and click **Build Nafath request**. The frontend
proxies `/api/*` to the Laravel backend automatically (see `frontend/vite.config.js`).

## Configuration

Edit `backend/.env`:

```
NAFATH_AUTHORIZE_URL=https://www.iam.gov.sa/authservice/authorize
NAFATH_CLIENT_ID=https://www.sp.com
NAFATH_REDIRECT_URI=http://localhost:5173/callback
NAFATH_UI_LOCALES=ar
# NAFATH_PRIVATE_KEY_PATH=/absolute/path/to/iam-private-key.pem
# NAFATH_KEY_ID=<kid from IAM, if provided>
```

### Signing key

For local testing a self-signed RSA keypair was generated at
`backend/storage/keys/private.pem` (+ `public.pem`). **Replace it** with the
private key/certificate issued by the IAM integration team and point
`NAFATH_PRIVATE_KEY_PATH` at it before going live.

Regenerate the test keypair if needed:

```bash
cd backend
openssl genrsa -out storage/keys/private.pem 2048
openssl rsa -in storage/keys/private.pem -pubout -out storage/keys/public.pem
```

## Notes / next steps

- The live **Redirect to Nafath** button only succeeds once your SP and
  certificate are registered with the IAM team and `redirect_uri` is whitelisted.
- The `/api/nafath/callback` handler currently **decodes the id_token without
  verifying** it — for display/testing only. Before production, verify the
  signature against the IAM public key (JWKS) and validate `nonce`/`state`.
