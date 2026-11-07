
# Private Proxy

Cloudflare Workers + D1 + Cloudflare Access.

## Features

- Member authentication
- Admin-only service registration
- Per-member service permissions
- HTTPS API relay
- Allowed-path restrictions
- Streaming upstream responses
- Access event logging without URL storage
- GitHub Actions deployment

## Requirements

- Cloudflare account
- GitHub repository
- Cloudflare Workers
- Cloudflare D1
- Cloudflare Access

## Setup

1. Create a D1 database.
2. Update database_id in wrangler.toml.
3. Configure Access Team Domain and AUD.
4. Configure Cloudflare Access to protect the entire Worker hostname.
5. Set ADMIN_EMAILS as a Worker secret.
6. Apply the D1 migration.
7. Configure GitHub Actions secrets.
8. Push to main.

## Local development

npm install

npx wrangler d1 migrations apply private-proxy-db --local

npx wrangler secret put ADMIN_EMAILS

npm run dev

## Production migration

npx wrangler d1 migrations apply private-proxy-db --remote

## Secrets

ADMIN_EMAILS:
Comma-separated administrator email addresses.

GitHub Secrets:

CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
