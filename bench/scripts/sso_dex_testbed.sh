#!/usr/bin/env bash
# Single sign-on on the AWS testbed's gateway host: Dex (ghcr.io/dexidp/dex:v2.43.1) on the host's
# private IP, port 8003 (the testbed security group admits 8000-8003 inside the VPC), and the
# compose stack's CALIBAN_OIDC_* settings. Run as root on the gateway, then sso_e2e.py and
# ui_login.py from the loadgen. Testbed only: plain http, an in-memory Dex.
#
# Dex connectors: `mock` (mockCallback: "Kilgore Trout", group "authors", mapped to owner) and the
# password DB with viewer@example.com / password (no groups; sso_e2e.py grants it viewer).
set -euo pipefail
. /etc/profile.d/caliban-testbed.sh
ISSUER="http://$GATEWAY_IP:8003/dex"
mkdir -p /opt/tb-dex
SECRET=$(openssl rand -hex 16)
HASH=$(docker run --rm httpd:2.4-alpine htpasswd -nbBC 10 viewer password | cut -d: -f2 | sed 's/^\$2y\$/$2a$/')
cat > /opt/tb-dex/dex.yaml <<DEX
issuer: $ISSUER
storage: { type: memory }
web: { http: 0.0.0.0:5556 }
oauth2: { skipApprovalScreen: true }
enablePasswordDB: true
staticPasswords:
  - email: viewer@example.com
    hash: "$HASH"
    username: viewer
    userID: 08a8684b-db88-4b73-90a9-3cd1661f5466
staticClients:
  - id: caliban-console
    name: Caliban
    secret: $SECRET
    redirectURIs: ["http://$GATEWAY_IP:8081/auth/callback"]
connectors:
  - { type: mockCallback, id: mock, name: Mock }
DEX
chmod 644 /opt/tb-dex/dex.yaml
docker rm -f tb-dex >/dev/null 2>&1 || true
docker run -d --name tb-dex --restart unless-stopped -p "$GATEWAY_IP:8003:5556" \
  -v /opt/tb-dex/dex.yaml:/etc/dex/config.yaml:ro ghcr.io/dexidp/dex:v2.43.1 dex serve /etc/dex/config.yaml >/dev/null
for _ in $(seq 1 30); do curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null && break; sleep 1; done

ENV=$CALIBAN_DEPLOY_DIR/compose/.env
setv() { if grep -q "^$1=" "$ENV"; then sed -i "s|^$1=.*|$1=$2|" "$ENV"; else echo "$1=$2" >> "$ENV"; fi; }
setv CALIBAN_OIDC_ISSUER "$ISSUER"
setv CALIBAN_OIDC_CLIENT_ID caliban-console
setv CALIBAN_OIDC_CLIENT_SECRET "$SECRET"
setv CALIBAN_OIDC_REDIRECT_URL "http://$GATEWAY_IP:8081/auth/callback"
setv CALIBAN_OIDC_SCOPES "openid,profile,email,groups"
setv CALIBAN_OIDC_OWNER_GROUPS authors
cd "$CALIBAN_DEPLOY_DIR/compose"
docker compose -f docker-compose.yml -f /opt/caliban-testbed/compose.testbed-gateway.yml up -d --force-recreate --wait caliban
curl -s localhost:8081/auth/config; echo
