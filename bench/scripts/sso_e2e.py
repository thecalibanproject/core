#!/usr/bin/env python3
"""Single sign-on end to end against a real Dex (stdlib only, Python 3.9+).

Dex runs with two connectors: `mock` (mockCallback: "Kilgore Trout", group "authors", mapped to
owner with CALIBAN_OIDC_OWNER_GROUPS=authors) and the password DB (viewer@example.com, no groups).

  sso_e2e.py --cp http://$GATEWAY_IP:8081 --admin BREAK_GLASS_TOKEN --viewer viewer@example.com --password password

Checks: login through the IdP ends with a session; /auth/me roles; a write needs the CSRF token;
the owner grants the second user `viewer` on one tenant through the role-binding API; the viewer
reads that tenant (200) and is refused writes (403) and the audit log (403); logout ends both
sessions (401 after); the audit log names both users, records login, logout, role_binding.create
and break-glass use, and its hash chain verifies.
"""
import argparse, time, html, http.cookiejar, json, re, sys, urllib.error, urllib.parse, urllib.request

results = []


def check(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + (f": {detail}" if detail else ""), file=sys.stderr)


class NoErr(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        if 300 <= response.status < 400:  # let the redirect handler follow it
            return super().http_response(request, response)
        return response
    https_response = http_response


def session():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoErr())
    return op, jar


def req(op, method, url, body=None, headers=None, form=None):
    h = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = op.open(urllib.request.Request(url, data=data, headers=h, method=method), timeout=30)
    raw = r.read().decode(errors="replace")
    try:
        j = json.loads(raw)
    except ValueError:
        j = raw
    return r.status, j, r.geturl()


def login(op, cp, connector, user=None, password=None):
    # Caliban -> Dex /auth (connector list, since Dex has two) -> connector -> Caliban callback.
    s, page, url = req(op, "GET", f"{cp}/auth/login?return_to=%2Fapi%2Fv1%2Fhealth")
    if isinstance(page, str) and "/dex/auth" in url:
        links = [html.unescape(m) for m in re.findall(r'href="([^"]*/auth/[^"]*)"', page)]
        pick = [l for l in links if f"/auth/{connector}" in l]
        if not pick:
            raise RuntimeError(f"no {connector} connector link on {url}: {links}")
        target = urllib.parse.urljoin(url, pick[0])
        s, page, url = req(op, "GET", target)
    if connector == "local":
        m = re.search(r'<form[^>]*action="([^"]*)"', page) if isinstance(page, str) else None
        action = urllib.parse.urljoin(url, html.unescape(m.group(1))) if m else url
        s, page, url = req(op, "POST", action, form={"login": user, "password": password})
    return s, url


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp", required=True)
    ap.add_argument("--admin", required=True)
    ap.add_argument("--viewer", default="viewer@example.com")
    ap.add_argument("--password", default="password")
    ap.add_argument("--out")
    a = ap.parse_args()
    cp = a.cp.rstrip("/")
    bg = {"Authorization": f"Bearer {a.admin}"}

    s, cfg, _ = req(urllib.request.build_opener(NoErr()), "GET", f"{cp}/auth/config")
    check("GET /auth/config reports SSO on", s == 200 and cfg.get("sso_enabled") is True, json.dumps(cfg))

    # Owner through the mock connector (group "authors" -> owner).
    own, _ = session()
    s, url = login(own, cp, "mock")
    s, me, _ = req(own, "GET", f"{cp}/auth/me")
    check("owner login ends in a session", s == 200 and me.get("method") == "session", f"{s} {str(me)[:200]}")
    check("owner role from the group mapping", me.get("roles") == [{"role": "owner"}], json.dumps(me.get("roles")))
    csrf = me.get("csrf_token") or ""
    s, _, _ = req(own, "POST", f"{cp}/api/v1/tenants", {"name": "sso-no-csrf"})
    check("write without X-CSRF-Token refused", s == 403, str(s))
    s, t, _ = req(own, "POST", f"{cp}/api/v1/tenants", {"name": f"sso-tenant-{int(time.time())}"}, {"X-CSRF-Token": csrf})
    check("write with X-CSRF-Token accepted", s == 201, f"{s} {str(t)[:120]}")
    tid = t.get("id") if isinstance(t, dict) else None
    s, _, _ = req(own, "POST", f"{cp}/api/v1/tenants", {"name": "sso-bad-origin"}, {"X-CSRF-Token": csrf, "Origin": "http://evil.example"})
    check("write from a foreign Origin refused", s == 403, str(s))

    # Viewer through the password connector: no groups, so no role until bound.
    vw, _ = session()
    s, url = login(vw, cp, "local", a.viewer, a.password)
    s, vme, _ = req(vw, "GET", f"{cp}/auth/me")
    check("viewer login ends in a session", s == 200 and vme.get("method") == "session", f"{s} {str(vme)[:200]}")
    check("viewer has no role before a binding", vme.get("roles") == [], json.dumps(vme.get("roles")))
    vid = (vme.get("user") or {}).get("id")
    s, _, _ = req(vw, "GET", f"{cp}/api/v1/tenants/{tid}/routes")
    check("viewer without a role refused a tenant read", s == 403, str(s))
    s, b, _ = req(own, "POST", f"{cp}/api/v1/role-bindings", {"subject_kind": "user", "subject": vid, "role": "viewer", "tenant_id": tid}, {"X-CSRF-Token": csrf})
    check("owner binds viewer on the tenant (role-binding API)", s in (200, 201), f"{s} {str(b)[:160]}")
    s, vme, _ = req(vw, "GET", f"{cp}/auth/me")
    check("viewer role takes effect on the next request", any(r.get("role") == "viewer" for r in vme.get("roles", [])), json.dumps(vme.get("roles")))
    vcsrf = vme.get("csrf_token") or ""
    s, _, _ = req(vw, "GET", f"{cp}/api/v1/tenants/{tid}/routes")
    check("viewer reads the tenant's routes", s == 200, str(s))
    s, _, _ = req(vw, "PUT", f"{cp}/api/v1/tenants/{tid}/routes", {"routes": [{"intent": "default", "models": ["local/qwen3.8-27b"]}]}, {"X-CSRF-Token": vcsrf})
    check("viewer refused a write (PUT routes, with CSRF)", s == 403, str(s))
    s, _, _ = req(vw, "POST", f"{cp}/api/v1/tenants/{tid}/api-keys", {"name": "x"}, {"X-CSRF-Token": vcsrf})
    check("viewer refused minting an API key", s == 403, str(s))
    s, _, _ = req(vw, "GET", f"{cp}/api/v1/audit?limit=1")
    check("viewer refused the audit log", s == 403, str(s))
    s, _, _ = req(vw, "GET", f"{cp}/api/v1/tenants/default/routes")
    check("viewer refused another tenant", s == 403, str(s))

    for name, op, c in (("viewer", vw, vcsrf), ("owner", own, csrf)):
        s, lo, _ = req(op, "POST", f"{cp}/auth/logout", None, {"X-CSRF-Token": c})
        check(f"{name} logout", s == 200, f"{s} {str(lo)[:120]}")
        s, _, _ = req(op, "GET", f"{cp}/auth/me")
        check(f"{name} session gone after logout", s == 401, str(s))

    s, au, _ = req(urllib.request.build_opener(NoErr()), "GET", f"{cp}/api/v1/audit?limit=60", None, bg)
    entries = au.get("entries", []) if isinstance(au, dict) else []
    acts = [(e["action"], e["actor"]) for e in entries]
    check("audit chain verifies", isinstance(au, dict) and au.get("chain_verified") is True)
    check("audit: break-glass use recorded", any(x == "auth.break_glass" for x, _ in acts))
    logins = {actor for x, actor in acts if x == "auth.login"}
    check("audit: both users' logins", len(logins) >= 2, "; ".join(sorted(logins))[:300])
    check("audit: logouts", sum(1 for x, _ in acts if x == "auth.logout") >= 2)
    check("audit: role_binding.create by the owner", any(x == "role_binding.create" and "kilgore" in actor for x, actor in acts))
    check("audit: tenant.create attributed to the SSO user", any(x == "tenant.create" and "kilgore" in actor for x, actor in acts))
    passed = sum(r["ok"] for r in results)
    print(f"{passed}/{len(results)} checks passed", file=sys.stderr)
    if a.out:
        json.dump({"results": results, "audit_actions": acts[:40]}, open(a.out, "w"), indent=1)
    sys.exit(0 if passed == len(results) else 1)


main()
