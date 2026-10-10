"""Console sign-in through Dex in headless Chromium (Playwright). Testbed scenario 4.

  docker run --rm --network host -v "$PWD":/w mcr.microsoft.com/playwright/python:v1.52.0-noble \
    bash -c "pip install -q playwright==1.52.0 && python /w/ui_login.py http://$GATEWAY_IP:8081 /w/out"

(the image ships the browsers; the Python package is installed at run time)
"""
import json, sys
from playwright.sync_api import sync_playwright

base, out = sys.argv[1].rstrip("/"), sys.argv[2]
steps = []
with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.goto(base + "/")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=f"{out}/ui-1-login.png")
    page.get_by_text("Sign in with SSO").first.click()
    page.wait_for_url("**/dex/**")
    steps.append(["dex page", page.url.split("?")[0]])
    page.get_by_text("Mock", exact=False).first.click()
    page.wait_for_url(base + "/**", timeout=30000)
    page.wait_for_load_state("networkidle")
    steps.append(["back on console", page.url])
    page.screenshot(path=f"{out}/ui-2-signed-in.png", full_page=True)
    me = page.request.get(base + "/auth/me").json()
    steps.append(["/auth/me", {"method": me.get("method"), "user": (me.get("user") or {}).get("name"), "roles": me.get("roles")}])
    body = page.inner_text("body")
    steps.append(["user name visible in the console", "Kilgore" in body or "kilgore" in body])
    b.close()
print(json.dumps(steps, indent=1))
ok = steps[-2][1]["method"] == "session" and steps[-1][1]
sys.exit(0 if ok else 1)
