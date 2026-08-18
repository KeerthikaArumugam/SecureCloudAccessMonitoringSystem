import urllib.request
import urllib.parse
import http.cookiejar


def main():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base = "http://127.0.0.1:5000"

    data = urllib.parse.urlencode({"username": "admin", "password": "admin123"}).encode()
    resp = opener.open(base + "/login", data, timeout=8)
    final_url = resp.url.replace(base, "")
    print(f"POST /login -> redirected to: {final_url}")
    print()

    protected = [
        "/dashboard",
        "/admin",
        "/threat-detection",
        "/ai-prediction",
        "/security-alerts",
        "/login-activity",
        "/analytics",
        "/audit-logs",
        "/model-performance",
        "/profile",
        "/settings",
    ]

    all_ok = True
    for r in protected:
        try:
            resp = opener.open(base + r, timeout=10)
            landed = resp.url.replace(base, "") or r
            status = "OK" if resp.status == 200 else f"STATUS={resp.status}"
            print(f"  {r:35s} -> {status}  (landed: {landed})")
        except Exception as e:
            print(f"  {r:35s} -> ERROR: {e}")
            all_ok = False

    print()
    print("All routes OK!" if all_ok else "Some routes had errors.")


if __name__ == "__main__":
    main()
