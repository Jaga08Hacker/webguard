import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

HIDDEN_PATHS = [
    # Admin & control panels
    "/admin", "/admin/login", "/administrator", "/wp-admin", "/cpanel",
    "/phpmyadmin", "/pma", "/adminer", "/webadmin", "/controlpanel",
    # Config & environment files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.yml", "/config.json", "/settings.py",
    "/wp-config.php", "/configuration.php", "/database.yml",
    # Backup files
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/site.zip", "/website.zip", "/dump.sql", "/.git/config",
    # Log & debug files
    "/error.log", "/access.log", "/debug.log", "/app.log",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    # API & docs
    "/api", "/api/v1", "/swagger", "/swagger-ui", "/api-docs",
    "/graphql", "/graphiql", "/openapi.json", "/docs",
    # Common sensitive files
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/.htpasswd",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/security.txt",
    "/.well-known/security.txt",
    # Version control
    "/.git/HEAD", "/.svn/entries", "/.hg/hgrc",
    # Server info
    "/server-status", "/server-info", "/_profiler", "/_debug",
    # CMS specific
    "/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-login.php",
    "/joomla/", "/drupal/", "/typo3/",
    # Credentials & keys
    "/id_rsa", "/id_dsa", "/.ssh/id_rsa", "/private.key",
    # Others
    "/upload", "/uploads", "/files", "/images", "/assets",
    "/include", "/includes", "/lib", "/vendor",
]

def check_path(base_url: str, path: str) -> dict | None:
    url = base_url.rstrip("/") + path
    try:
        r = requests.get(url, timeout=5, allow_redirects=False,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; WebGuard/1.0)"})
        if r.status_code in [200, 301, 302, 403]:
            severity = "LOW"
            if r.status_code == 200:
                severity = classify_path_severity(path)
            return {
                "path": path,
                "url": url,
                "status_code": r.status_code,
                "content_length": len(r.content),
                "severity": severity,
                "content_type": r.headers.get("Content-Type", "")
            }
    except Exception:
        pass
    return None

def classify_path_severity(path: str) -> str:
    critical_patterns = [".env", ".git", "config", "password", "secret", "private", "id_rsa", "wp-config", ".sql", "backup"]
    high_patterns = ["admin", "phpmyadmin", "cpanel", "phpinfo", "debug", ".htpasswd", "xmlrpc"]
    medium_patterns = ["login", "swagger", "api-docs", "graphql", "wp-admin"]

    for p in critical_patterns:
        if p in path.lower():
            return "CRITICAL"
    for p in high_patterns:
        if p in path.lower():
            return "HIGH"
    for p in medium_patterns:
        if p in path.lower():
            return "MEDIUM"
    return "LOW"

def scan_hidden_paths(domain: str) -> list:
    base_url = f"https://{domain}"
    found = []

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_path, base_url, path): path for path in HIDDEN_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    found.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return found
