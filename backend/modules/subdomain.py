import requests
import dns.resolver
import ssl, socket
import json

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

def find_subdomains(domain: str) -> list:
    subdomains = set()

    # Method 1: crt.sh (Certificate Transparency Logs)
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if domain in sub:
                        subdomains.add(sub)
    except Exception as e:
        print(f"[crt.sh] Error: {e}")

    # Method 2: HackerTarget
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if domain in sub:
                        subdomains.add(sub)
    except Exception as e:
        print(f"[HackerTarget] Error: {e}")

    # Method 3: DNS brute-force (common prefixes)
    common_prefixes = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "blog", "shop", "portal", "vpn", "remote", "ns1", "ns2", "smtp",
        "pop", "imap", "webmail", "cpanel", "login", "secure", "cdn",
        "static", "media", "images", "assets", "support", "help", "docs",
        "git", "gitlab", "jenkins", "jira", "confluence", "monitor", "db",
        "mysql", "sql", "backup", "files", "s3", "storage", "cloud"
    ]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    for prefix in common_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            resolver.resolve(subdomain, "A")
            subdomains.add(subdomain)
        except Exception:
            pass

    result = []
    for sub in subdomains:
        entry = {"subdomain": sub, "ip": None, "status": "unknown"}
        try:
            ip = socket.gethostbyname(sub)
            entry["ip"] = ip
            entry["status"] = "active"
        except Exception:
            entry["status"] = "inactive"
        result.append(entry)

    return result
