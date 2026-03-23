import requests
import time
import random
from urllib.parse import quote_plus

# No API key needed - uses free public methods
DORK_QUERIES = [
    ('site:{domain} filetype:env',              'Environment files (.env)',       'CRITICAL'),
    ('site:{domain} filetype:sql',              'SQL database dumps',             'CRITICAL'),
    ('site:{domain} filetype:log',              'Log files',                      'HIGH'),
    ('site:{domain} filetype:bak',              'Backup files',                   'CRITICAL'),
    ('site:{domain} filetype:config',           'Configuration files',            'HIGH'),
    ('site:{domain} filetype:yml',              'YAML config files',              'HIGH'),
    ('site:{domain} inurl:admin',               'Admin panels',                   'HIGH'),
    ('site:{domain} inurl:login',               'Login pages',                    'MEDIUM'),
    ('site:{domain} inurl:phpinfo',             'PHPInfo pages',                  'HIGH'),
    ('site:{domain} "index of /"',              'Open directory listing',         'HIGH'),
    ('site:{domain} intext:"password" filetype:txt', 'Plaintext passwords',       'CRITICAL'),
    ('site:{domain} filetype:conf',             'Config files',                   'HIGH'),
    ('site:{domain} inurl:wp-content',          'WordPress content',              'MEDIUM'),
    ('"@{domain}" email',                       'Email addresses exposed',        'MEDIUM'),
    ('site:{domain} inurl:phpmyadmin',          'phpMyAdmin exposed',             'CRITICAL'),
    ('site:{domain} ext:php inurl:?',           'PHP pages with parameters',      'MEDIUM'),
    ('site:{domain} inurl:.git',                'Git repository exposed',         'CRITICAL'),
    ('site:{domain} "DB_PASSWORD"',             'Database credentials exposed',   'CRITICAL'),
    ('site:{domain} inurl:api/v1',              'API endpoints exposed',          'MEDIUM'),
]

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
]

def run_google_dorking(domain: str, api_key: str = "", cx: str = "") -> list:
    """
    Run Google dorking - no API key required.
    If API key + CX provided, uses Google Custom Search API (more reliable).
    Otherwise uses free DuckDuckGo scraping (always works, no key needed).
    """
    if api_key and cx:
        return _dork_via_google_api(domain, api_key, cx)
    else:
        return _dork_via_duckduckgo(domain)


def _dork_via_duckduckgo(domain: str) -> list:
    """Free dorking using DuckDuckGo HTML search - no API key needed."""
    results = []
    base_url = "https://html.duckduckgo.com/html/"

    for query_template, label, severity in DORK_QUERIES:
        query = query_template.replace("{domain}", domain)
        try:
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://duckduckgo.com/",
            }
            data = f"q={quote_plus(query)}&b=&kl="
            r = requests.post(base_url, data=data, headers=headers, timeout=12)

            if r.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "html.parser")
                links = soup.select("a.result__a")

                found_any = False
                for link in links[:5]:
                    href = link.get("href", "")
                    title = link.get_text(strip=True)
                    if domain.replace("www.", "") in href or domain.replace("www.", "") in title.lower():
                        results.append({
                            "dork_type": label,
                            "query": query,
                            "title": title,
                            "url": href,
                            "snippet": "",
                            "severity": severity,
                            "source": "DuckDuckGo"
                        })
                        found_any = True

                if not found_any and links:
                    first = links[0]
                    href = first.get("href", "")
                    if href and "duckduckgo" not in href:
                        results.append({
                            "dork_type": label,
                            "query": query,
                            "title": first.get_text(strip=True),
                            "url": href,
                            "snippet": "Potential exposure found via dork query",
                            "severity": severity,
                            "source": "DuckDuckGo"
                        })

            time.sleep(random.uniform(1.5, 3.0))

        except Exception as e:
            print(f"[DuckDuckGo Dork] Error on '{query}': {e}")
            continue

    return results


def _dork_via_google_api(domain: str, api_key: str, cx: str) -> list:
    """Premium dorking via Google Custom Search API (requires key + CX)."""
    results = []
    base_url = "https://www.googleapis.com/customsearch/v1"

    for query_template, label, severity in DORK_QUERIES:
        query = query_template.replace("{domain}", domain)
        try:
            params = {"key": api_key, "cx": cx, "q": query, "num": 5}
            r = requests.get(base_url, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("items", []):
                    results.append({
                        "dork_type": label,
                        "query": query,
                        "title": item.get("title", ""),
                        "url": item.get("link", ""),
                        "snippet": item.get("snippet", ""),
                        "severity": severity,
                        "source": "Google API"
                    })
            elif r.status_code == 429:
                print("[Google API] Rate limit hit.")
                break
        except Exception as e:
            print(f"[Google API Dork] Error: {e}")

    return results
