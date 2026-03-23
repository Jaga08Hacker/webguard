import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def map_cve(shodan_data: dict, nvd_key: str = "") -> list:
    cves = []

    # First, get CVEs already identified by Shodan
    for vuln in shodan_data.get("vulnerabilities", []):
        cves.append({
            "cve_id": vuln.get("cve", ""),
            "cvss_score": vuln.get("cvss", "N/A"),
            "description": vuln.get("summary", ""),
            "source": "Shodan",
            "severity": cvss_to_severity(vuln.get("cvss", 0))
        })

    # Then look up CVEs for each detected service via NVD
    services = shodan_data.get("services", [])
    for svc in services:
        product = svc.get("service", "")
        version = svc.get("version", "")
        if not product or product in ("Unknown", ""):
            continue

        keyword = f"{product} {version}".strip()
        try:
            headers = {}
            if nvd_key:
                headers["apiKey"] = nvd_key

            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 3,
                "startIndex": 0
            }
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=12)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")

                    # Avoid duplicates
                    if any(c["cve_id"] == cve_id for c in cves):
                        continue

                    desc_list = cve.get("descriptions", [])
                    desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "")

                    metrics = cve.get("metrics", {})
                    cvss_score = "N/A"
                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        m = metrics.get(key, [])
                        if m:
                            cvss_score = m[0].get("cvssData", {}).get("baseScore", "N/A")
                            break

                    cves.append({
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "description": desc[:300],
                        "affected_product": keyword,
                        "source": "NVD",
                        "severity": cvss_to_severity(cvss_score)
                    })
        except Exception as e:
            print(f"[CVE] Error for '{keyword}': {e}")

    return cves

def cvss_to_severity(score) -> str:
    try:
        s = float(score)
        if s >= 9.0:
            return "CRITICAL"
        elif s >= 7.0:
            return "HIGH"
        elif s >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    except Exception:
        return "UNKNOWN"
