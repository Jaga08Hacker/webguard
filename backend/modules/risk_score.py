def calculate_risk(data: dict) -> dict:
    score = 0
    breakdown = {}

    # --- Subdomains ---
    subdomain_count = len(data.get("subdomains", []))
    sub_score = min(subdomain_count * 1.5, 15)
    breakdown["subdomains"] = round(sub_score, 1)
    score += sub_score

    # --- Google Dorks ---
    dorks = data.get("google_dorks", [])
    dork_score = 0
    for d in dorks:
        sev = d.get("severity", "LOW")
        if sev == "HIGH":
            dork_score += 5
        elif sev == "MEDIUM":
            dork_score += 3
        else:
            dork_score += 1
    dork_score = min(dork_score, 20)
    breakdown["google_dorks"] = round(dork_score, 1)
    score += dork_score

    # --- Open Ports ---
    ports = data.get("shodan", {}).get("open_ports", [])
    dangerous_ports = {21, 22, 23, 25, 3306, 5432, 27017, 6379, 9200, 5900, 445, 139, 3389, 8080, 8443}
    port_score = sum(3 if p in dangerous_ports else 0.5 for p in ports)
    port_score = min(port_score, 15)
    breakdown["open_ports"] = round(port_score, 1)
    score += port_score

    # --- CVEs ---
    cves = data.get("cves", [])
    cve_score = 0
    for cve in cves:
        sev = cve.get("severity", "LOW")
        if sev == "CRITICAL":
            cve_score += 8
        elif sev == "HIGH":
            cve_score += 5
        elif sev == "MEDIUM":
            cve_score += 2
        else:
            cve_score += 0.5
    cve_score = min(cve_score, 25)
    breakdown["cves"] = round(cve_score, 1)
    score += cve_score

    # --- S3 Buckets ---
    buckets = data.get("s3_buckets", [])
    bucket_score = 0
    for b in buckets:
        if b.get("status") == "PUBLICLY ACCESSIBLE":
            bucket_score += 10
        elif "Access Denied" in b.get("status", ""):
            bucket_score += 2
    bucket_score = min(bucket_score, 15)
    breakdown["s3_buckets"] = round(bucket_score, 1)
    score += bucket_score

    # --- Hidden Paths ---
    paths = data.get("hidden_paths", [])
    path_score = 0
    for p in paths:
        sev = p.get("severity", "LOW")
        sc = p.get("status_code", 404)
        if sc == 200:
            if sev == "CRITICAL":
                path_score += 6
            elif sev == "HIGH":
                path_score += 4
            elif sev == "MEDIUM":
                path_score += 2
            else:
                path_score += 0.5
    path_score = min(path_score, 10)
    breakdown["hidden_paths"] = round(path_score, 1)
    score += path_score

    score = min(round(score, 1), 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "breakdown": breakdown,
        "recommendations": get_recommendations(data, level)
    }

def get_recommendations(data: dict, level: str) -> list:
    recs = []
    if data.get("google_dorks"):
        recs.append("Remove sensitive files indexed by Google (use robots.txt or noindex meta tags).")
    if data.get("s3_buckets"):
        recs.append("Review and restrict S3 bucket permissions — disable public access immediately.")
    if data.get("shodan", {}).get("open_ports"):
        recs.append("Close unnecessary open ports and use firewall rules to restrict access.")
    if data.get("cves"):
        recs.append("Patch all detected CVEs — prioritize CRITICAL and HIGH severity vulnerabilities.")
    if data.get("hidden_paths"):
        recs.append("Restrict access to admin panels, config files, and backup files via server configuration.")
    if data.get("subdomains"):
        recs.append("Audit all active subdomains and decommission unused or forgotten ones.")
    if level in ("CRITICAL", "HIGH"):
        recs.append("Conduct an immediate full security audit with a certified professional.")
    return recs
