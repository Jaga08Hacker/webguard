import shodan
import socket

def run_shodan_scan(domain: str, api_key: str) -> dict:
    result = {
        "ip": None,
        "open_ports": [],
        "services": [],
        "vulnerabilities": [],
        "os": None,
        "country": None,
        "org": None,
        "hostnames": [],
        "raw_banners": []
    }

    try:
        api = shodan.Shodan(api_key)

        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
            result["ip"] = ip
        except Exception:
            return result

        host = api.host(ip)

        result["country"] = host.get("country_name", "Unknown")
        result["org"] = host.get("org", "Unknown")
        result["os"] = host.get("os", "Unknown")
        result["hostnames"] = host.get("hostnames", [])

        for item in host.get("data", []):
            port = item.get("port")
            transport = item.get("transport", "tcp")
            product = item.get("product", "Unknown")
            version = item.get("version", "")
            banner = item.get("data", "")[:200]

            result["open_ports"].append(port)
            result["services"].append({
                "port": port,
                "protocol": transport,
                "service": product,
                "version": version,
                "banner": banner
            })

            # Extract CVEs from Shodan
            vulns = item.get("vulns", {})
            for cve_id, cve_info in vulns.items():
                result["vulnerabilities"].append({
                    "cve": cve_id,
                    "cvss": cve_info.get("cvss", "N/A"),
                    "summary": cve_info.get("summary", "")
                })

            result["raw_banners"].append(banner)

        result["open_ports"] = list(set(result["open_ports"]))

    except shodan.APIError as e:
        print(f"[Shodan] API Error: {e}")
    except Exception as e:
        print(f"[Shodan] Error: {e}")

    return result
