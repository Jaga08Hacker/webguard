import requests

def check_s3_buckets(domain: str) -> list:
    exposed = []
    base = domain.replace("www.", "").replace(".", "-")

    # Common bucket naming patterns
    variants = [
        domain,
        base,
        f"{base}-backup",
        f"{base}-assets",
        f"{base}-media",
        f"{base}-static",
        f"{base}-files",
        f"{base}-uploads",
        f"{base}-data",
        f"{base}-public",
        f"{base}-dev",
        f"{base}-staging",
        f"{base}-prod",
        f"{base}-logs",
        f"backup-{base}",
        f"static-{base}",
        f"media-{base}",
        f"assets-{base}",
    ]

    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

    for bucket_name in variants:
        # Check default S3 endpoint
        urls_to_check = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
        ]
        # Check regional endpoints
        for region in regions:
            urls_to_check.append(f"https://{bucket_name}.s3.{region}.amazonaws.com")

        for url in urls_to_check[:3]:  # Limit checks per bucket
            try:
                r = requests.get(url, timeout=6, allow_redirects=True)
                if r.status_code == 200:
                    exposed.append({
                        "bucket_name": bucket_name,
                        "url": url,
                        "status": "PUBLICLY ACCESSIBLE",
                        "severity": "CRITICAL",
                        "content_preview": r.text[:500]
                    })
                    break  # Found, no need to check other URLs
                elif r.status_code == 403:
                    exposed.append({
                        "bucket_name": bucket_name,
                        "url": url,
                        "status": "EXISTS (Access Denied)",
                        "severity": "MEDIUM",
                        "content_preview": ""
                    })
                    break
            except requests.exceptions.ConnectionError:
                pass  # Bucket doesn't exist
            except Exception as e:
                print(f"[S3] Error checking {url}: {e}")

    return exposed
