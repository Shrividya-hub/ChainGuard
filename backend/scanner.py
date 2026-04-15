import requests

OSV_URL = "https://api.osv.dev/v1/query"

def check_vulnerability(package, version):
    payload = {
        "package": {
            "name": package
        },
        "version": version
    }

    try:
        response = requests.post(OSV_URL, json=payload)
        data = response.json()

        vulns = data.get("vulns", [])
        results = []

        for v in vulns:
            results.append({
                "id": v.get("id"),
                "summary": v.get("summary", "No description")
            })

        return results

    except:
        return []