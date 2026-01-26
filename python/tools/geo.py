import json, urllib.request

def run(args):
    if not args:
        return {"err": "please proporcione una Ip"}
    ip = args[0]
    try:
        with urllib.request.urlopen(
            f"https://ipinfo.io/{ip}/json",
            timeout=3
        ) as r:
            data = json.loads(r.read().decode())
        return {
            "ip": data.get("ip"),
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "org": data.get("org"),
            "loc": data.get("loc")
        }

    except Exception as e:
        return {"error": str(e)}

