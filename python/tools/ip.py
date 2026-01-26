import requests
import re
import json

def run(args):
    output = []
    def print_to_output(message):
        output.append(str(message))
        print(message)

    #print_to_output(f"recibido: {args}")
    ip = None
    if len(args) >= 1:
        for arg in args:
            if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", arg):
                ip = arg
                break

    if not ip:
        print_to_output("[X] Proporciona una IP!")
        print_to_output("TypeUse: !ip2 <ip>")
        print_to_output("ex: ip2 192.175.11.165")
        return {"status": "error", "message": "dame ip !", "output": output}

    print_to_output(f"Scan ip: {ip}")

    results = {}
    services = [
        ("ip-api", f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"),
        ("ipinfo", f"https://ipinfo.io/{ip}/json"),
        ("freegeoip", f"https://freegeoip.app/json/{ip}"),
        ("ipwhois", f"https://ipwhois.app/json/{ip}"),
        ("ip2location", f"https://api.ip2location.io/?ip={ip}"),
        ("ipstack", f"http://api.ipstack.com/{ip}?access_key=free"),
        ("ipdata", f"https://api.ipdata.co/{ip}?api-key=free"),
        ("abstractapi", f"https://ipgeolocation.abstractapi.com/v1/?api_key=free&ip_address={ip}"),
        ("keycdn", f"https://tools.keycdn.com/geo.json?host={ip}"),
        ("extreme-ip", f"https://extreme-ip-lookup.com/json/{ip}"),
        ("geojs", f"https://get.geojs.io/v1/ip/geo/{ip}.json"),
        ("ipfind", f"https://ipfind.co/me?ip={ip}"),
        ("db-ip", f"https://api.db-ip.com/v2/free/{ip}"),
        ("ipregistry", f"https://api.ipregistry.co/{ip}?key=free"),
        ("iplocation", f"https://www.iplocation.net/api/iplocation/v1/ip/{ip}"),
        ("ipapi", f"https://ipapi.co/{ip}/json/"),
        ("ipgeolocationapi", f"https://ipgeolocationapi.com/api/ip/{ip}"),
        ("iplocate", f"https://www.iplocate.io/api/lookup/{ip}"),
        ("ipapi-com", f"https://api.ipapi.com/api/{ip}?access_key=free"),
        ("ip-api-io", f"https://ip-api.io/json/{ip}")
    ]

    for name, url in services:
        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            data = r.json()
            results[name] = data
            print_to_output(f"[{name}] *Data*:")
            for key, value in data.items():
                print_to_output(f"  {key}: {value}")
        except Exception as e:
            results[name] = {"err": str(e)}
            print_to_output(f"*[{name}] err*: {str(e)}")

    return {
        "status": "success",
        "message": "*Done!*",
        "output": output,
        "data": results
    }

if __name__ == "__main__":
    import sys
    result = run(sys.argv)
    for message in result.get("output", []):
        print(message)
    print(result["message"])

