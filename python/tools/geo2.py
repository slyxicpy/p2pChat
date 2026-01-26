#!/usr/bin/env python3
import requests
import socket
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


def exTarget(input_str):

    input_str = re.sub(r'^https?://', '', input_str)
    input_str = input_str.split('/')[0]
    input_str = input_str.split(':')[0]
    
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, input_str):
        return input_str, 'ip'
    
    return input_str, 'domain'

def resDomain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None


def getIpApi(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipapiCo(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipwhois(ip):
    try:
        r = requests.get(f"http://ipwhois.app/json/{ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipinfo(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def freeGeo(ip):
    try:
        r = requests.get(f"https://freegeoip.app/json/{ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ip2Location(ip):
    try:
        r = requests.get(f"https://api.ip2location.io/?ip={ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipGeoIo(ip):
    try:
        r = requests.get(f"https://api.ipgeolocation.io/ipgeo?ip={ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipapiIs(ip):
    try:
        r = requests.get(f"https://api.ipapi.is/?q={ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def get_freeipapi_com(ip):
    try:
        r = requests.get(f"https://freeipapi.com/api/json/{ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def exIpLookup(ip):
    try:
        r = requests.get(f"https://extreme-ip-lookup.com/json/{ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipLocationNet(ip):
    try:
        r = requests.get(f"https://api.iplocation.net/?ip={ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def geoPlugin(ip):
    try:
        r = requests.get(f"http://www.geoplugin.net/json.gp?ip={ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipRegCo(ip):
    try:
        r = requests.get(f"https://api.ipregistry.co/{ip}?key=tryout", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipStack(ip):
    try:
        r = requests.get(f"http://api.ipstack.com/{ip}?access_key=demo", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def absIp(ip):
    try:
        r = requests.get(f"https://ipgeolocation.abstractapi.com/v1/?ip_address={ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipQuali(ip):
    try:
        r = requests.get(f"https://ipqualityscore.com/api/json/ip/demo/{ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def keyCdn(ip):
    try:
        r = requests.get(f"https://tools.keycdn.com/geo.json?host={ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipDataCo(ip):
    try:
        r = requests.get(f"https://api.ipdata.co/{ip}?api-key=test", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def ipFy(ip):
    try:
        r = requests.get(f"https://geo.ipify.org/api/v2/country?apiKey=at_test&ipAddress={ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def bigCloud(ip):
    try:
        r = requests.get(f"https://api.bigdatacloud.net/data/ip-geolocation?ip={ip}", timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def mergeData(results):
    merged = {
        'ip': None,
        'country': None,
        'country_code': None,
        'continent': None,
        'region': None,
        'state': None,
        'city': None,
        'district': None,
        'postal': None,
        'latitude': None,
        'longitude': None,
        'timezone': None,
        'offset': None,
        'currency': None,
        'currency_name': None,
        'calling_code': None,
        'languages': None,
        'flag': None,
        'isp': None,
        'org': None,
        'as': None,
        'asn': None,
        'mobile': None,
        'proxy': None,
        'vpn': None,
        'tor': None,
        'hosting': None,
        'datacenter': None,
        'bot': None,
        'threat': None,
        'country_area': None,
        'country_population': None,
    }
    
    for data in results:
        if not data:
            continue
        
        merged['ip'] = merged['ip'] or data.get('query') or data.get('ip') or data.get('ip_address')
        
        merged['country'] = merged['country'] or data.get('country') or data.get('country_name') or data.get('countryName')
        merged['country_code'] = merged['country_code'] or data.get('countryCode') or data.get('country_code') or data.get('country_code2')
        
        merged['continent'] = merged['continent'] or data.get('continent') or data.get('continent_name') or data.get('continentName')
        
        merged['region'] = merged['region'] or data.get('region') or data.get('regionName') or data.get('state_prov')
        merged['state'] = merged['state'] or data.get('state') or data.get('stateProv')
        
        merged['city'] = merged['city'] or data.get('city') or data.get('city_name')
        merged['district'] = merged['district'] or data.get('district')
        
        merged['postal'] = merged['postal'] or data.get('zip') or data.get('postal') or data.get('zipcode') or data.get('postcode')
        
        merged['latitude'] = merged['latitude'] or data.get('lat') or data.get('latitude')
        merged['longitude'] = merged['longitude'] or data.get('lon') or data.get('longitude')
        
        if not merged['timezone']:
            tz = data.get('timezone') or data.get('time_zone')
            if isinstance(tz, dict):
                merged['timezone'] = tz.get('name') or tz.get('id')
                merged['offset'] = tz.get('offset') or tz.get('gmt_offset')
            elif isinstance(tz, str):
                merged['timezone'] = tz
        
        if not merged['offset']:
            merged['offset'] = data.get('offset') or data.get('utc_offset') or data.get('gmt_offset')
        
        if not merged['currency']:
            curr = data.get('currency') or data.get('currency_code')
            if isinstance(curr, dict):
                merged['currency'] = curr.get('code')
                merged['currency_name'] = curr.get('name')
            else:
                merged['currency'] = curr
        
        if not merged['currency_name']:
            merged['currency_name'] = data.get('currency_name')
        
        merged['calling_code'] = merged['calling_code'] or data.get('calling_code') or data.get('country_calling_code') or data.get('phone_code')
        
        if not merged['languages']:
            langs = data.get('languages') or data.get('language')
            if isinstance(langs, list):
                merged['languages'] = ', '.join([l.get('name', l) if isinstance(l, dict) else l for l in langs])
            elif isinstance(langs, str):
                merged['languages'] = langs
        
        merged['flag'] = merged['flag'] or data.get('country_flag') or data.get('flag')
        if isinstance(merged['flag'], dict):
            merged['flag'] = merged['flag'].get('emoji') or merged['flag'].get('png')
        
        merged['isp'] = merged['isp'] or data.get('isp')
        if not merged['isp'] and data.get('connection'):
            merged['isp'] = data.get('connection').get('isp')
        
        merged['org'] = merged['org'] or data.get('org') or data.get('organization')
        merged['as'] = merged['as'] or data.get('as')
        
        if not merged['asn']:
            asn = data.get('asn')
            if isinstance(asn, dict):
                merged['asn'] = asn.get('number') or asn.get('asn')
            else:
                merged['asn'] = asn
        
        merged['mobile'] = merged['mobile'] if merged['mobile'] is not None else data.get('mobile')
        merged['proxy'] = merged['proxy'] if merged['proxy'] is not None else (data.get('proxy') or data.get('is_proxy'))
        merged['vpn'] = merged['vpn'] if merged['vpn'] is not None else data.get('vpn')
        merged['tor'] = merged['tor'] if merged['tor'] is not None else data.get('tor')
        merged['hosting'] = merged['hosting'] if merged['hosting'] is not None else data.get('hosting')
        merged['datacenter'] = merged['datacenter'] if merged['datacenter'] is not None else data.get('datacenter')
        merged['bot'] = merged['bot'] if merged['bot'] is not None else data.get('bot')
        merged['threat'] = merged['threat'] or data.get('threat_level') or data.get('fraud_score')
        
        merged['country_area'] = merged['country_area'] or data.get('country_area')
        merged['country_population'] = merged['country_population'] or data.get('country_population')
    
    return merged

def main():
    if len(sys.argv) < 2:
        print("\n*[Geo]*")
        print("\n*Type:*")
        print("  *.geo <IP-Shited>*")
        print("  *.geo <dominio>*")
        print("  *.geo <url>*")
        print("\n*Ej:*")
        print("  *.geo 192.189.11.179*")
        print("  *.geo hentaila.com*")
        print("  *.geo https://pornhub.com*")
        print()
        sys.exit(1)
    
    input_target = sys.argv[1]
    
    print(f"\n*[Consulta to: {input_target}]*\n")
    
    target, target_type = exTarget(input_target)
    
    if target_type == 'domain':
        ip = resDomain(target)
        if not ip:
            print(f"*[err] no pude resolve dom!*")
            sys.exit(1)
        print(f"[V-DoneResolv!] {target} -> {ip}\n")
    else:
        ip = target
    

    sources = [
        getIpApi,
        ipapiCo,
        ipwhois,
        ipinfo,
        freeGeo,
        ip2Location,
        ipGeoIo,
        ipapiIs,
        get_freeipapi_com,
        exIpLookup,
        ipLocationNet,
        geoPlugin,
        ipRegCo,
        ipStack,
        absIp,
        ipQuali,
        keyCdn,
        ipDataCo,
        ipFy,
        bigCloud,
    ]
    
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(func, ip): func for func in sources}
        for future in as_completed(futures):
            try:
                data = future.result()
                if data:
                    results.append(data)
            except:
                pass
    
    
    if not results:
        print("*[err] NOt info to ip! maybe ip privada or incorrect!*")
        sys.exit(1)
    
    geo = mergeData(results)

    print("*[Consulta geoloca!]*")
    
    print(f"\n*[Objetivo!]*")
    if target_type == 'domain':
        print(f"Dominio: `{target}`")
    print(f"IP: `{geo['ip']}`")
    
    print(f"\n*[GEO]*")
    if geo['country']:
        country_str = geo['country']
        if geo['country_code']:
            country_str += f" ({geo['country_code']})"
        if geo['flag']:
            country_str += f" {geo['flag']}"
        print(f"Pais: {country_str}")
    
    if geo['continent']:
        print(f"Continente: {geo['continent']}")
    
    if geo['region'] or geo['state']:
        region = geo['region'] or geo['state']
        print(f"Region/Estado: {region}")
    
    if geo['city']:
        print(f"Ciudad: {geo['city']}")
    
    if geo['district']:
        print(f"Distrito: {geo['district']}")
    
    if geo['postal']:
        print(f"Code Postal: {geo['postal']}")
    
    if geo['latitude'] and geo['longitude']:
        print(f"\n*[COORD'S]*")
        print(f"Lat: {geo['latitude']}")
        print(f"Long: {geo['longitude']}")
        
        print(f"\n*[MAP'S]*")
        print(f"Gg: https://www.google.com/maps?q={geo['latitude']},{geo['longitude']}")
        print(f"OpenS-Map: https://www.openstreetmap.org/?mlat={geo['latitude']}&mlon={geo['longitude']}&zoom=12")
        print(f"Bing: https://www.bing.com/maps?cp={geo['latitude']}~{geo['longitude']}&lvl=12")
    
    if geo['timezone'] or geo['offset']:
        print(f"\n*[ZONA H!]*")
        if geo['timezone']:
            print(f"Timezone: {geo['timezone']}")
        if geo['offset']:
            print(f"UTC: {geo['offset']}")
    
    if geo['currency'] or geo['calling_code'] or geo['languages']:
        print(f"\n*[INFO PAIS!]*")
        if geo['currency']:
            curr_str = geo['currency']
            if geo['currency_name']:
                curr_str += f" ({geo['currency_name']})"
            print(f"Coins: {curr_str}")
        
        if geo['calling_code']:
            print(f"Codigo telefonico: {geo['calling_code']}")
        
        if geo['languages']:
            print(f"Idioma's: {geo['languages']}")
        
        if geo['country_area']:
            print(f"Area: {geo['country_area']} km²")
        
        if geo['country_population']:
            print(f"Poblacion: {geo['country_population']:,}")
    
    if geo['isp'] or geo['org'] or geo['asn']:
        print(f"\n*[IRED/ISP!]*")
        if geo['isp']:
            print(f"ISP: {geo['isp']}")
        if geo['org']:
            print(f"Org: {geo['org']}")
        if geo['as']:
            print(f"AS: {geo['as']}")
        if geo['asn']:
            print(f"ASN: {geo['asn']}")
    
    flags = []
    if geo['mobile']:
        flags.append('Mobile')
    if geo['proxy']:
        flags.append('Proxy')
    if geo['vpn']:
        flags.append('VPN')
    if geo['tor']:
        flags.append('TOR')
    if geo['hosting']:
        flags.append('Hosting')
    if geo['datacenter']:
        flags.append('Datacenter')
    if geo['bot']:
        flags.append('Bot')
    
    if flags:
        print(f"\n*[STAT'S!]*")
        print(f"Flags: {', '.join(flags)}")
    
    if geo['threat']:
        print(f"Threat Lv: {geo['threat']}")
    
    print(f"\n*[Consulta finished!]*")

if __name__ == "__main__":
    main()
