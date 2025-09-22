#!/usr/bin/env python3
"""
lookupip.py — Enrich relay IP with rDNS hostname + PoP detection
"""

import sys, socket, requests

CITY_HINTS = {
    # EU
    "ams": "Amsterdam", "fra": "Frankfurt", "lhr": "London",
    "cdg": "Paris", "mad": "Madrid", "waw": "Warsaw", "mil": "Milan",
    "vie": "Vienna", "bru": "Brussels", "cph": "Copenhagen",
    "arn": "Stockholm", "osl": "Oslo", "hel": "Helsinki",
    "zrh": "Zurich", "dub": "Dublin",
    # US
    "sjc": "San Jose", "sfo": "San Francisco", "lax": "Los Angeles",
    "iad": "Ashburn", "dfw": "Dallas", "ord": "Chicago", "nyc": "New York",
}

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return ""

def guess_pop_from_rdns(hostname: str) -> str:
    for key, city in CITY_HINTS.items():
        if key in hostname:
            return city
    return ""

def geoip_fallback(ip: str) -> dict:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def enrich(ip: str) -> dict:
    out = {"ip": ip}

    # Try rDNS → PoP
    rdns = reverse_dns(ip)
    if rdns:
        out["rdns"] = rdns
        pop = guess_pop_from_rdns(rdns)
        if pop:
            out["pop"] = pop
            return out  # strong signal: stop here

    # Fallback: GeoIP
    geo = geoip_fallback(ip)
    if geo:
        out.update({
            "city": geo.get("city", ""),
            "region": geo.get("region", ""),
            "country": geo.get("country", ""),
            "org": geo.get("org", "")
        })
    return out

def main():
    if len(sys.argv) != 2:
        print("Usage: lookupip.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]
    info = enrich(ip)
    for k,v in info.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    main()
