#!/usr/bin/env python3
"""
lookupip.py — Enrich relay IP with GeoIP + rDNS hostname
- Tries reverse DNS first (to catch PoP codes like ams/fra/lhr)
- Falls back to ipinfo.io / ipapi.co JSON APIs
"""

import sys, json, socket, urllib.request

CITY_HINTS = {
    "ams": "Amsterdam", "fra": "Frankfurt", "lhr": "London",
    "cdg": "Paris", "mad": "Madrid", "waw": "Warsaw", "mil": "Milan",
    "vie": "Vienna", "bru": "Brussels", "cph": "Copenhagen",
    "arn": "Stockholm", "osl": "Oslo", "hel": "Helsinki",
    "zrh": "Zurich", "dub": "Dublin",
    "sjc": "San Jose", "sfo": "San Francisco", "lax": "Los Angeles",
    "iad": "Ashburn", "dfw": "Dallas", "ord": "Chicago", "nyc": "New York",
}

def _fetch(url):
    with urllib.request.urlopen(url, timeout=8) as resp:
        return json.loads(resp.read().decode())

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return ""

def guess_city_from_rdns(hostname: str) -> str:
    for key, city in CITY_HINTS.items():
        if key in hostname:
            return city
    return ""

def lookup(ip: str) -> dict:
    """Return best-effort info: rDNS, city, region, country, ASN/ISP."""
    result = {"ip": ip}

    # Try reverse DNS first
    rdns = reverse_dns(ip)
    if rdns:
        result["rdns"] = rdns
        city = guess_city_from_rdns(rdns)
        if city:
            result["city"] = city
            return result  # good enough (PoP identified)

    # Try ipinfo.io
    try:
        d = _fetch(f"https://ipinfo.io/{ip}/json")
        if d and "ip" in d:
            result.update({
                "city": d.get("city"),
                "region": d.get("region"),
                "country": d.get("country"),
                "asn": d.get("org").split()[0] if d.get("org") else None,
                "isp": d.get("org"),
            })
            return result
    except Exception:
        pass

    # Fallback: ipapi.co
    try:
        d = _fetch(f"https://ipapi.co/{ip}/json/")
        result.update({
            "city": d.get("city"),
            "region": d.get("region"),
            "country": d.get("country_name") or d.get("country"),
            "asn": d.get("asn"),
            "isp": d.get("org"),
        })
    except Exception:
        pass

    return result

def main():
    if len(sys.argv) < 2:
        print("Usage: lookupip.py <IP> [<IP> ...]")
        sys.exit(1)
    for ip in sys.argv[1:]:
        info = lookup(ip)
        for k, v in info.items():
            if v:
                print(f"{k}: {v}")

if __name__ == "__main__":
    main()
