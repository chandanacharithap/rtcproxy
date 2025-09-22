#!/usr/bin/env python3
"""
lookupip.py — Enrich relay IP with PoP detection priority.
- Prefer rDNS with city code (ams, fra, lhr, etc.)
- Fall back to traceroute rDNS hints
- Last resort: GeoIP database
"""

import sys, socket, re, requests, subprocess, shlex

CITY_HINTS = {
    "ams": "Amsterdam", "fra": "Frankfurt", "lhr": "London",
    "cdg": "Paris", "mad": "Madrid", "waw": "Warsaw", "mil": "Milan",
    "vie": "Vienna", "bru": "Brussels", "cph": "Copenhagen",
    "arn": "Stockholm", "osl": "Oslo", "hel": "Helsinki",
    "zrh": "Zurich", "dub": "Dublin",
    "sjc": "San Jose", "sfo": "San Francisco", "lax": "Los Angeles",
    "iad": "Ashburn", "dfw": "Dallas", "ord": "Chicago", "nyc": "New York",
}

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

def traceroute_guess(ip: str, port: int = 8801) -> str:
    try:
        out = subprocess.run(
            shlex.split(f"traceroute -q1 -U -p {port} {ip}"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20
        )
        lines = out.stdout.decode(errors="ignore").splitlines()
        for line in lines[-4:]:  # last hops
            m = re.search(r"\s+\d+\s+([^\s(]+)", line)
            if not m:
                continue
            host = m.group(1).lower()
            for key, city in CITY_HINTS.items():
                if key in host:
                    return city
    except Exception:
        pass
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

    # Step 1: reverse DNS check
    rdns = reverse_dns(ip)
    if rdns:
        out["rdns"] = rdns
        city = guess_city_from_rdns(rdns)
        if city:
            out["pop"] = city
            return out  # PoP detected, highest priority

    # Step 2: traceroute last hops
    tr_city = traceroute_guess(ip)
    if tr_city:
        out["pop"] = tr_city
        return out

    # Step 3: fallback GeoIP
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
