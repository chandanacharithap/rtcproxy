#!/usr/bin/env python3
"""
lookupip.py — enrich a single IP with geolocation and ASN info

Usage:
    python3 lookupip.py <ip>

Output (lines of key: value) that check_dpi.py can parse:
    city: Amsterdam
    region: North Holland
    country: NL
    asn: AS16509 Amazon.com, Inc.
    isp: Amazon.com, Inc.
"""

import sys
import requests

def lookup_ip(ip: str) -> None:
    try:
        # Query ipinfo.io (free tier, no token required)
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()

        if "city" in resp:
            print(f"city: {resp['city']}")
        if "region" in resp:
            print(f"region: {resp['region']}")
        if "country" in resp:
            print(f"country: {resp['country']}")
        if "org" in resp:
            print(f"asn: {resp['org']}")
            print(f"isp: {resp['org']}")
        if "ip" in resp:
            print(f"ip: {resp['ip']}")
    except Exception as e:
        print(f"error: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: lookupip.py <ip>")
        sys.exit(1)
    ip = sys.argv[1]
    lookup_ip(ip)

if __name__ == "__main__":
    main()
