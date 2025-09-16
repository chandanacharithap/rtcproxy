import sys
import requests

if len(sys.argv) < 2:
    print("Usage: python3 lookupip.py <IP>")
    sys.exit(1)

ip = sys.argv[1]
url = f"http://ip-api.com/json/{ip}"

try:
    resp = requests.get(url)
    data = resp.json()

    if data["status"] == "success":
        print(f"IP: {ip}")
        print(f"City: {data['city']}")
        print(f"Region: {data['regionName']}")
        print(f"Country: {data['country']}")
        print(f"ISP: {data['isp']}")
    else:
        print(f"Lookup failed for {ip}: {data}")
except Exception as e:
    print(f"Error looking up {ip}: {e}")
