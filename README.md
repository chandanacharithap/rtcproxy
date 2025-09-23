
# 📘 Azure RTC Capture & WireGuard Setup Guide

This guide explains how to deploy two Azure VMs (East US + West Europe), configure them for packet capture, analyze Zoom/WebRTC relay IPs using `check_dpi.py`, and connect your phone to a VM via WireGuard.

---

## 1. Create the Virtual Machines

1. Log in to the [Azure Portal](https://portal.azure.com).
2. Create **two VMs** in the same resource group (e.g., `rtc-test`):

   * **VM1 (East US)**

     * Region: **East US (Zone 3)**
     * Size: `Standard D2s v3` (2 vCPUs, 8 GB RAM)
     * OS: **Ubuntu 22.04 LTS**
     * Public IP: `20.55.35.218` [This is your VM1's IP]

   * **VM2 (West Europe)**

     * Region: **West Europe (Zone 2)**
     * Size: `Standard D2s v3` (2 vCPUs, 8 GB RAM)
     * OS: **Ubuntu 22.04 LTS**
     * Public IP: `20.56.16.9` [This is your VM2's IP]

⚠️ Use **SSH key authentication**. Save your private key as `azure_rtc.pem`.

---

## 2. Configure Networking Rules (NSG)

Each VM needs inbound rules in its **Network Security Group (NSG).**

### ✅ VM1 (East US)

| Priority | Name      | Port(s) | Protocol | Source | Destination | Action |
| -------- | --------- | ------- | -------- | ------ | ----------- | ------ |
| 110      | allow-wg  | 51820   | UDP      | Any    | Any         | Allow  |
| 300      | SSH       | 22      | TCP      | Any    | Any         | Allow  |
| 310      | RDP-Allow | 3389    | TCP      | Any    | Any         | Allow  |
| 320      | allow-tcp | 5000    | TCP      | Any    | Any         | Allow  |

### ✅ VM2 (West Europe)

| Priority | Name                     | Port(s)     | Protocol | Source | Destination | Action |
| -------- | ------------------------ | ----------- | -------- | ------ | ----------- | ------ |
| 110      | allow-wg                 | 51820       | UDP      | Any    | Any         | Allow  |
| 120      | allow-turn-udp           | 3478        | UDP      | Any    | Any         | Allow  |
| 121      | allow-turn-tcp           | 3478        | TCP      | Any    | Any         | Allow  |
| 122      | allow-turn-relay-udp     | 49160–49200 | UDP      | Any    | Any         | Allow  |
| 200      | allow-flask-5000-from-ip | 5000        | TCP      | Any    | Any         | Allow  |

---

## 3. Install Dependencies

SSH into each VM:

```bash
ssh -i ~/azure_rtc.pem azureuser@<VM_PUBLIC_IP>
```

Install tools:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y tcpdump python3 python3-pip git iptables
pip3 install flask dpkt pyshark
```

---

## 4. Deploy the Capture API

Copy your `api.py` to `/opt/rtcproxy`:

```bash
sudo mkdir -p /opt/rtcproxy
sudo cp api.py /opt/rtcproxy/
cd /opt/rtcproxy
```

Run the API:

```bash
sudo python3 api.py &
```

Verify:

```bash
ps aux | grep api.py
sudo ss -tulnp | grep 5000
```

---

## 5. Start / Stop Capture

From your laptop (PowerShell):

```powershell
$h = @{"X-API-Key"="MYSECRET"}

# Start
Invoke-WebRequest -Uri "http://<VM_PUBLIC_IP>:5000/start" -Method POST -Headers $h -Proxy $null

# Stop
Invoke-WebRequest -Uri "http://<VM_PUBLIC_IP>:5000/stop" -Method POST -Headers $h -Proxy $null
```

---

## 6. Analyze PCAP with `check_dpi.py`

Upload `check_dpi.py` + `lookupip.py` to `/opt/rtcproxy/`.

Run analysis:

```bash
ssh -i ~/azure_rtc.pem azureuser@<VM_PUBLIC_IP> \
  "python3 /opt/rtcproxy/check_dpi.py --pcap /var/log/rtc/<pcap_file>"
```

---

## 7. Download PCAP to Local

```powershell
Invoke-WebRequest -Uri "http://<VM_PUBLIC_IP>:5000/download?file=/var/log/rtc/<pcap_file>" `
  -Method GET -Headers $h -OutFile "C:\Users\chand\Downloads\<pcap_file>"
```

---
---

# 📱 Connect Phone to VM via WireGuard (QR Setup)

## 1. Install WireGuard on the VM

```bash
ssh -i ~/azure_rtc.pem azureuser@<VM_PUBLIC_IP>
sudo apt update
sudo apt install -y wireguard qrencode
```

---

## 2. Generate Server Keys

```bash
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key
```

---

## 3. Configure WireGuard Server

```bash
sudo nano /etc/wireguard/wg0.conf
```

Paste this (replace `<SERVER_PRIVATE_KEY>` and `<VM_PUBLIC_IP>`):

```ini
[Interface]
PrivateKey = <SERVER_PRIVATE_KEY>
Address = 10.8.0.1/24
ListenPort = 51820

# Phone peer
[Peer]
PublicKey = <PHONE_PUBLIC_KEY>
AllowedIPs = 10.8.0.2/32
```

---

## 4. Generate Phone (Client) Config

```bash
wg genkey | tee phone_private.key | wg pubkey > phone_public.key
```

Create `phone.conf`:

```ini
[Interface]
PrivateKey = <PHONE_PRIVATE_KEY>
Address = 10.8.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <VM_PUBLIC_IP>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

---

## 5. Show QR Code for Phone

```bash
qrencode -t ansiutf8 < phone.conf
```

👉 Open WireGuard app on your phone → **Add Tunnel** → **Scan QR code**.

---

## 6. Start WireGuard

```bash
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
```

Check:

```bash
sudo wg
```

On your phone, activate the tunnel.



