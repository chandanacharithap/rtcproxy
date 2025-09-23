
# 📘 Azure RTC Capture Setup Guide

This guide explains how to deploy two Azure VMs (East US + West Europe), configure them for packet capture, and analyze Zoom/WebRTC relay IPs using `check_dpi.py`.

---

## 1. Create the Virtual Machines

1. Log in to the [Azure Portal](https://portal.azure.com).
2. Create **two VMs** in the same resource group (e.g., `rtc-test`):

   * **VM1**

     * Region: **East US (Zone 3)**
     * Size: `Standard D2s v3` (2 vCPUs, 8 GB RAM)
     * OS: **Ubuntu 22.04 LTS**
     * Public IP: `20.55.35.218`

   * **VM2**

     * Region: **West Europe (Zone 2)**
     * Size: `Standard D2s v3` (2 vCPUs, 8 GB RAM)
     * OS: **Ubuntu 22.04 LTS**
     * Public IP: `20.56.16.9`

⚠️ Use **SSH key authentication**. Save your private key as `azure_rtc.pem`.

---

## 2. Configure Networking Rules

Each VM needs inbound rules in its **Network Security Group (NSG).**

### ✅ VM1 (East US)

| Priority | Name      | Port(s) | Protocol | Source | Destination | Action |
| -------- | --------- | ------- | -------- | ------ | ----------- | ------ |
| 110      | allow-wg  | 51820   | UDP      | Any    | Any         | Allow  |
| 300      | SSH       | 22      | TCP      | Any    | Any         | Allow  |
| 310      | RDP-Allow | 3389    | TCP      | Any    | Any         | Allow  |
| 320      | allow-tcp | 5000    | TCP      | Any    | Any         | Allow  |
| 65000    | AllowVnet | Any     | Any      | VNet   | VNet        | Allow  |
| 65001    | AllowLB   | Any     | Any      | ALB    | Any         | Allow  |
| 65500    | DenyAllIn | Any     | Any      | Any    | Any         | Deny   |

### ✅ VM2 (West Europe)

| Priority | Name                     | Port(s)     | Protocol | Source | Destination | Action |
| -------- | ------------------------ | ----------- | -------- | ------ | ----------- | ------ |
| 110      | allow-wg                 | 51820       | UDP      | Any    | Any         | Allow  |
| 120      | allow-turn-udp           | 3478        | UDP      | Any    | Any         | Allow  |
| 121      | allow-turn-tcp           | 3478        | TCP      | Any    | Any         | Allow  |
| 122      | allow-turn-relay-udp     | 49160–49200 | UDP      | Any    | Any         | Allow  |
| 200      | allow-flask-5000-from-ip | 5000        | TCP      | Any    | Any         | Allow  |
| 300      | SSH                      | 22          | TCP      | Any    | Any         | Allow  |
| 310      | RDP-Allow                | 3389        | TCP      | Any    | Any         | Allow  |
| 65000    | AllowVnet                | Any         | Any      | VNet   | VNet        | Allow  |
| 65001    | AllowLB                  | Any         | Any      | ALB    | Any         | Allow  |
| 65500    | DenyAllIn                | Any         | Any      | Any    | Any         | Deny   |

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

## 8. Latency Notes

* **VM1 (East US)** ↔ **VM2 (West Europe)** traffic crosses the Atlantic.
* Expected RTT: **140–250 ms**, matches your observed \~256 ms.
* If both VMs are in the **same region**, RTT drops to **20–40 ms**.

| VM Placement              | Expected RTT |
| ------------------------- | ------------ |
| East US ↔ East US         | 20–40 ms     |
| West Europe ↔ West Europe | 20–40 ms     |
| East US ↔ West Europe     | 140–250 ms   |

---

✅ With this setup, you can reliably capture Zoom/WebRTC traffic, download `.pcap` files, and analyze relay IPs and latency.

