# 🛰️ RTC Relay Measurement Setup & Usage (Azure + WireGuard + Capture Controller)

This guide walks you through setting up **two Azure Ubuntu VMs**, configuring the **RTC capture service**, linking **phones via WireGuard VPN**, and running automated captures via the PowerShell controller script (`rtc_capture.ps1`).
It supports **relay IP detection**, **ASN/CIDR blocking**, and **geolocation lookup via ipinfo.io**.

---

## 🧩 1️⃣ VM Setup in Azure Portal

### **Create 2 Ubuntu VMs**

* Region examples: `West Europe` and `Southeast Asia`
* **Size:** 2 vCPUs, 4 GB RAM (Standard_B2s works fine)
* **Image:** Ubuntu Server 20.04 LTS or 22.04 LTS
* **Authentication:** SSH key (generate or reuse one)

  ```bash
  ssh-keygen -t rsa -b 4096 -f ~/.ssh/azure_rtc
  ```
* Copy the **public key** to both VMs during creation.

---

### **Networking Configuration (via Azure Portal)**

Go to each VM → **Networking → Add inbound port rules:**

| Purpose         | Port  | Protocol | Source | Action |
| --------------- | ----- | -------- | ------ | ------ |
| RTC Capture API | 5000  | TCP      | My IP  | Allow  |
| WireGuard VPN   | 51820 | UDP      | Any    | Allow  |
| SSH Access      | 22    | TCP      | My IP  | Allow  |

> ✅ This enables the capture API, VPN tunnel, and remote control access.

---

## ⚙️ 2️⃣ Install Dependencies on Each VM

Connect via SSH:

```bash
ssh -i ~/.ssh/azure_rtc azureuser@<VM_PUBLIC_IP>
```

Install required packages:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip tshark git wireguard qrencode whois
```

Install python:
```
mkdir -p "$HOME/.venvs"
python3 -m venv "$HOME/.venvs/rtcproxy"
source "$HOME/.venvs/rtcproxy/bin/activate"
```

---

## 🧠 3️⃣ Clone Repo and Setup API Service

```bash
sudo git clone https://github.com/<your-repo>/rtcproxy.git /opt/rtcproxy
cd /opt/rtcproxy
pip3 install -r requirements.txt
```

Ensure `api.py` and `check_dpi.py` exist:

```bash
ls /opt/rtcproxy
```

Create a systemd service:

```bash
sudo tee /etc/systemd/system/rtcproxy.service <<EOF
[Unit]
Description=RTC Capture API
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/rtcproxy/api.py
WorkingDirectory=/opt/rtcproxy
Restart=always
User=azureuser

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start the API:

```bash
sudo systemctl daemon-reexec
sudo systemctl enable rtcproxy
sudo systemctl start rtcproxy
sudo systemctl status rtcproxy
```

> Should show **active (running)** and **Listening on 0.0.0.0:5000**

---

## 🔐 4️⃣ WireGuard Setup (Phone ↔ VM)

### **On the VM**

```bash
sudo apt install -y wireguard qrencode
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key
```

Edit `/etc/wireguard/wg0.conf`:

```
[Interface]
PrivateKey = <SERVER_PRIVATE_KEY>
Address = 10.8.0.1/24
ListenPort = 51820
```

Generate client keys:

```bash
wg genkey | tee phone_private.key | wg pubkey > phone_public.key
```

Create `phone.conf`:

```
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
to get your phone's keys and your VM keys use cat commands. (ex: cat server_public.key)
Show QR for your phone:

```bash
qrencode -t ansiutf8 < phone.conf
```

📱 **On your phone:** Open WireGuard → “Add Tunnel” → “Scan QR Code”

Start the VPN:

```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
sudo wg
```

✅ You should see a live handshake.

---

## 💻 5️⃣ Local Controller (Windows Machine)

Make sure you have:

* `rtc_capture.ps1` script in `C:\Users\chand`
* `scp` and `ssh` accessible from PowerShell (`where ssh` should show OpenSSH path)
* Your private key:
  `C:\Users\chand\.ssh\azure_rtc.pem`

Edit the top of `rtc_capture.ps1`:

```powershell
$VM1_IP    = "20.55.35.218"
$VM2_IP    = "20.24.57.248"
$SSH_KEY   = "C:\Users\chand\.ssh\azure_rtc.pem"
$USER      = "azureuser"
$BASE_DIR  = "C:\Users\chand\captures"
$BLOCK_FILE = "$BASE_DIR\blocking.txt"
$IPINFO_TOKEN = "YOUR_TOKEN_HERE"  # Optional
$REGION1   = "west-europe"
$REGION2   = "south-east-asia"
```

---

## 🧪 6️⃣ Running a Capture

Turn **on WireGuard** on both phones.
Start a Zoom / Meet / WhatsApp / Teams call.
Then, in PowerShell:

```powershell
cd C:\Users\chand
.\rtc_capture.ps1
```

✅ The script will:

1. Start capture on both VMs (`/start`)
2. Record for 30 seconds
3. Stop capture (`/stop`)
4. Download PCAPs
5. Run `check_dpi.py` remotely
6. Show relay IPs, geolocation, and top IPs
7. Offer to block detected relays (iptables)

---

## 📊 7️⃣ Example Output

```
========== ANALYSIS DONE ==========
VM1 (20.55.35.218):
Relay found from DPI: 206.247.43.41 (San Jose, US, Zoom)

Top 5 IPs:
206.247.43.41, 61k pkts (relay)
151.101.3.6, 418 pkts
1.0.0.1, 98 pkts

VM2 (20.24.57.248):
Relay found from DPI: 206.247.43.41 (San Jose, US, Zoom)
...
===================================
Captured files stored in: C:\Users\chand\captures\west-europe-south-east-asia-run_5
```

---

## 🚫 8️⃣ Blocking Relay Subnets Automatically

When prompted:

```
Relay IP detected: 206.247.43.41
Press 'b' to block this relay subnet 206.247.0.0/16 (or Enter to skip):
```

If you press **b**, the script:

* Adds subnet to `blocking.txt`
* Applies `iptables` rules on both VMs:

  ```
  sudo iptables -I FORWARD -d <subnet> -j DROP
  sudo iptables -I FORWARD -s <subnet> -j DROP
  sudo iptables -I OUTPUT -d <subnet> -j DROP
  sudo iptables -I INPUT -s <subnet> -j DROP
  ```

---

## 💡 9️⃣ Notes & Gotchas

* Uses **ipinfo.io** for location lookup (replace `YOUR_TOKEN_HERE` with real token).
* Private IPs (`172.x`, `192.168.x`) are skipped — those are internal tunnels.
* If `check_dpi.py` shows only `172.x` IPs, you’ve blocked all public relays — the app may fall back to local peers.
* Output and logs are stored per run under:

  ```
  C:\Users\chand\captures\<region1>-<region2>-run_<N>\
  ```

* **For business accounts**, we have set up 2 accounts for Zoom, Google Meet, and Microsoft Teams. See login instructions [here](https://docs.google.com/spreadsheets/d/1mPv7KNgY9s4xKgqWKOYSE27-RdRJQZg1zn9V6VfSwWg/edit?gid=0#gid=0). The accounts are paid monthly.


---

## ⚡ That’s It!

