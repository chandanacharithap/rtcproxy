RTC Relay Measurement Setup & Usage

This guide explains how to set up two fresh Azure VMs (VM1 and VM2), configure them for RTC capture, and run the relay detection scripts.
It covers **VM cloning, repo setup, API service, WireGuard, capture/analysis steps, and interpreting results.**

---

## 1️⃣ VM Setup & Cloning

1. **Create two Azure Ubuntu VMs** (e.g., `us-east` and `europe-west` regions).

   * Minimum: 2 vCPUs, 4 GB RAM.
   * OS: Ubuntu 20.04+.

2. Generate or reuse your SSH keypair:

   ```bash
   ssh-keygen -t rsa -b 4096 -f ~/.ssh/azure_rtc
   ```

   Add the **public key** to both VMs.

3. Verify connectivity:

   ```bash
   ssh -i ~/.ssh/azure_rtc azureuser@<VM_IP>
   ```

---

## 2️⃣ Install Dependencies on Each VM

Run the following **once on each VM**:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip tshark git
```

---

## 3️⃣ Clone Repo & Set Up Capture API

1. Clone the `rtcproxy` repo:

   ```bash
   git clone https://github.com/<your-repo>/rtcproxy.git /opt/rtcproxy
   cd /opt/rtcproxy
   pip3 install -r requirements.txt
   ```

2. Make sure `check_dpi.py` exists in `/opt/rtcproxy`.

3. **Setup the capture API** as a service:

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

4. Enable + start the service:

   ```bash
   sudo systemctl daemon-reexec
   sudo systemctl enable rtcproxy
   sudo systemctl start rtcproxy
   sudo systemctl status rtcproxy
   ```

   API should now run at `http://<VM_IP>:5000/`.
---

## 4️⃣ WireGuard Setup

1. Install WireGuard + QR utility:

   ```bash
   sudo apt update
   sudo apt install -y wireguard qrencode
   ```

2. Generate server keys:

   ```bash
   umask 077
   wg genkey | tee server_private.key | wg pubkey > server_public.key
   ```

3. Configure `wg0.conf` on VM:

   ```ini
   [Interface]
   PrivateKey = <SERVER_PRIVATE_KEY>
   Address = 10.8.0.1/24
   ListenPort = 51820
   ```

   Save this file:

   ```bash
   sudo nano /etc/wireguard/wg0.conf
   ```

4. Generate phone (client) config:

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

5. Show QR code for phone:

   ```bash
   qrencode -t ansiutf8 < phone.conf
   ```

   👉 On your phone: Open WireGuard app → *Add Tunnel* → *Scan QR code*.

6. Enable WireGuard service:

   ```bash
   sudo wg-quick up wg0
   sudo systemctl enable wg-quick@wg0
   ```

7. Verify tunnel:

   ```bash
   sudo wg show
   ping 10.8.0.2
   ```

---

## 5️⃣ Local Controller Setup

On your Windows machine, ensure:

* `rtc_capture.ps1` script is present.
* `scp` and `ssh` work with your private key.

Adjust the script config:

```powershell
$VM1_IP   = "<VM1_PUBLIC_IP>"
$VM2_IP   = "<VM2_PUBLIC_IP>"
$SSH_KEY  = "C:\Users\<you>\.ssh\azure_rtc.pem"
$USER     = "azureuser"
```

---

## 6️⃣ Running a Capture
This rtc_capture.ps1 script should be in "C:/Users/chand"

1. Start a Zoom/WhatsApp/Messenger/Google Meet call between the endpoints (or from one VM if testing loop).

2. Run the controller script:

   ```powershell
   .\rtc_capture.ps1
   ```

3. Script workflow:

   * Starts capture on both VMs (`/start` API).
   * Collects traffic for 30s.
   * Stops capture (`/stop` API).
   * Downloads PCAPs to local `C:\Users\chand\captures\us-east-europe-west-run_<N>\`.
   * Runs DPI analysis (`check_dpi.py`) on each VM.
   * Prints + saves relay IP + geolocation + service name.

---

## 7️⃣ Output Layout

Example Zoom call:

```
========== ANALYSIS DONE ==========
VM1 (20.55.35.218):
Relay found from DPI: 206.247.43.41 (San Jose, United States, Zoom)

Top 5 IPs:
206.247.43.41, 61k pkts (relay)
...

Saved to: C:\Users\chand\captures\us-east-europe-west-run_59\vm1-analysis.txt

VM2 (20.56.16.9):
Relay found from DPI: 206.247.43.41 (San Jose, United States, Zoom)

Top 5 IPs:
206.247.43.41, 80k pkts (relay)
...

===================================
Captured files stored in: C:\Users\chand\captures\us-east-europe-west-run_59
```

* **Relay IP**: The main IP handling RTP.
* **Location**: City + Country (via DPI + ip-api lookup).
* **Service**: Zoom, WhatsApp, Messenger, Meet, etc.
* **Top 5 IPs**: Ranked by packet count.

---

## 8️⃣ Notes & Gotchas

* **Meta Services (WhatsApp, Messenger, Instagram)** → all use the same Meta relay infra. Relay IPs will be owned by *Facebook/Meta*. To distinguish WhatsApp vs Messenger requires packet signature/port heuristics.
* **DNS IPs (1.1.1.1, 8.8.8.8)** are filtered out in output.
* If output has `?`, fallback API lookup fills missing fields.
* **Service Map** in script maps ASNs/ISPs to known apps.

* **For business accounts**, we have set up 2 accounts for Zoom, Google Meet, and Microsoft Teams. See login instructions [here](https://docs.google.com/spreadsheets/d/1mPv7KNgY9s4xKgqWKOYSE27-RdRJQZg1zn9V6VfSwWg/edit?gid=0#gid=0). The accounts are paid monthly.


---

Place your Azure private key (azure_rtc.pem) in C:\Users\chand\.ssh\ and ensure the captures folder exists at C:\Users\chand\captures.

⚡ That’s it! With these steps, you can spin up new VMs anytime and immediately start measuring RTC relays.
