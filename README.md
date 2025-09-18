# RTC Proxy Lab – Quick Start (FINAL)

**Prove these three things:**
- Phone exits the Internet from **VM1’s IP** (WireGuard).
- Laptop exits the Internet from **VM2’s IP** (WireGuard).
- WebRTC call relays via **TURN on VM2** (see `type=relay` + capture).

---

## 1) Azure (Portal)
- RG: `rtc-lab-rg`
- Create **two** Ubuntu 22.04 VMs with **Public IP**: `vm1-wireguard`, `vm2-turn`
- NSG rules:
  - **VM1**: UDP `51820`, TCP `22`
  - **VM2**: UDP `51820`, TCP `22`, UDP **3478**, TCP **3478**, UDP **49160–49200`

---

## 2) VM1 (WireGuard for PHONE)
```bash
ssh -i <KEY> azureuser@<VM1_IP>
sudo apt update && sudo apt -y install wireguard qrencode netfilter-persistent iptables-persistent

umask 077
# Generate server + phone keys (needed for QR and server peer section)
wg genkey | tee ~/v1_server.key | wg pubkey > ~/v1_server.pub
wg genkey | tee ~/phone.key     | wg pubkey > ~/phone.pub
SERVER_PRIV=$(cat ~/v1_server.key); SERVER_PUB=$(cat ~/v1_server.pub)
PHONE_PRIV=$(cat ~/phone.key);    PHONE_PUB=$(cat ~/phone.pub)

echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-wg.conf
sudo sysctl --system

WAN=eth0
sudo bash -c 'cat >/etc/wireguard/wg0.conf' <<EOF
[Interface]
Address = 10.8.1.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIV}
PostUp   = iptables -t nat -A POSTROUTING -o ${WAN} -j MASQUERADE; iptables -A FORWARD -i wg0 -o ${WAN} -j ACCEPT; iptables -A FORWARD -i ${WAN} -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${WAN} -j MASQUERADE; iptables -D FORWARD -i wg0 -o ${WAN} -j ACCEPT; iptables -D FORWARD -i ${WAN} -m state --state RELATED,ESTABLISHED -j ACCEPT
[Peer]
PublicKey = ${PHONE_PUB}
AllowedIPs = 10.8.1.2/32
EOF
sudo systemctl enable --now wg-quick@wg0
sudo netfilter-persistent save

VM1_PUBLIC_IP=$(curl -s ifconfig.me)
cat <<EOF > ~/phone.conf
[Interface]
PrivateKey = ${PHONE_PRIV}
Address = 10.8.1.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${VM1_PUBLIC_IP}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
qrencode -t ansiutf8 < ~/phone.conf
```
**Phone** → WireGuard app → Add (QR) → **ON** → “what’s my IP” = **VM1_IP** ✅

---

## 3) VM2 (WireGuard for LAPTOP + TURN)
```bash
ssh -i <KEY> azureuser@<VM2_IP>
sudo apt update && sudo apt -y install wireguard netfilter-persistent iptables-persistent coturn

umask 077
wg genkey | tee ~/v2_server.key | wg pubkey > ~/v2_server.pub
wg genkey | tee ~/laptop.key    | wg pubkey > ~/laptop.pub
SERVER2_PRIV=$(cat ~/v2_server.key); SERVER2_PUB=$(cat ~/v2_server.pub)
LAPTOP_PRIV=$(cat ~/laptop.key);    LAPTOP_PUB=$(cat ~/laptop.pub)

echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/98-wg.conf
sudo sysctl --system

WAN=eth0
sudo bash -c 'cat >/etc/wireguard/wg0.conf' <<EOF
[Interface]
Address = 10.8.2.1/24
ListenPort = 51820
PrivateKey = ${SERVER2_PRIV}
PostUp   = iptables -t nat -A POSTROUTING -o ${WAN} -j MASQUERADE; iptables -A FORWARD -i wg0 -o ${WAN} -j ACCEPT; iptables -A FORWARD -i ${WAN} -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${WAN} -j MASQUERADE; iptables -D FORWARD -i wg0 -o ${WAN} -j ACCEPT; iptables -D FORWARD -i ${WAN} -m state --state RELATED,ESTABLISHED -j ACCEPT
[Peer]
PublicKey = ${LAPTOP_PUB}
AllowedIPs = 10.8.2.2/32
EOF
sudo systemctl enable --now wg-quick@wg0
sudo netfilter-persistent save

sudo bash -c 'cat >/etc/turnserver.conf' <<'EOF'
listening-port=3478
fingerprint
lt-cred-mech
realm=rtc.lab
user=labuser:supersecretpassword
no-tls
no-dtls
min-port=49160
max-port=49200
verbose
EOF
sudo systemctl enable coturn && sudo systemctl restart coturn

VM2_PUBLIC_IP=$(curl -s ifconfig.me); echo $VM2_PUBLIC_IP
```
**Laptop** → WireGuard app → Add tunnel with:
```
[Interface]
PrivateKey = <paste LAPTOP_PRIV>
Address = 10.8.2.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = <paste SERVER2_PUB>
Endpoint = <VM2_PUBLIC_IP>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```
Activate → “what’s my IP” = **VM2_IP** ✅

---

## 4) Capture API Workflow (CloudLab server + Phone + Laptop)

> Replace:
> - `MYSECRET` → your API key
> - `hp070.utah.cloudlab.us` (or `128.110.218.146`) → your CloudLab hostname/IP
> - `10.0.0.3` → your peer IP behind WireGuard

### A) On the CloudLab server (e.g., `hp070`)

**1) Bring up WireGuard**
```bash
sudo wg-quick up wg0
sudo wg
```

**2) Run the capture API (in tmux)**
```bash
sudo apt update && sudo apt install -y tmux
tmux new -s rtc

# repo & deps (if not already there)
sudo apt update && sudo apt install -y git python3-pip tcpdump tshark
cd /opt
sudo git clone https://github.com/chandanacharithap/rtcproxy.git
sudo chown -R $USER:$USER rtcproxy
cd /opt/rtcproxy/rtcproxy

# env + start (if your shell is bash, use 'export VAR=value' instead of 'setenv')
setenv RTC_API_KEY "MYSECRET"
setenv RTC_IFACE "wg0"
setenv RTC_PEER_IP "10.0.0.3"
sudo -E python3 api.py
```
- Detach: **Ctrl+B**, then **D**. Reattach: `tmux attach -t rtc`  
- If you see “Port 5000 in use”:
```bash
sudo lsof -i :5000
sudo fuser -k 5000/tcp
```

### B) On your phone
- WireGuard app → toggle your tunnel **ON** (Endpoint example: `hp070.utah.cloudlab.us:51820`).

### C) From your laptop (PowerShell)
```powershell
# Status
Invoke-WebRequest -Uri "http://hp070.utah.cloudlab.us:5000/status" -Headers @{"X-API-Key"="MYSECRET"}

# Start capture (place your call while VPN is ON)
Invoke-WebRequest -Uri "http://hp070.utah.cloudlab.us:5000/start" -Method POST -Headers @{"X-API-Key"="MYSECRET"}

# Stop capture
Invoke-WebRequest -Uri "http://hp070.utah.cloudlab.us:5000/stop" -Method POST -Headers @{"X-API-Key"="MYSECRET"}

# Download PCAP
Invoke-WebRequest -Uri "http://hp070.utah.cloudlab.us:5000/download?file=current" -Headers @{"X-API-Key"="MYSECRET"} -OutFile "rtc_capture.pcap"
```
Open `rtc_capture.pcap` in Wireshark; handy filter: `stun or rtp or quic`.

### D) Extras
```bash
# Restart wg after edits
sudo wg-quick down wg0 && sudo wg-quick up wg0

# Confirm a PCAP exists
ls -lh /var/log/rtc/rtc-*.pcap
```
```powershell
# Download a specific PCAP
Invoke-WebRequest -Uri "http://hp070.utah.cloudlab.us:5000/download?file=/var/log/rtc/rtc-20250917-012628.pcap" -Headers @{"X-API-Key"="MYSECRET"} -OutFile "rtc_capture.pcap"
```

**DPI check & lookups (on server)**
```bash
cd /opt/rtcproxy/rtcproxy
python3 check_dpi.py --pcap /var/log/rtc/rtc-20250917-012628.pcap
tshark -r /var/log/rtc/rtc-20250917-012628.pcap -Y "stun" -T fields -e ip.src -e ip.dst | head -n 30
python3 lookupip.py 31.13.66.53
python3 lookupip.py 157.240.245.62
```

---

## 5) Prove TURN relay (WebRTC)
On **both** phone + laptop, open the **Trickle ICE** sample and add:
- `turn:<VM2_PUBLIC_IP>:3478?transport=udp`
- `turn:<VM2_PUBLIC_IP>:3478?transport=tcp`
- Username: `labuser` | Password: `supersecretpassword`

You should see ICE candidates with **`type=relay`**, IP = **<VM2_PUBLIC_IP>**, port **49160–49200**. ✅

---

## Troubleshooting (super short)
- No VPN? Check NSG ports, `sudo wg show`, `sysctl net.ipv4.ip_forward`, iptables PostUp rules.
- No relay? Confirm TURN IP/creds, NSG ports 3478 UDP/TCP + 49160–49200 UDP, try `?transport=tcp`, restart coturn.
- API busy? Kill port 5000 (see above).

---

## GitHub (optional)
```bash
mkdir rtc-proxy-lab && cd rtc-proxy-lab
printf "# RTC Proxy Lab\n" > README.md
echo "*.key
*.pem
wg0.conf
turnserver.conf" > .gitignore
git init && git add . && git commit -m "init"
# push to a new private repo (use GitHub or gh cli)
```
