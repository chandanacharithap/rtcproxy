# RTC Proxy Lab – Quick Start
---

## 1) Azure (Portal)
- RG: `rtc-lab-rg`
- Create **two** Ubuntu 22.04 VMs with **Public IP**: `vm1-wireguard`, `vm2-turn`
- NSG rules:
  - **VM1**: UDP `51820`, TCP `22`
  - **VM2**: UDP `51820`, TCP `22`, UDP **3478**, TCP **3478**, UDP **49160–49200**

---

## 2) VM1 (WireGuard for PHONE)
```bash
ssh -i <KEY> azureuser@<VM1_IP>
sudo apt update && sudo apt -y install wireguard qrencode netfilter-persistent iptables-persistent

umask 077
wg genkey | tee ~/v1_server.key | wg pubkey > ~/v1_server.pub
SERVER_PRIV=$(cat ~/v1_server.key); SERVER_PUB=$(cat ~/v1_server.pub)

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

## 4) Prove TURN relay (WebRTC)
Open **Trickle ICE** page on both phone + laptop. Add TURN:
- `turn:<VM2_PUBLIC_IP>:3478?transport=udp`
- `turn:<VM2_PUBLIC_IP>:3478?transport=tcp`
- Username: `labuser`  |  Password: `supersecretpassword`

Start the test. You should see ICE candidates with **`type=relay`** and IP = **VM2_PUBLIC_IP**, port **49160–49200**. ✅

---

## 5) Capture on laptop (Wireshark)
- Start WG tunnel (to VM2) **ON**
- Wireshark filter options:
  - `udp.port == 3478`
  - `ip.addr == <VM2_PUBLIC_IP> && udp.port >= 49160 && udp.port <= 49200`

You’ll see STUN/TURN to `:3478` and media to/from `49160–49200/udp`.

---

## Troubleshooting 
- No VPN? Check NSG ports, `sudo wg show`, `sysctl net.ipv4.ip_forward`, iptables PostUp rules.
- No relay? Confirm TURN IP/creds, NSG ports 3478 UDP/TCP + 49160–49200 UDP, try `?transport=tcp`, restart coturn.

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

That’s it. Phone on **VM1**, Laptop on **VM2**, TURN on VM2 = verified relay. 🚀
