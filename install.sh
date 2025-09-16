#!/usr/bin/env bash
set -euo pipefail

# === Basic packages ===
sudo apt update
sudo apt -y upgrade
sudo apt install -y wireguard wireguard-tools tcpdump iptables git python3-pip ufw tmux tshark

# Python deps for API + dpi
pip3 install --break-system-packages -U flask requests dpkt pyshark

# === Enable IP forwarding ===
sudo sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
sudo sed -i '/^net.ipv6.conf.all.forwarding/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# === Repo checkout/update ===
sudo mkdir -p /opt/rtc-api
sudo chown "$USER":"$USER" /opt/rtc-api
if [ ! -d /opt/rtc-api/.git ]; then
  git clone https://github.com/chandanacharithap/rtcproxy /opt/rtc-api
else
  cd /opt/rtc-api && git pull
fi

# === UFW basics (keep SSH+WG+API open) ===
sudo ufw allow 22/tcp || true
sudo ufw allow 51820/udp || true
sudo ufw allow 5000/tcp || true
echo "y" | sudo ufw enable || true
sudo ufw status numbered

echo
echo "======================"
echo "Install complete."
echo "Next steps:"
echo "1) Create /etc/wireguard/wg0.conf (use your server key and correct NIC in PostUp)."
echo "   Example in repo: wg0.conf.example (add your keys & interface)."
echo "2) Bring WG up:   sudo wg-quick up wg0"
echo "3) Run API:       cd /opt/rtc-api && setenv RTC_API_KEY 'MYSECRET' && setenv RTC_IFACE 'wg0' && setenv RTC_PEER_IP '10.0.0.3' && sudo -E python3 api.py"
echo "4) Or enable systemd service below."
