#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# RTC Relay Measurement - One-key Installer (Sections 2–4 of README)
# - Installs system packages (Python, tcpdump, tshark, WireGuard, qrencode, etc.)
# - Deploys rtcproxy API to /opt/rtcproxy with a venv and systemd service
# - Configures WireGuard server (wg0) + NAT + forwarding + two phone clients
# - Opens UFW ports 22/tcp, 5000/tcp, 51820/udp
# Tested on Ubuntu 20.04/22.04. Root not required; sudo will be used.
# =============================================================================

# ---------- Helpers ----------
log() { printf "\n=== %s ===\n" "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

detect_pkg_mgr() {
	if command -v apt-get >/dev/null 2>&1; then
		echo "apt"
	elif command -v dnf >/dev/null 2>&1; then
		echo "dnf"
	elif command -v yum >/dev/null 2>&1; then
		echo "yum"
	else
		die "Unsupported OS: need apt, dnf or yum."
	fi
}

SERVICE_USER="${SUDO_USER:-$USER}"
if [ -z "${SERVICE_USER}" ] || [ "${SERVICE_USER}" = "root" ]; then
	# Fall back to azureuser if running as root without SUDO_USER
	SERVICE_USER="${SERVICE_USER:-azureuser}"
fi

# Try to get HOME dir of service user
HOME_DIR="$(getent passwd "${SERVICE_USER}" 2>/dev/null | cut -d: -f6 || true)"
[ -z "${HOME_DIR}" ] && HOME_DIR="/home/${SERVICE_USER}"

PKG_MGR="$(detect_pkg_mgr)"

# ---------- 2) Install Dependencies on VM ----------
log "Installing system dependencies (this may take a while)..."
case "${PKG_MGR}" in
	apt)
		sudo apt-get update -y
		sudo apt-get upgrade -y
		# Note: iptables-persistent/netfilter-persistent conflict with ufw on Ubuntu 24.04+
		# They are not required because WireGuard PostUp/PostDown handle rules dynamically.
		sudo apt-get install -y \
			python3 python3-pip python3-venv git curl jq \
			wireguard wireguard-tools qrencode whois \
			tcpdump tshark iproute2 \
			ufw lsof tmux
		;;
	dnf|yum)
		sudo ${PKG_MGR} -y install \
			python3 python3-pip python3-venv git curl jq \
			wireguard-tools qrencode whois \
			tcpdump wireshark-cli iproute \
			iptables-services \
			lsof tmux
		# UFW may not exist on RHEL-like; skip if unavailable
		;;
esac

# ---------- Python venv & repo deploy ----------
log "Preparing Python venv for rtcproxy..."
sudo -u "${SERVICE_USER}" mkdir -p "${HOME_DIR}/.venvs"
if [ ! -d "${HOME_DIR}/.venvs/rtcproxy" ]; then
	sudo -u "${SERVICE_USER}" python3 -m venv "${HOME_DIR}/.venvs/rtcproxy"
fi
VENVPY="${HOME_DIR}/.venvs/rtcproxy/bin/python"
VENPIP="${HOME_DIR}/.venvs/rtcproxy/bin/pip"

log "Deploying code to /opt/rtcproxy..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
sudo mkdir -p /opt/rtcproxy
sudo chown -R "${SERVICE_USER}:${SERVICE_USER}" /opt/rtcproxy

# If current script is inside repo with api.py, prefer copying; else clone
if [ -f "${SCRIPT_DIR}/api.py" ] && [ -f "${SCRIPT_DIR}/requirements.txt" ]; then
	rsync -a --delete "${SCRIPT_DIR}/" /opt/rtcproxy/
else
	if [ ! -f /opt/rtcproxy/api.py ]; then
		# Fallback to GitHub clone if /opt/rtcproxy is empty
		sudo -u "${SERVICE_USER}" git clone https://github.com/chandanacharithap/rtcproxy.git /opt/rtcproxy
	fi
fi

log "Installing Python dependencies..."
sudo -u "${SERVICE_USER}" "${VENPIP}" install --upgrade pip
sudo -u "${SERVICE_USER}" "${VENPIP}" install -r /opt/rtcproxy/requirements.txt

# ---------- tcpdump capability & capture dir ----------
log "Configuring tcpdump capabilities and capture directory..."
if command -v setcap >/dev/null 2>&1; then
	sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v tcpdump)" || true
fi
sudo mkdir -p /var/log/rtc
sudo chown "${SERVICE_USER}:${SERVICE_USER}" /var/log/rtc
sudo chmod 775 /var/log/rtc

# ---------- systemd service for API ----------
log "Creating systemd service rtcproxy.service..."
sudo tee /etc/default/rtcproxy >/dev/null <<'ENVEOF'
# Optional overrides for rtcproxy/api.py
RTC_API_BIND=0.0.0.0
RTC_API_PORT=5000
RTC_IFACE=eth0
# RTC_API_KEY=your_secret_here
ENVEOF

sudo tee /etc/systemd/system/rtcproxy.service >/dev/null <<EOF
[Unit]
Description=RTC Capture API
After=network-online.target
Wants=network-online.target

[Service]
User=${SERVICE_USER}
EnvironmentFile=-/etc/default/rtcproxy
WorkingDirectory=/opt/rtcproxy
ExecStart=${VENVPY} /opt/rtcproxy/api.py
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable rtcproxy
sudo systemctl restart rtcproxy || sudo systemctl start rtcproxy
sleep 1
sudo systemctl --no-pager -l status rtcproxy || true

# ---------- UFW rules ----------
if command -v ufw >/dev/null 2>&1; then
	log "Configuring UFW (5000/tcp, 51820/udp, 22/tcp)..."
	sudo ufw allow 22/tcp || true
	sudo ufw allow 5000/tcp || true
	sudo ufw allow 51820/udp || true
	yes | sudo ufw enable || true
	sudo ufw status numbered || true
fi

# ---------- 4) WireGuard Setup (server + two clients) ----------
log "Configuring WireGuard server and phone clients..."
WG_IF="wg0"
WG_DIR="/etc/wireguard"
KEEPALIVE="25"
DNS_ADDR="1.1.1.1"

sudo mkdir -p "${WG_DIR}"
sudo chmod 700 "${WG_DIR}"

# Generate keys if missing (idempotent)
if [ ! -f "${WG_DIR}/server_private.key" ]; then
	sudo bash -c "umask 077 && wg genkey | tee '${WG_DIR}/server_private.key' | wg pubkey > '${WG_DIR}/server_public.key'"
fi
if [ ! -f "${WG_DIR}/phone1_private.key" ]; then
	sudo bash -c "umask 077 && wg genkey | tee '${WG_DIR}/phone1_private.key' | wg pubkey > '${WG_DIR}/phone1_public.key'"
fi
if [ ! -f "${WG_DIR}/phone2_private.key" ]; then
	sudo bash -c "umask 077 && wg genkey | tee '${WG_DIR}/phone2_private.key' | wg pubkey > '${WG_DIR}/phone2_public.key'"
fi

SERVER_PRIV="$(sudo cat "${WG_DIR}/server_private.key")"
SERVER_PUB="$(sudo cat "${WG_DIR}/server_public.key")"
P1_PRIV="$(sudo cat "${WG_DIR}/phone1_private.key")"
P1_PUB="$(sudo cat "${WG_DIR}/phone1_public.key")"
P2_PRIV="$(sudo cat "${WG_DIR}/phone2_private.key")"
P2_PUB="$(sudo cat "${WG_DIR}/phone2_public.key")"

SERVER_ADDR="10.8.0.1/24"
P1_ADDR="10.8.0.2/24"
P2_ADDR="10.8.0.3/24"

# Routing & rp_filter sysctls
sudo tee /etc/sysctl.d/99-wg-routing.conf >/dev/null <<'SYS'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
SYS
sudo sysctl --system >/dev/null
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
sudo sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
sudo sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sudo sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null

# Detect egress NIC and public endpoint
EGRESS_IF="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
[ -z "${EGRESS_IF}" ] && EGRESS_IF="eth0"
ENDPOINT="$(curl -s ifconfig.me 2>/dev/null || echo "<YOUR_PUBLIC_IP>"):51820"

# Server config
sudo tee "${WG_DIR}/${WG_IF}.conf" >/dev/null <<EOF
[Interface]
PrivateKey = ${SERVER_PRIV}
Address    = ${SERVER_ADDR}
ListenPort = 51820
MTU        = 1380

# NAT + FORWARD accept + MSS clamp
PostUp   = iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ${EGRESS_IF} -j MASQUERADE
PostUp   = iptables -A FORWARD -i ${WG_IF} -j ACCEPT
PostUp   = iptables -A FORWARD -o ${WG_IF} -j ACCEPT
PostUp   = iptables -t mangle -A FORWARD -i ${WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o ${EGRESS_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_IF} -j ACCEPT
PostDown = iptables -D FORWARD -o ${WG_IF} -j ACCEPT
PostDown = iptables -t mangle -D FORWARD -i ${WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

[Peer]
# Phone 1
PublicKey  = ${P1_PUB}
AllowedIPs = 10.8.0.2/32
PersistentKeepalive = ${KEEPALIVE}

[Peer]
# Phone 2
PublicKey  = ${P2_PUB}
AllowedIPs = 10.8.0.3/32
PersistentKeepalive = ${KEEPALIVE}
EOF

# Phone client configs
sudo tee "${WG_DIR}/phone1.conf" >/dev/null <<EOF
[Interface]
PrivateKey = ${P1_PRIV}
Address    = ${P1_ADDR}
DNS        = ${DNS_ADDR}

[Peer]
PublicKey  = ${SERVER_PUB}
Endpoint   = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = ${KEEPALIVE}
EOF

sudo tee "${WG_DIR}/phone2.conf" >/dev/null <<EOF
[Interface]
PrivateKey = ${P2_PRIV}
Address    = ${P2_ADDR}
DNS        = ${DNS_ADDR}

[Peer]
PublicKey  = ${SERVER_PUB}
Endpoint   = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = ${KEEPALIVE}
EOF

# Harden permissions & enable service
sudo chown root:root \
	"${WG_DIR}/wg0.conf" \
	"${WG_DIR}/phone1.conf" \
	"${WG_DIR}/phone2.conf" \
	"${WG_DIR}/server_private.key" \
	"${WG_DIR}/server_public.key" \
	"${WG_DIR}/phone1_private.key" \
	"${WG_DIR}/phone1_public.key" \
	"${WG_DIR}/phone2_private.key" \
	"${WG_DIR}/phone2_public.key"
sudo chmod 777 \
	"${WG_DIR}/wg0.conf" \
	"${WG_DIR}/phone1.conf" \
	"${WG_DIR}/phone2.conf" \
	"${WG_DIR}/server_private.key" \
	"${WG_DIR}/server_public.key" \
	"${WG_DIR}/phone1_private.key" \
	"${WG_DIR}/phone1_public.key" \
	"${WG_DIR}/phone2_private.key" \
	"${WG_DIR}/phone2_public.key"
sudo systemctl enable "wg-quick@${WG_IF}"
sudo systemctl restart "wg-quick@${WG_IF}" || sudo systemctl start "wg-quick@${WG_IF}"

sudo chmod 777 "${WG_DIR}"

# Show QR codes (best-effort)
log "WireGuard phone configs (scan these in the WireGuard mobile app)"
echo '=========== Phone 1 (scan) ==========='
sudo qrencode -t ansiutf8 < "${WG_DIR}/phone1.conf" || true
echo '=========== Phone 2 (scan) ==========='
sudo qrencode -t ansiutf8 < "${WG_DIR}/phone2.conf" || true

# ---------- Done ----------
log "Installation complete."
cat <<OUT
What next:
- Verify API:   curl -sS http://127.0.0.1:5000/status
- Start/Stop:   curl -sS -X POST http://127.0.0.1:5000/start ; curl -sS -X POST http://127.0.0.1:5000/stop
- Logs:         sudo journalctl -u rtcproxy -e -n 100 --no-pager
- Capture dir:  ls -l /var/log/rtc
- QR again:     sudo qrencode -t ansiutf8 < /etc/wireguard/phone1.conf
- Endpoint:     Public IP autodetected as ${ENDPOINT}. Edit /etc/wireguard/phone*.conf if needed.
- Env override: Edit /etc/default/rtcproxy (e.g. RTC_API_KEY=xxx) then: sudo systemctl restart rtcproxy
OUT