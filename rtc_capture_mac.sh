#!/usr/bin/env bash
set -euo pipefail

# ===== Config (edit for your environment) =====
VM1_IP="20.246.106.73"
VM2_IP="20.246.106.73"
SSH_KEY="~/.ssh/id_ed25519"
USER="azureuser"
BASE_DIR="$HOME/captures" # put this capture folder in your working directory
REGION1="us-east"
REGION2="us-east"
APP="zoom" # zoom, whatsapp, messenger, discord, facetime, teams, googlemeet
# Capture interface on VM:
# - Use 'any' to capture both wg0 (inner RTP) and eth0 (NATed public relay) simultaneously.
# - Optionally set to 'wg0' for inner-only, or 'eth0' for public-only.
IFACE="any"
# If your remote API uses an API key, fill it here; otherwise leave empty
API_KEY=""
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

# ===== P2P control (force relay) =====
# When both phones connect to the same VM via WireGuard, apps may use P2P over wg0 (10.8.0.2<->10.8.0.3).
# Only enable P2P blocking automatically when both VM IPs are the same.
if [[ "${VM1_IP}" == "${VM2_IP}" ]]; then
	P2P_BLOCK="1"
else
	P2P_BLOCK="0"
fi

# ===== Prepare working directory =====
mkdir -p "$BASE_DIR"
# Hierarchy: $BASE_DIR/$APP/$REGION1-$REGION2/$REP_NO
app_dir="${BASE_DIR}/${APP}"
region_dir="${app_dir}/${REGION1}-${REGION2}"
mkdir -p "$region_dir"
# Determine next repetition number under the region directory
rep_no=$(find "$region_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
rep_no=$((rep_no + 1))
RUN_FOLDER="${region_dir}/${rep_no}"
mkdir -p "$RUN_FOLDER"

local_pcap1="${RUN_FOLDER}/${REGION1}-${REGION2}-vm1.pcap"
local_pcap2="${RUN_FOLDER}/${REGION1}-${REGION2}-vm2.pcap"
local_txt="${RUN_FOLDER}/${REGION1}-${REGION2}-analysis.txt"

# Helper: POST with optional API_KEY header
curl_post() {
	local url="$1"
	if [[ -n "${API_KEY}" ]]; then
		curl -sS -X POST -H "X-API-Key: ${API_KEY}" "$url"
	else
		curl -sS -X POST "$url"
	fi
}

SAME_VM="0"
if [[ "${VM1_IP}" == "${VM2_IP}" ]]; then
	SAME_VM="1"
fi

echo ">>> Starting capture on both VMs..."
# Optionally force relay by blocking wg0<->wg0 forwarding (P2P) on both VMs
# Activate only when both phones are on the same VM (VM1_IP == VM2_IP)
if [[ "${P2P_BLOCK}" == "1" && "${VM1_IP}" == "${VM2_IP}" ]]; then
	echo ">>> Enforcing anti-P2P (drop wg0<->wg0 forwarding) on both VMs..."
	for ip in "$VM1_IP" "$VM2_IP"; do
		ssh -i "$SSH_KEY" $SSH_OPTS "${USER}@${ip}" \
			"sudo iptables -C FORWARD -i wg0 -o wg0 -j DROP 2>/dev/null || sudo iptables -I FORWARD 1 -i wg0 -o wg0 -j DROP"
	done
fi
if [[ "${P2P_BLOCK}" == "1" ]]; then
	# same-host scenario: explicitly capture on IFACE (e.g., wg0/any)
	curl_post "http://${VM1_IP}:5000/start?iface=${IFACE}" >/dev/null
	# 如果是同一台 VM，就只启动一次
	if [[ "${SAME_VM}" != "1" ]]; then
		curl_post "http://${VM2_IP}:5000/start?iface=${IFACE}" >/dev/null
	fi
else
	# cross-VM scenario: use API default iface on each VM
	curl_post "http://${VM1_IP}:5000/start" >/dev/null
	if [[ "${SAME_VM}" != "1" ]]; then
		curl_post "http://${VM2_IP}:5000/start" >/dev/null
	fi
fi

echo ">>> Capture running for 30 seconds..."
sleep 20
for i in $(seq 10 -1 1); do
	echo "   ${i}s remaining..."
	sleep 1
done
# Audible bell notification
printf "\a" || true
echo ">>> 30 seconds RTC traffic collected. Time to end collection."

echo ">>> Stopping capture on both VMs..."
stop1=$(curl_post "http://${VM1_IP}:5000/stop" || true)
if [[ "${SAME_VM}" != "1" ]]; then
	stop2=$(curl_post "http://${VM2_IP}:5000/stop" || true)
else
	stop2=""
fi

# Extract remote pcap path (the /stop response contains file=<path>)
pcap1=$(printf "%s" "$stop1" | sed -n 's/.*file=\(.*\)$/\1/p' | tr -d '\r')
pcap2=$(printf "%s" "$stop2" | sed -n 's/.*file=\(.*\)$/\1/p' | tr -d '\r')

echo "VM1 latest pcap: ${pcap1}"
if [[ -n "${pcap2}" ]]; then
	echo "VM2 latest pcap: ${pcap2}"
fi

echo ">>> Downloading PCAP files..."
scp -i "$SSH_KEY" $SSH_OPTS "${USER}@${VM1_IP}:${pcap1}" "$local_pcap1"
if [[ -n "${pcap2}" ]]; then
	scp -i "$SSH_KEY" $SSH_OPTS "${USER}@${VM2_IP}:${pcap2}" "$local_pcap2"
fi



echo ">>> Running local DPI (check_dpi.py) on downloaded PCAPs..."
# Activate local virtualenv if available; otherwise fall back to system python3
if [ -f "$HOME/.venvs/rtcproxy/bin/activate" ]; then
	. "$HOME/.venvs/rtcproxy/bin/activate"
	PY_BIN="python"
else
	PY_BIN="python3"
fi

latency_summary=""
vm1_relay=""
vm2_relay=""
vm_relay=""

if [[ "${P2P_BLOCK}" == "1" ]]; then
	# Same-host scenario: use single pcap with same-host analyzer
	same_raw=$($PY_BIN /Users/apple/Documents/RTC/RTC_relay_infra/new/rtcproxy/check_dpi_same_host.py --pcap "$local_pcap1" 2>&1 || true)
	# Prefer relay from same_host analyzer (it supports SLL/SLL2)
	vm_relay=$(printf "%s\n" "$same_raw" | awk '/^Relay IPs \(from RTP flows\):/{show=1; next} show && /packets=/{print; exit}')
	# Fallback: if still empty, try generic DPI once
	if [[ -z "${vm_relay}" ]]; then
		vm_raw=$($PY_BIN /Users/apple/Documents/RTC/RTC_relay_infra/new/rtcproxy/check_dpi.py --pcap "$local_pcap1" 2>&1 || true)
		vm_relay=$(printf "%s\n" "$vm_raw" | awk '/^Relay IPs \(from RTP flows\):/{show=1; next} show && /packets=/{print; exit}')
	fi
	latency_summary=$(printf "%s\n" "$same_raw" | grep -E '^(Latency|Estimated RTT)' || true)
else
	# Two-host scenario: use two pcaps with cross-end analyzer
	vm1_raw=$($PY_BIN /Users/apple/Documents/RTC/RTC_relay_infra/new/rtcproxy/check_dpi.py --pcap "$local_pcap1" 2>&1 || true)
	vm2_raw=$($PY_BIN /Users/apple/Documents/RTC/RTC_relay_infra/new/rtcproxy/check_dpi.py --pcap "$local_pcap2" 2>&1 || true)
	# Take the first line of Relay list (check_dpi.py filters private IPs and sorts by occurrences desc)
	vm1_relay=$(printf "%s\n" "$vm1_raw" | awk '/^Relay IPs \(from RTP flows\):/{show=1; next} show && /packets=/{print; exit}')
	vm2_relay=$(printf "%s\n" "$vm2_raw" | awk '/^Relay IPs \(from RTP flows\):/{show=1; next} show && /packets=/{print; exit}')
	# Use both PCAPs together to compute one-way latency and estimated RTT
	both_raw=$($PY_BIN /Users/apple/Documents/RTC/RTC_relay_infra/new/rtcproxy/check_dpi.py --pcap "$local_pcap1" "$local_pcap2" 2>&1 || true)
	latency_summary=$(printf "%s\n" "$both_raw" | grep -E '^(Latency|Estimated RTT)' || true)
fi

# Compose the final summary into analysis.txt and also print to console
{
	# Print relay lines only if detected
	if [[ "${P2P_BLOCK}" == "1" ]]; then
		[ -n "${vm_relay}" ] && echo "VM1 relay: ${vm_relay}"
	else
		[ -n "${vm1_relay}" ] && echo "VM1 relay: ${vm1_relay}"
		[ -n "${vm2_relay}" ] && echo "VM2 relay: ${vm2_relay}"
	fi
	# Print latency/RTT lines only if present
	[ -n "${latency_summary}" ] && printf "%s\n" "$latency_summary"
} | tee "$local_txt"

echo ""
echo "========== ANALYSIS DONE =========="
echo "Saved to: $local_txt"
echo "==================================="
echo ""
echo "Captured files stored in: $RUN_FOLDER"


