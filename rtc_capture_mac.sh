#!/usr/bin/env bash
set -euo pipefail

# ===== Config (edit for your environment) =====
# You only need to modify REGION1 / REGION2; VM1_IP and VM2_IP will be mapped automatically based on the region name.
# If an unknown region is encountered, an error will be shown prompting you to add it to the mapping function.
# If you do want to override the IP manually, you can export the environment variables VM1_IP/VM2_IP before running.
SSH_KEY="~/.ssh/id_ed25519"
USER="azureuser"
BASE_DIR="$HOME/captures" # put this capture folder in your working directory
REGION1="canada-east"
REGION2="canada-east"
APP="zoom" # zoom, whatsapp, messenger, discord, facetime, teams, googlemeet
# Capture interface on VM:
# - Use 'any' to capture both wg0 (inner RTP) and eth0 (NATed public relay) simultaneously.
# - Optionally set to 'wg0' for inner-only, or 'eth0' for public-only.
IFACE="any"
# If your remote API uses an API key, fill it here; otherwise leave empty
API_KEY=""
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

# ===== 区域名 -> IP 映射（已内置 13 个地区；支持多种写法） =====
get_ip_for_region() {
	local region="$1"
	# 归一化：小写、去掉前缀 rtc-、空格/下划线转为短横线
	local key
	key="$(printf "%s" "$region" | tr '[:upper:]' '[:lower:]')"
	key="${key#rtc-}"
	key="${key// /-}"
	key="${key//_/-}"
	case "$key" in
		# us-east
		"us-east"|"east-us") echo "172.200.238.240" ;;
		# central-us
		"central-us"|"us-central") echo "40.78.172.213" ;;
		# west-us
		"west-us"|"us-west") echo "172.184.159.0" ;;
		# south-central-us
		"south-central-us"|"us-south-central"|"southcentral-us") echo "20.114.65.229" ;;
		# chile-central
		"chile-central"|"central-chile") echo "57.156.58.197" ;;
		# uk-south
		"uk-south"|"south-uk") echo "172.166.200.53" ;;
		# poland-central
		"poland-central"|"central-poland") echo "20.215.249.204" ;;
		# uae-north
		"uae-north"|"north-uae") echo "20.74.220.56" ;;
		# japan-east
		"japan-east"|"east-japan") echo "4.189.136.130" ;;
		# central-india
		"central-india"|"india-central") echo "98.70.125.186" ;;
		# south-africa-north
		"south-africa-north"|"southafrica-north"|"north-south-africa") echo "40.120.25.50" ;;
		# australia-east
		"australia-east"|"east-australia") echo "68.218.11.9" ;;
		# malaysia-west
		"malaysia-west"|"west-malaysia") echo "85.211.199.90" ;;
		# canada-east
		"canada-east"|"east-canada") echo "4.239.98.217" ;;
		*) return 1 ;;
	esac
}

# 如果未通过环境变量显式指定 VM1_IP/VM2_IP，则根据区域名自动填充
: "${VM1_IP:=}"
: "${VM2_IP:=}"
if [[ -z "${VM1_IP}" ]]; then
	if ! VM1_IP="$(get_ip_for_region "${REGION1}")"; then
		echo "错误：未知区域名 '${REGION1}'。请在脚本函数 get_ip_for_region 中添加该区域到 IP 的映射。" >&2
		exit 1
	fi
fi
if [[ -z "${VM2_IP}" ]]; then
	if ! VM2_IP="$(get_ip_for_region "${REGION2}")"; then
		echo "错误：未知区域名 '${REGION2}'。请在脚本函数 get_ip_for_region 中添加该区域到 IP 的映射。" >&2
		exit 1
	fi
fi

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
# Ensure tcpdump has required capabilities on remote VMs before starting capture
for ip in "$VM1_IP" "$VM2_IP"; do
	ssh -i "$SSH_KEY" $SSH_OPTS "${USER}@${ip}" \
		"sudo setcap cap_net_raw,cap_net_admin+eip \$(command -v tcpdump) || sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump || true"
done
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


