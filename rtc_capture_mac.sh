#!/usr/bin/env bash
set -euo pipefail

# ===== Config (edit for your environment) =====
VM1_IP="20.246.106.73"
VM2_IP="172.185.146.233"
SSH_KEY="~/.ssh/id_ed25519"
USER="azureuser"
BASE_DIR="$HOME/captures" # put this capture folder in your working directory
REGION1="us-east"
REGION2="west-us"
APP="zoom" # zoom, whatsapp, messenger, discord, facetime, teams, googlemeet
# If your remote API uses an API key, fill it here; otherwise leave empty
API_KEY=""
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

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

echo ">>> Starting capture on both VMs..."
curl_post "http://${VM1_IP}:5000/start" >/dev/null
curl_post "http://${VM2_IP}:5000/start" >/dev/null

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
stop2=$(curl_post "http://${VM2_IP}:5000/stop" || true)

# Extract remote pcap path (the /stop response contains file=<path>)
pcap1=$(printf "%s" "$stop1" | sed -n 's/.*file=\(.*\)$/\1/p' | tr -d '\r')
pcap2=$(printf "%s" "$stop2" | sed -n 's/.*file=\(.*\)$/\1/p' | tr -d '\r')

echo "VM1 latest pcap: ${pcap1}"
echo "VM2 latest pcap: ${pcap2}"

echo ">>> Downloading PCAP files..."
scp -i "$SSH_KEY" $SSH_OPTS "${USER}@${VM1_IP}:${pcap1}" "$local_pcap1"
scp -i "$SSH_KEY" $SSH_OPTS "${USER}@${VM2_IP}:${pcap2}" "$local_pcap2"



echo ">>> Running local DPI (check_dpi.py) on downloaded PCAPs..."
# Activate local virtualenv if available; otherwise fall back to system python3
if [ -f "$HOME/.venvs/rtcproxy/bin/activate" ]; then
	. "$HOME/.venvs/rtcproxy/bin/activate"
	PY_BIN="python"
else
	PY_BIN="python3"
fi

# For each PCAP, compute its own relay summary
vm1_raw=$($PY_BIN /Users/apple/Documents/RTC/RTC_relay_infra/new/rtcproxy/check_dpi.py --pcap "$local_pcap1" 2>&1 || true)
vm2_raw=$($PY_BIN /Users/apple/Documents/RTC/RTC_relay_infra/new/rtcproxy/check_dpi.py --pcap "$local_pcap2" 2>&1 || true)
# Take the first line of Relay list (check_dpi.py filters private IPs and sorts by occurrences desc)
vm1_relay=$(printf "%s\n" "$vm1_raw" | awk '/^Relay IPs \(from RTP flows\):/{show=1; next} show && /packets=/{print; exit}')
vm2_relay=$(printf "%s\n" "$vm2_raw" | awk '/^Relay IPs \(from RTP flows\):/{show=1; next} show && /packets=/{print; exit}')

# Use both PCAPs together to compute one-way latency and estimated RTT
both_raw=$($PY_BIN /Users/apple/Documents/RTC/RTC_relay_infra/new/rtcproxy/check_dpi.py --pcap "$local_pcap1" "$local_pcap2" 2>&1 || true)
latency_summary=$(printf "%s\n" "$both_raw" | grep -E '^(Latency|Estimated RTT)' || true)

# Compose the final summary into analysis.txt and also print to console
{
	echo "VM1 relay: ${vm1_relay:-N/A}"
	echo "VM2 relay: ${vm2_relay:-N/A}"
	echo ""
	if [ -n "$latency_summary" ]; then
		printf "%s\n" "$latency_summary"
	else
		echo "Latency summary: N/A"
	fi
} | tee "$local_txt"

echo ""
echo "========== ANALYSIS DONE =========="
echo "Saved to: $local_txt"
echo "==================================="
echo ""
echo "Captured files stored in: $RUN_FOLDER"


