#!/usr/bin/env bash
# rtc_capture-3.sh — Host & Client Zoom UITests + VM tcpdump/DPI (Test Plan aware)
# Save with LF line endings. Usage: bash ~/Downloads/rtc_capture-3.sh
set -euo pipefail

# --- ensure we are running under bash (not sh/zsh) ---
if [ -z "${BASH_VERSION:-}" ]; then exec /usr/bin/env bash "$0" "$@"; fi
# --- refuse CRLF early (occasionally happens when copying scripts) ---
if file "$0" | grep -qi 'CRLF'; then
  echo "[ERR] Script has Windows line endings (CRLF). Convert to LF and retry." >&2
  exit 1
fi

# ===================== CONFIG (edit as needed) =====================
# iPhones (device UDIDs)
HOST_DEVICE_ID="00008120-00107819262A601E"   # iPhoneChandana
CLIENT_DEVICE_ID="00008030-000E71900A12202E" # Patrick's iPhone

# Xcode project
XCODE_PROJECT="$HOME/Desktop/zoomautomation/wireguardZoomAutomation.xcodeproj"
SCHEME="wireguardZoomAutomation"
TEST_PLAN="wireguardZoomAutomation"          # your .xctestplan name
DERIVED="$HOME/Library/Developer/Xcode/DerivedData/rtc-dd"

# ---- Test identifiers (MATCH YOUR SWIFT CODE) ----
# xcodebuild format: <TestBundleTarget>/<TestClass>/<testMethod>
TEST_BUNDLE="ZoomDualUITests"
HOST_TEST_CLASS="ZoomDualUITests"
CLIENT_TEST_CLASS="ZoomDualUITests"
HOST_TEST_METHOD="testHost_RunAllTunnels"
CLIENT_TEST_METHOD="testClient_RunAllTunnels"
HOST_FILTER="${TEST_BUNDLE}/${HOST_TEST_CLASS}/${HOST_TEST_METHOD}"
CLIENT_FILTER="${TEST_BUNDLE}/${CLIENT_TEST_CLASS}/${CLIENT_TEST_METHOD}"

# WireGuard tunnels (must match Settings → VPN list text in the test if you vary them here)
HOST_TUNNEL="rtc-australia-east"
CLIENT_TUNNEL="rtc-central-us"

# Azure VMs (for tcpdump + DPI)
VMS=(
  "rtc-australia-east|20.211.147.9"
  "rtc-central-us|20.118.200.60"
  "rtc-japan-east|20.210.195.119"
  "rtc-germany-west-central|4.182.233.62"
)

SSH_KEY="$HOME/Downloads/azure_rtc.pem"
SSH_USER="azureuser"
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8)

REMOTE_DIR="/var/log/rtc"               # where pcaps are written on VM
REMOTE_DPI="/opt/rtcproxy/check_dpi.py" # DPI path on VM
PYTHON_BIN="python3"

# Your Swift keeps calls alive ~20s; add a buffer so we catch setup/teardown
CALL_SECONDS=25
EXTRA_CAPTURE_BUFFER=20                 # seconds after call to keep capturing

RUN_DIR="$HOME/Downloads/Captures/Zoom/run_$(date +%Y%m%d-%H%M%S)"
# ================================================================

say(){ echo -e "\033[1;36m>>> $*\033[0m"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*" >&2; }
err(){ echo -e "\033[1;31m[ERR]\033[0m  $*" >&2; }
need(){ command -v "$1" >/dev/null || { err "Missing: $1"; exit 1; }; }

need xcrun; need ssh; need scp; need /usr/bin/osascript
chmod 600 "$SSH_KEY" 2>/dev/null || true
mkdir -p "$RUN_DIR" "$DERIVED"

# ============ VM helpers ============
ensure_vm_tools() {
  local ip="$1"
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" "set -e
    sudo mkdir -p '$REMOTE_DIR'
    if ! command -v tcpdump >/dev/null 2>&1; then
      if command -v apt-get >/dev/null 2>&1; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump >/dev/null 2>&1 || true
      elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y tcpdump >/dev/null 2>&1 || true
      fi
    fi
  "
}

start_capture_vm() {
  local name="$1" ip="$2"
  say "[$name] start tcpdump"
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" "set -e
    sudo pkill tcpdump >/dev/null 2>&1 || true
    IFACE=\$(ip -o -4 route show to default 2>/dev/null | awk '{print \$5}' | head -1)
    [ -z \"\$IFACE\" ] && IFACE=\$(ip -o link show | awk -F': ' '!/lo/ {print \$2; exit}')
    sudo mkdir -p '$REMOTE_DIR'
    OUT=\$('$PYTHON_BIN' - <<'PY'
import time; print(time.strftime('rtc-%Y%m%d-%H%M%S.pcap'))
PY
)
    sudo nohup tcpdump -i \"\$IFACE\" -U -w \"$REMOTE_DIR/\$OUT\" >/dev/null 2>&1 & disown
  "
}

stop_capture_vm() {
  local name="$1" ip="$2"
  say "[$name] stop tcpdump"
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo pkill tcpdump >/dev/null 2>&1 || true"
}

last_pcap_vm() {
  local ip="$1"
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" "ls -t '$REMOTE_DIR'/*.pcap 2>/dev/null | head -1" || true
}

download_pcap() {
  local name="$1" ip="$2" pcap_remote="$3"
  local local_pcap="$RUN_DIR/${name}.pcap"
  scp "${SSH_OPTS[@]}" "$SSH_USER@$ip:$pcap_remote" "$local_pcap" >/dev/null 2>&1 || \
    warn "[$name] scp failed"
}

analyze_vm() {
  local name="$1" ip="$2" pcap_remote="$3"
  local out_txt="$RUN_DIR/${name}.txt"
  local relay country

  relay="$(ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" "$PYTHON_BIN '$REMOTE_DPI' --pcap '$pcap_remote' 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1" || true)"
  if [[ -n "${relay:-}" ]]; then
    if command -v curl >/dev/null 2>/dev/null; then
      country="$(curl -m 4 -fsS "https://ipapi.co/${relay}/country_name" 2>/dev/null || true)"
      [[ -z "$country" ]] && country="$(curl -m 4 -fsS "https://ipinfo.io/${relay}/country" 2>/dev/null || true)"
    fi
    [[ -z "$country" ]] && country="Unknown"
  else
    country="Unknown"
  fi

  {
    echo "vm: $name"
    echo "pcap: $pcap_remote"
    echo "relay_ip: ${relay:-N/A}"
    echo "country: $country"
    echo "generated_at: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  } > "$out_txt"

  if [[ -n "${relay:-}" ]]; then
    echo "[$name] Relay: $relay ($country)"
  else
    echo "[$name] Relay: N/A"
  fi
}

# ============ Xcode helpers ============
clean_build_once() {
  say "Clean + build (no runner)…"
  xcrun xcodebuild \
    -project "$XCODE_PROJECT" \
    -scheme "$SCHEME" \
    -destination "id=$HOST_DEVICE_ID" \
    -derivedDataPath "$DERIVED" \
    clean build \
    >/dev/null
}

# Write small per-tab scripts to /tmp to avoid nested quoting hell
write_tab_scripts() {
  local HOST_TMP="/tmp/rtc_host_cmd.$$_.sh"
  local CLNT_TMP="/tmp/rtc_client_cmd.$$_.sh"

  cat > "$HOST_TMP" <<SH
#!/usr/bin/env bash
set -euo pipefail
xcrun xcodebuild test \\
  -project "$XCODE_PROJECT" \\
  -scheme "$SCHEME" \\
  -destination "id=$HOST_DEVICE_ID" \\
  -derivedDataPath "$DERIVED" \\
  -testPlan "$TEST_PLAN" \\
  "-only-testing:$HOST_FILTER"
echo
echo "=== [Host automation done] ==="
SH

  cat > "$CLNT_TMP" <<SH
#!/usr/bin/env bash
set -euo pipefail
xcrun xcodebuild test \\
  -project "$XCODE_PROJECT" \\
  -scheme "$SCHEME" \\
  -destination "id=$CLIENT_DEVICE_ID" \\
  -derivedDataPath "$DERIVED" \\
  -testPlan "$TEST_PLAN" \\
  "-only-testing:$CLIENT_FILTER"
echo
echo "=== [Client automation done] ==="
SH

  chmod +x "$HOST_TMP" "$CLNT_TMP"
  echo "$HOST_TMP|$CLNT_TMP"
}

open_tabs_and_run() {
  local host_sh="$1" client_sh="$2"
  /usr/bin/osascript <<OSA
tell application "Terminal"
  activate
  do script "/bin/bash '$host_sh'"
  do script "/bin/bash '$client_sh'"
end tell
OSA
}

# ===================== MAIN =====================
main() {
  say "Run dir: $RUN_DIR"

  # Fresh build to avoid stale runners
  rm -rf "$DERIVED"
  clean_build_once

  # Pick VM IPs that match chosen tunnels (optional; independent of UI tests)
  local HOST_NAME="$HOST_TUNNEL" CLIENT_NAME="$CLIENT_TUNNEL"
  local HOST_IP="" CLIENT_IP=""
  for pair in "${VMS[@]}"; do
    IFS='|' read -r n ip <<<"$pair"
    [[ "$n" == "$HOST_NAME" ]] && HOST_IP="$ip"
    [[ "$n" == "$CLIENT_NAME" ]] && CLIENT_IP="$ip"
  done
  [[ -z "$HOST_IP"   ]] && HOST_IP="$(echo "${VMS[0]}" | cut -d'|' -f2)"
  [[ -z "$CLIENT_IP" ]] && CLIENT_IP="$(echo "${VMS[1]}" | cut -d'|' -f2)"

  say "=== Host=${HOST_NAME} (${HOST_IP}) ⇄ Client=${CLIENT_NAME} (${CLIENT_IP}) ==="

  ensure_vm_tools "$HOST_IP"
  ensure_vm_tools "$CLIENT_IP"

  start_capture_vm "$HOST_NAME" "$HOST_IP"
  start_capture_vm "$CLIENT_NAME" "$CLIENT_IP"

  say "Starting Host & Client UITests in Terminal tabs…"
  TMP_PAIR="$(write_tab_scripts)"
  HOST_TMP="${TMP_PAIR%%|*}"
  CLNT_TMP="${TMP_PAIR#*|}"
  open_tabs_and_run "$HOST_TMP" "$CLNT_TMP"

  local wait=$(( CALL_SECONDS + EXTRA_CAPTURE_BUFFER ))
  say "Capturing for ~${wait}s…"
  sleep "$wait"

  stop_capture_vm   "$HOST_NAME" "$HOST_IP"
  stop_capture_vm   "$CLIENT_NAME" "$CLIENT_IP"

  H_PCAP="$(last_pcap_vm "$HOST_IP" || true)"
  C_PCAP="$(last_pcap_vm "$CLIENT_IP" || true)"
  [[ -z "${H_PCAP:-}" ]] && warn "[$HOST_NAME] no pcap found"
  [[ -z "${C_PCAP:-}" ]] && warn "[$CLIENT_NAME] no pcap found"

  [[ -n "${H_PCAP:-}" ]] && download_pcap "$HOST_NAME" "$HOST_IP" "$H_PCAP"
  [[ -n "${C_PCAP:-}" ]] && download_pcap "$CLIENT_NAME" "$CLIENT_IP" "$C_PCAP"

  [[ -n "${H_PCAP:-}" ]] && analyze_vm  "$HOST_NAME" "$HOST_IP" "$H_PCAP"
  [[ -n "${C_PCAP:-}" ]] && analyze_vm  "$CLIENT_NAME" "$CLIENT_IP" "$C_PCAP"

  say "Done. Outputs in: $RUN_DIR"
  ls -lh "$RUN_DIR" || true
}

main "$@"
