#!/usr/bin/env bash
set -euo pipefail

# ===== Config (请根据你的环境修改) =====
VM1_IP="20.5.187.106"
VM2_IP="4.240.95.132"
SSH_KEY="~/.ssh/config/id_ed25519"
USER="azureuser"
BASE_DIR="$HOME/captures"
REGION1="australia-east"
REGION2="central-india"
# 如果你的远端 API 配置了密钥，这里填写；否则留空
API_KEY=""

# ===== 准备运行目录 =====
mkdir -p "$BASE_DIR"
# 统计现有 run 目录数量，生成新的 run 号
run_no=$(find "$BASE_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
run_no=$((run_no + 1))
RUN_FOLDER="${BASE_DIR}/${REGION1}-${REGION2}-run_${run_no}"
mkdir -p "$RUN_FOLDER"

local_pcap1="${RUN_FOLDER}/${REGION1}-${REGION2}-vm1.pcap"
local_pcap2="${RUN_FOLDER}/${REGION1}-${REGION2}-vm2.pcap"
local_txt="${RUN_FOLDER}/${REGION1}-${REGION2}-analysis.txt"

# ===== 确保远端 /opt/rtcproxy 为最新 =====
echo ">>> Updating /opt/rtcproxy on both VMs..."
remote_update_cmd='
set -e
if [ -d /opt/rtcproxy ] && [ -d /opt/rtcproxy/.git ]; then
  cd /opt/rtcproxy
  git fetch --all --prune --tags || true
  # 解析 origin 默认分支（如 origin/main）
  defref=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)
  defbranch=""
  if [ -n "$defref" ]; then
    defbranch="${defref#origin/}"
  else
    # 回退：优先 main，再 master
    if git show-ref --quiet --verify refs/remotes/origin/main; then
      defbranch="main"
    elif git show-ref --quiet --verify refs/remotes/origin/master; then
      defbranch="master"
    fi
  fi
  if [ -n "$defbranch" ]; then
    git reset --hard "origin/${defbranch}" || true
  else
    git pull --ff-only --rebase || true
  fi
  # 依赖尽量安装，不阻塞主流程
  if [ -f requirements.txt ]; then
    python3 -m pip install -r requirements.txt >/dev/null 2>&1 || true
  fi
else
  echo "/opt/rtcproxy not a git repo; skip update."
fi
'
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${USER}@${VM1_IP}" "bash -lc '$remote_update_cmd'" >/dev/null 2>&1 || true
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${USER}@${VM2_IP}" "bash -lc '$remote_update_cmd'" >/dev/null 2>&1 || true

# 简单封装带可选 API_KEY 的 POST
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
# 响铃提示
printf "\a" || true
echo ">>> 30 seconds RTC traffic collected. Time to end collection."

echo ">>> Stopping capture on both VMs..."
stop1=$(curl_post "http://${VM1_IP}:5000/stop" || true)
stop2=$(curl_post "http://${VM2_IP}:5000/stop" || true)

# 提取远端 pcap 路径（/stop 返回文本中含 file=<path>）
pcap1=$(printf "%s" "$stop1" | sed -n 's/.*file=\(.*\)$/\1/p' | tr -d '\r')
pcap2=$(printf "%s" "$stop2" | sed -n 's/.*file=\(.*\)$/\1/p' | tr -d '\r')

echo "VM1 latest pcap: ${pcap1}"
echo "VM2 latest pcap: ${pcap2}"

echo ">>> Downloading PCAP files..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${USER}@${VM1_IP}:${pcap1}" "$local_pcap1"
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${USER}@${VM2_IP}:${pcap2}" "$local_pcap2"

# ===== 分析函数：聚合 packets 并输出 Top 5，尝试定位 =====
format_analysis() {
	# 输入：完整原始文本（stdin）
	# 输出：人类可读的分析摘要到 stdout；同时通过全局变量 RELAY_IP 输出候选中继 IP
	local raw
	raw=$(cat)

	# awk 聚合各 IP 的 packets 总数，同时剔除私网/保留地址
	# 输出格式：<packets_sum> <ip>
	local aggregated
	aggregated=$(printf "%s" "$raw" | awk '
function is_priv(ip,   a){ 
	split(ip,a,".");
	if(a[1]==10) return 1;
	if(a[1]==127) return 1;
	if(a[1]==192 && a[2]==168) return 1;
	if(a[1]==169 && a[2]==254) return 1;
	if(a[1]==172 && a[2]>=16 && a[2]<=31) return 1;
	return 0;
}
{
	if (match($0,/([0-9]{1,3}(\.[0-9]{1,3}){3}).*packets=([0-9]+)/,m)) {
		ip=m[1]; pkts=m[3]+0;
		if (!is_priv(ip) && !(ip=="1.1.1.1" || ip=="1.0.0.1" || ip=="8.8.8.8" || ip=="3.3.3.3")) {
			sum[ip]+=pkts;
		}
	}
}
END{
	for (ip in sum) printf "%d %s\n", sum[ip], ip;
}')

	if [[ -z "${aggregated}" ]]; then
		echo "No public relay IPs detected in analysis output"
		RELAY_IP=""
		return 0
	fi

	# 选最大 packets 的作为候选 relay
	local top_line
	top_line=$(printf "%s\n" "$aggregated" | sort -nr | head -n1 || true)
	local relay_ip relay_pkts
	relay_pkts=$(printf "%s" "$top_line" | awk '{print $1}')
	relay_ip=$(printf "%s" "$top_line" | awk '{print $2}')
	RELAY_IP="${relay_ip}"

	# 查地理位置（尽量不引入 jq 依赖，简单解析）
	local loc_json city country org
	loc_json=$(curl -sS "http://ip-api.com/json/${relay_ip}" || true)
	city=$(printf "%s" "$loc_json" | sed -n 's/.*"city":"\([^"]*\)".*/\1/p' | head -n1)
	country=$(printf "%s" "$loc_json" | sed -n 's/.*"country":"\([^"]*\)".*/\1/p' | head -n1)
	org=$(printf "%s" "$loc_json" | sed -n 's/.*"org":"\([^"]*\)".*/\1/p' | head -n1)

	if [[ -n "$city$country$org" ]]; then
		echo "Relay found from DPI: ${relay_ip} ($(printf "%s%s%s" "$city" "${city:+, }$country" "${org:+, }$org"))"
	else
		echo "Relay found from DPI: ${relay_ip} (Location lookup failed)"
	fi

	echo ""
	echo "Top 5 IPs:"
	# 打印前 5，格式化 k
	printf "%s\n" "$aggregated" | sort -nr | head -n5 | while read -r line; do
		local pk ip tag
		pk=$(printf "%s" "$line" | awk '{print $1}')
		ip=$(printf "%s" "$line" | awk '{print $2}')
		if [[ "$pk" -ge 1000 ]]; then
			pk="$(( (pk + 500) / 1000 ))k"
		fi
		tag=""
		if [[ "$ip" == "$relay_ip" ]]; then
			tag=" (relay)"
		fi
		echo "${ip}, ${pk} pkts${tag}"
	done
}

echo ">>> Running local DPI (check_dpi.py) on both PCAPs..."
# 本地运行支持多 pcap 的 check_dpi.py，一次性输出两个文件的摘要和方向性延迟/RTT
combined_raw=$(python3 /Users/apple/Documents/RTC/RTC_relay_infra/new/rtcproxy/check_dpi.py --pcap "$local_pcap1" "$local_pcap2" 2>/dev/null || true)
printf "%s\n" "$combined_raw" >"$local_txt"

echo ""
echo "========== ANALYSIS DONE =========="
echo "$combined_raw"
echo "Saved to: $local_txt"
echo "==================================="
echo ""
echo "Captured files stored in: $RUN_FOLDER"


