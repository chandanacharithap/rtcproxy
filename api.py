from flask import Flask, request, send_file, jsonify
import os, subprocess, signal, time, json, datetime

app = Flask(__name__)

# ====== Config ======
CAP_DIR = "/var/log/rtc"
STATE_FILE = "/tmp/rtc_capture.json"
DEFAULT_IFACE = os.environ.get("RTC_IFACE", "wg0")
DEFAULT_PEER_IP = os.environ.get("RTC_PEER_IP", "10.0.0.3")   
API_PORT = int(os.environ.get("RTC_API_PORT", "5000"))
API_BIND = os.environ.get("RTC_API_BIND", "0.0.0.0")
API_KEY  = os.environ.get("RTC_API_KEY", "")  

os.makedirs(CAP_DIR, exist_ok=True)

def require_key():
    if not API_KEY:
        return True
    return request.headers.get("X-API-Key") == API_KEY

def nowstamp():
    return datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")

def read_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {}

def write_state(d):
    with open(STATE_FILE, "w") as f:
        json.dump(d, f)

@app.route("/status", methods=["GET"])
def status():
    st = read_state()
    return jsonify(st or {"running": False})

@app.route("/start", methods=["POST"])
def start_capture():
    if not require_key():
        return ("unauthorized\n", 401)
    st = read_state()
    if st.get("running"):
        return (f"already running: {st}\n", 200)

    iface  = request.args.get("iface", DEFAULT_IFACE)
    peer   = request.args.get("peer", DEFAULT_PEER_IP)
    flt    = request.args.get("filter")
   
    bpf    = flt if flt else f"host {peer} and (udp or tcp) and not port 51820"

    fname = os.path.join(CAP_DIR, f"rtc-{nowstamp()}.pcap")
    cmd = ["tcpdump", "-U", "-i", iface, "-w", fname, bpf]
    
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)

    st = {
        "running": True,
        "pid": proc.pid,
        "iface": iface,
        "filter": bpf,
        "file": fname,
        "started_at": int(time.time())
    }
    write_state(st)
    return (f"started pid={proc.pid} file={fname} iface={iface} filter='{bpf}'\n", 200)

@app.route("/stop", methods=["POST"])
def stop_capture():
    if not require_key():
        return ("unauthorized\n", 401)
    st = read_state()
    if not st.get("running"):
        return ("not running\n", 200)

    pid = st.get("pid")
    try:
        os.killpg(int(pid), signal.SIGTERM)
    except ProcessLookupError:
        pass
    st["running"] = False
    st["stopped_at"] = int(time.time())
    write_state(st)
    return (f"stopped pid={pid} file={st.get('file')}\n", 200)

@app.route("/download", methods=["GET"])
def download():
    st = read_state()
    arg = request.args.get("file", "current")
    path = st.get("file") if arg == "current" else arg
    if not path or not os.path.exists(path):
        return ("no such file\n", 404)
    return send_file(path, as_attachment=True)

@app.route("/block", methods=["POST"])
def block():
    if not require_key():
        return ("unauthorized\n", 401)
    ip = request.args.get("ip")
    if not ip:
        return ("usage: POST /block?ip=1.2.3.4\n", 400)

    rules = [
        ["iptables", "-I", "FORWARD", "-d", ip, "-m", "comment", "--comment", "RTC_BLOCK", "-j", "DROP"],
        ["iptables", "-I", "FORWARD", "-s", ip, "-m", "comment", "--comment", "RTC_BLOCK", "-j", "DROP"],
        ["iptables", "-I", "OUTPUT",  "-d", ip, "-m", "comment", "--comment", "RTC_BLOCK", "-j", "DROP"],
    ]
    for r in rules:
        subprocess.call(r)
    return (f"blocked {ip}\n", 200)

@app.route("/unblock", methods=["POST"])
def unblock():
    if not require_key():
        return ("unauthorized\n", 401)
    ip = request.args.get("ip")
    if not ip:
        return ("usage: POST /unblock?ip=1.2.3.4\n", 400)

    rules = [
        ["iptables", "-D", "FORWARD", "-d", ip, "-m", "comment", "--comment", "RTC_BLOCK", "-j", "DROP"],
        ["iptables", "-D", "FORWARD", "-s", ip, "-m", "comment", "--comment", "RTC_BLOCK", "-j", "DROP"],
        ["iptables", "-D", "OUTPUT",  "-d", ip, "-m", "comment", "--comment", "RTC_BLOCK", "-j", "DROP"],
    ]
    for r in rules:
        subprocess.call(r)
    return (f"unblocked {ip}\n", 200)

@app.route("/blocked", methods=["GET"])
def blocked():
    out = subprocess.check_output(["iptables", "-S"]).decode()
    lines = [ln for ln in out.splitlines() if "RTC_BLOCK" in ln]
    return ("".join(ln + "\n" for ln in lines) or "none\n", 200)

if __name__ == "__main__":
    print(f"Starting API on {API_BIND}:{API_PORT} (iface={DEFAULT_IFACE}, peer={DEFAULT_PEER_IP})")
    app.run(host=API_BIND, port=API_PORT)
