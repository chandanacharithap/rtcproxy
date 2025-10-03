# ==== Config ====
$VM1_IP    = "20.55.35.218"
$VM2_IP    = "20.56.16.9"
$SSH_KEY   = "C:\Users\chand\.ssh\azure_rtc.pem"
$USER      = "azureuser"
$BASE_DIR  = "C:\Users\chand\captures"

# Region names for naming convention
$REGION1   = "us-east"
$REGION2   = "europe-west"

# Ensure base folder exists
if (-Not (Test-Path -Path $BASE_DIR)) {
    New-Item -ItemType Directory -Path $BASE_DIR | Out-Null
}

# Count existing run folders
$existingRuns = (Get-ChildItem -Path $BASE_DIR -Directory -ErrorAction SilentlyContinue).Count
$run_no = $existingRuns + 1

# Create new run folder
$RUN_FOLDER = "${BASE_DIR}\${REGION1}-${REGION2}-run_${run_no}"
New-Item -ItemType Directory -Path $RUN_FOLDER | Out-Null

Write-Host ">>> Starting capture on both VMs..."
Invoke-WebRequest -Uri ("http://{0}:5000/start" -f $VM1_IP) -Method POST -Proxy $null | Out-Null
Invoke-WebRequest -Uri ("http://{0}:5000/start" -f $VM2_IP) -Method POST -Proxy $null | Out-Null

Write-Host ">>> Capture running for 30 seconds..."
Start-Sleep -Seconds 20

# Countdown for the last 10s
for ($i=10; $i -gt 0; $i--) {
    Write-Host ("   {0}s remaining..." -f $i)
    Start-Sleep -Seconds 1
}

# Beep + notice
[console]::beep(1000,500)
Write-Host ">>> 30 seconds RTC traffic collected. Time to end collection."

Write-Host ">>> Stopping capture on both VMs..."
$stop1 = Invoke-WebRequest -Uri ("http://{0}:5000/stop" -f $VM1_IP) -Method POST -Proxy $null
$stop2 = Invoke-WebRequest -Uri ("http://{0}:5000/stop" -f $VM2_IP) -Method POST -Proxy $null

# Extract remote pcap paths
$pcap1 = ($stop1.Content -split "file=")[-1].Trim()
$pcap2 = ($stop2.Content -split "file=")[-1].Trim()

# Create proper filenames
$local_pcap1 = "${RUN_FOLDER}\${REGION1}-${REGION2}-vm1.pcap"
$local_pcap2 = "${RUN_FOLDER}\${REGION1}-${REGION2}-vm2.pcap"
$local_txt1  = "${RUN_FOLDER}\vm1-analysis.txt"
$local_txt2  = "${RUN_FOLDER}\vm2-analysis.txt"

Write-Host "VM1 latest pcap: $pcap1"
Write-Host "VM2 latest pcap: $pcap2"

Write-Host ">>> Downloading PCAP files..."
scp -i $SSH_KEY "${USER}@${VM1_IP}:$pcap1" $local_pcap1
scp -i $SSH_KEY "${USER}@${VM2_IP}:$pcap2" $local_pcap2

function Lookup-IPLocation {
    param([string]$ip)

    try {
        $resp = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -TimeoutSec 5 -ErrorAction Stop
        if ($resp.status -eq "success") {
            return [PSCustomObject]@{
                City    = $resp.city
                Region  = $resp.regionName
                Country = $resp.country
                ISP     = $resp.isp
                Org     = $resp.org
                ASN     = $resp.as
            }
        }
    } catch {
        # Silent fail on API error
    }
    return $null
}

function Format-Analysis {
    param(
        [string]$raw,
        [string]$forceRelayIP = $null
    )

    $rtcServices = @("Zoom", "WhatsApp", "Messenger", "Discord", "Google Meet", "Teams", "Meta", "Facebook")
    $ignoreIPs   = @("1.1.1.1","1.0.0.1", "8.8.8.8", "3.3.3.3")

    $serviceMap = @{
        "AS32934"   = "Meta (WhatsApp/Messenger/Instagram)"
        "Facebook"  = "Meta (WhatsApp/Messenger/Instagram)"
        "Meta"      = "Meta (WhatsApp/Messenger/Instagram)"
        "AS8075"    = "Microsoft (Teams/Skype/Zoom Hosting)"
        "Zoom Video"= "Zoom"
        "Zoom"      = "Zoom"
        "Google LLC"= "Google Meet"
        "Discord"   = "Discord"
        "AS15169"   = "Google (Google Meet)"
    }

    function Is-PublicIP($ip) {
        return -not (
            $ip -like "10.*" -or
            $ip -like "172.1[6-9].*" -or
            $ip -like "172.2[0-9].*" -or
            $ip -like "172.3[0-1].*" -or
            $ip -like "192.168.*" -or
            $ip -like "127.*" -or
            $ip -like "169.254.*"
        )
    }

    $lines = $raw -split "`n" | ForEach-Object { $_.Trim() } | Where-Object {$_ -ne ""}
    $entries = @()

    foreach ($l in ($lines | Where-Object {$_ -match "\d+\.\d+\.\d+\.\d+.*packets="})) {
        $matches = [regex]::Matches($l, "(\d{1,3}(\.\d{1,3}){3}).*?packets=(\d+)")
        foreach ($m in $matches) {
            $ip   = $m.Groups[1].Value
            $pkt  = [int]$m.Groups[3].Value
            $meta = $l.Substring($l.IndexOf($ip) + $ip.Length).Trim()
            if (Is-PublicIP $ip -and ($ignoreIPs -notcontains $ip)) {
                $entries += [PSCustomObject]@{ IP=$ip; Packets=$pkt; Meta=$meta }
            }
        }
    }

    if (-not $entries) {
        return @("No public relay IPs detected in analysis output", $null)
    }

    $relay = $null
    if ($forceRelayIP -and ($entries | Where-Object { $_.IP -eq $forceRelayIP })) {
        $relay = $entries | Where-Object { $_.IP -eq $forceRelayIP } | Sort-Object Packets -Descending | Select-Object -First 1
    }
    if (-not $relay) {
        $serviceMatches = $entries | Where-Object {
            foreach ($svc in $rtcServices) { if ($_.Meta -match $svc) { return $true } }
            return $false
        }
        if ($serviceMatches) {
            $relay = $serviceMatches | Sort-Object Packets -Descending | Select-Object -First 1
        }
    }
    if (-not $relay) {
        $relay = $entries | Sort-Object Packets -Descending | Select-Object -First 1
    }

    $output = @()
    if ($relay) {
        $locLookup = Lookup-IPLocation $relay.IP
        $finalParts = @()
        if ($locLookup.City)    { $finalParts += $locLookup.City }
        if ($locLookup.Country) { $finalParts += $locLookup.Country }

        $service = $null
        foreach ($key in $serviceMap.Keys) {
            if ($locLookup.ASN -match $key -or $locLookup.ISP -match $key -or $locLookup.Org -match $key) {
                $service = $serviceMap[$key]
                break
            }
        }
        if ($service) { $finalParts += $service }

        if ($finalParts.Count -gt 0) {
            $loc = $finalParts -join ", "
            $output += "Relay found from DPI: $($relay.IP) ($loc)"
        } else {
            $output += "Relay found from DPI: $($relay.IP) (Location lookup failed)"
        }
    } else {
        $output += "No known relay service detected."
    }

    $output += ""
    $output += "Top 5 IPs:"

    $ordered = $entries | Sort-Object Packets -Descending | Select-Object -First 5
    foreach ($e in $ordered) {
        $pkts = if ($e.Packets -ge 1000) { "{0}k" -f [math]::Round($e.Packets/1000) } else { $e.Packets }
        $tag = ""
        if ($relay -and $e.IP -eq $relay.IP) { $tag = " (relay)" }
        $output += ("{0}, {1} pkts{2}" -f $e.IP, $pkts, $tag)
    }

    if ($relay) {
        return ,($output -join "`n"), $relay.IP
    } else {
        return ,($output -join "`n"), $null
    }
}

Write-Host ">>> Running check_dpi.py on both VMs..."
$vm1_raw = & ssh -i $SSH_KEY "${USER}@${VM1_IP}" "python3 /opt/rtcproxy/check_dpi.py --pcap `"$pcap1`""
$vm2_raw = & ssh -i $SSH_KEY "${USER}@${VM2_IP}" "python3 /opt/rtcproxy/check_dpi.py --pcap `"$pcap2`""

$vm1_result = Format-Analysis $vm1_raw
$vm1_out = $vm1_result[0]
$relayIP = $vm1_result[1]

$vm2_result = Format-Analysis $vm2_raw $relayIP
$vm2_out = $vm2_result[0]

$vm1_out | Out-File -FilePath $local_txt1 -Encoding utf8
$vm2_out | Out-File -FilePath $local_txt2 -Encoding utf8

Write-Host ""
Write-Host "========== ANALYSIS DONE =========="
Write-Host "VM1 ($VM1_IP):"
Write-Host $vm1_out
Write-Host "Saved to: $local_txt1"
Write-Host ""
Write-Host "VM2 ($VM2_IP):"
Write-Host $vm2_out
Write-Host "Saved to: $local_txt2"
Write-Host "==================================="
Write-Host ""
Write-Host "Captured files stored in: $RUN_FOLDER"

