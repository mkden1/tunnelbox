$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "tunnelbox-daemon", [System.IO.Pipes.PipeDirection]::InOut)
$pipe.Connect(3000)
$writer = New-Object System.IO.StreamWriter($pipe)
$reader = New-Object System.IO.StreamReader($pipe)
$writer.AutoFlush = $true

# List / create profile
$writer.WriteLine('{"id":"t-000","cmd":"profile_list","payload":{}}')
$r = $reader.ReadLine()
$profiles = ($r | ConvertFrom-Json).payload
$existing = $profiles | Where-Object { $_.name -eq "test" }
if ($existing) {
    $profileId = $existing.id
    Write-Host "Using existing profile: $profileId"
} else {
    $writer.WriteLine('{"id":"t-001","cmd":"profile_create","payload":{"name":"test"}}')
    $r = $reader.ReadLine()
    $profileId = ($r | ConvertFrom-Json).payload.id
    Write-Host "Created profile: $profileId"
}

# Import wireguard config
$confPath = "E:\Projects\VPN Container\tunnelbox-daemon\vpn.conf"
$confContents = Get-Content $confPath -Raw
$confEscaped = $confContents -replace '\\', '\\' -replace '"', '\"' -replace "`r`n", '\n' -replace "`n", '\n'
$writer.WriteLine("{`"id`":`"t-002`",`"cmd`":`"wireguard_import`",`"payload`":{`"profile_id`":`"$profileId`",`"contents`":`"$confEscaped`"}}")
$r = $reader.ReadLine()
Write-Host "Import: $r"

# Bind curl to the profile BEFORE connecting
# This is what triggers WFP filter installation on connect
$writer.WriteLine("{`"id`":`"t-003`",`"cmd`":`"app_bind`",`"payload`":{`"profile_id`":`"$profileId`",`"exe_path`":`"C:\\Windows\\System32\\curl.exe`"}}")
$r = $reader.ReadLine()
Write-Host "Bind curl: $r"

# Disconnect first in case already connected from a previous run
$writer.WriteLine("{`"id`":`"t-003b`",`"cmd`":`"tunnel_disconnect`",`"payload`":{`"profile_id`":`"$profileId`"}}")
$r = $reader.ReadLine()
Write-Host "Pre-disconnect: $r"   # ok if this errors, profile may not be connected
Start-Sleep -Seconds 1

# Connect profile
$writer.WriteLine("{`"id`":`"t-004`",`"cmd`":`"tunnel_connect`",`"payload`":{`"profile_id`":`"$profileId`"}}")
$r = $reader.ReadLine()
Write-Host "Connect: $r"
Start-Sleep -Seconds 3

# ── WFP check 1: filters should exist now ────────────────────────────────────
netsh wfp show filters file=C:\temp\wfp_connected.xml | Out-Null
$hits = Select-String -Path C:\temp\wfp_connected.xml -Pattern "Tunnelbox-Block|Tunnelbox-Permit" -SimpleMatch
Write-Host "`nWFP filters after connect: $($hits.Count) hits"
$hits | ForEach-Object { Write-Host "  $_" }

# Launch curl through tunnel
$writer.WriteLine("{`"id`":`"t-005`",`"cmd`":`"app_launch`",`"payload`":{`"profile_id`":`"$profileId`",`"exe_path`":`"C:\\Windows\\System32\\curl.exe`",`"args`":[`"-4`",`"-s`",`"-o`",`"C:\\temp\\out.txt`",`"https://ifconfig.me`"]}}")
$r = $reader.ReadLine()
Write-Host "Launch curl: $r"
Start-Sleep -Seconds 10
$result = Get-Content "C:\temp\out.txt" -ErrorAction SilentlyContinue
Write-Host "IP via tunnel: $result"

# Disconnect
$writer.WriteLine("{`"id`":`"t-006`",`"cmd`":`"tunnel_disconnect`",`"payload`":{`"profile_id`":`"$profileId`"}}")
$r = $reader.ReadLine()
Write-Host "Disconnect: $r"
Start-Sleep -Seconds 1

# ── WFP check 2: filters should be gone now ───────────────────────────────────
netsh wfp show filters file=C:\temp\wfp_disconnected.xml | Out-Null
$hits2 = Select-String -Path C:\temp\wfp_disconnected.xml -Pattern "Tunnelbox-Block|Tunnelbox-Permit" -SimpleMatch
Write-Host "`nWFP filters after disconnect: $($hits2.Count) hits (expect 0)"
$hits2 | ForEach-Object { Write-Host "  $_" }

$pipe.Close()