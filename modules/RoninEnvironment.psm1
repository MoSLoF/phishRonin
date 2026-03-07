Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
  RoninEnvironment - Pre/During/Post triage system environment monitor.

.DESCRIPTION
  Captures network connections, process state, and system baselines before,
  during, and after triage to detect anomalous activity triggered by analysis.

  Usage:
    $monitor = Start-RoninEnvironment     # Captures pre-triage baseline
    # ... run triage pipeline ...
    Stop-RoninEnvironment -Monitor $monitor -DelaySeconds 60  # Captures post with 60s soak
    Show-RoninEnvironment -Monitor $monitor
#>

# -- Snapshot helper: captures current system state ---------------------------

function Get-RoninSystemSnapshot {
  [CmdletBinding()]
  param([string]$Label = 'snapshot')

  $ts = Get-Date

  # Network connections (TCP established + listen)
  $connections = @()
  try {
    $raw = Get-NetTCPConnection -ErrorAction SilentlyContinue |
      Where-Object { $_.State -in @('Established','Listen','SynSent','SynReceived','CloseWait') } |
      Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    foreach ($c in $raw) {
      $procName = ''
      try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
      $connections += [PSCustomObject]@{
        LocalAddress  = $c.LocalAddress
        LocalPort     = $c.LocalPort
        RemoteAddress = $c.RemoteAddress
        RemotePort    = $c.RemotePort
        State         = $c.State
        PID           = $c.OwningProcess
        ProcessName   = $procName
      }
    }
  } catch {
    $connections = @([PSCustomObject]@{ Error = "Get-NetTCPConnection failed: $_" })
  }

  # Running processes (lightweight)
  $processes = @()
  try {
    $procs = Get-Process -ErrorAction SilentlyContinue |
      Select-Object -Property Id, ProcessName, Path, WorkingSet64, StartTime -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
      $processes += [PSCustomObject]@{
        PID         = $p.Id
        Name        = $p.ProcessName
        Path        = $p.Path
        MemoryMB    = [math]::Round(($p.WorkingSet64 / 1MB), 1)
        StartTime   = $p.StartTime
      }
    }
  } catch {
    $processes = @([PSCustomObject]@{ Error = "Get-Process failed: $_" })
  }

  # DNS cache sample
  $dnsCache = @()
  try {
    $dns = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 100
    foreach ($d in $dns) {
      $dnsCache += [PSCustomObject]@{
        Name   = $d.Entry
        Type   = $d.Type
        TTL    = $d.TimeToLive
        Data   = $d.Data
      }
    }
  } catch {}

  return [PSCustomObject]@{
    Label       = $Label
    Timestamp   = $ts
    Connections = $connections
    Processes   = $processes
    DnsCache    = $dnsCache
    UniqueRemoteIps = @($connections | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' -and $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' } | ForEach-Object { $_.RemoteAddress } | Select-Object -Unique)
    UniqueProcesses = @($processes | ForEach-Object { $_.Name } | Select-Object -Unique)
    ConnectionCount = $connections.Count
    ProcessCount    = $processes.Count
  }
}

# -- Start Environment Monitor ------------------------------------------------

function Start-RoninEnvironment {
  [CmdletBinding()]
  param()

  Write-Host "[RoninEnvironment] Capturing pre-triage baseline..." -ForegroundColor Cyan
  $preSnapshot = Get-RoninSystemSnapshot -Label 'pre-triage'

  $monitor = [PSCustomObject]@{
    StartTime      = Get-Date
    StopTime       = $null
    PreSnapshot    = $preSnapshot
    DuringSnapshots = New-Object System.Collections.Generic.List[object]
    PostSnapshot   = $null
    Deltas         = @{
      NewConnections = @()
      LostConnections = @()
      NewProcesses   = @()
      LostProcesses  = @()
      NewRemoteIps   = @()
      NewDnsEntries  = @()
    }
    Findings       = New-Object System.Collections.Generic.List[string]
  }

  Write-Host "[RoninEnvironment] Baseline captured: $($preSnapshot.ConnectionCount) connections, $($preSnapshot.ProcessCount) processes, $($preSnapshot.UniqueRemoteIps.Count) unique remote IPs" -ForegroundColor Green
  return $monitor
}

# -- Capture a during-triage snapshot -----------------------------------------

function Add-RoninEnvironmentSnapshot {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Monitor,
    [string]$Label = 'during-triage'
  )

  $snap = Get-RoninSystemSnapshot -Label $Label
  $Monitor.DuringSnapshots.Add($snap)
  return $Monitor
}

# -- Stop Environment Monitor -------------------------------------------------

function Stop-RoninEnvironment {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Monitor,
    [int]$DelaySeconds = 60
  )

  if ($DelaySeconds -gt 0) {
    Write-Host "[RoninEnvironment] Post-triage soak period: waiting $DelaySeconds seconds..." -ForegroundColor Cyan
    Start-Sleep -Seconds $DelaySeconds
  }

  Write-Host "[RoninEnvironment] Capturing post-triage snapshot..." -ForegroundColor Cyan
  $Monitor.PostSnapshot = Get-RoninSystemSnapshot -Label 'post-triage'
  $Monitor.StopTime = Get-Date

  # -- Compute deltas between pre and post ------------------------------------
  $pre  = $Monitor.PreSnapshot
  $post = $Monitor.PostSnapshot

  # New remote IPs (connected to after triage that weren't before)
  $preIps  = @($pre.UniqueRemoteIps)
  $postIps = @($post.UniqueRemoteIps)
  $Monitor.Deltas.NewRemoteIps = @($postIps | Where-Object { $preIps -notcontains $_ })

  # New processes
  $preProcs  = @($pre.UniqueProcesses)
  $postProcs = @($post.UniqueProcesses)
  $Monitor.Deltas.NewProcesses = @($postProcs | Where-Object { $preProcs -notcontains $_ })
  $Monitor.Deltas.LostProcesses = @($preProcs | Where-Object { $postProcs -notcontains $_ })

  # New connections (by remote IP:port + process)
  $preConnKeys = @($pre.Connections | Where-Object { $_.RemoteAddress } | ForEach-Object { "{0}:{1}|{2}" -f $_.RemoteAddress, $_.RemotePort, $_.ProcessName })
  $postConnKeys = @($post.Connections | Where-Object { $_.RemoteAddress } | ForEach-Object { "{0}:{1}|{2}" -f $_.RemoteAddress, $_.RemotePort, $_.ProcessName })

  $newConnKeys = @($postConnKeys | Where-Object { $preConnKeys -notcontains $_ })
  $Monitor.Deltas.NewConnections = @()
  foreach ($key in $newConnKeys) {
    $parts = $key -split '\|'
    $addrPort = $parts[0] -split ':'
    $Monitor.Deltas.NewConnections += [PSCustomObject]@{
      RemoteAddress = ($addrPort[0..($addrPort.Count-2)] -join ':')
      RemotePort    = $addrPort[-1]
      ProcessName   = $parts[1]
    }
  }

  $lostConnKeys = @($preConnKeys | Where-Object { $postConnKeys -notcontains $_ })
  $Monitor.Deltas.LostConnections = @()
  foreach ($key in $lostConnKeys) {
    $parts = $key -split '\|'
    $addrPort = $parts[0] -split ':'
    $Monitor.Deltas.LostConnections += [PSCustomObject]@{
      RemoteAddress = ($addrPort[0..($addrPort.Count-2)] -join ':')
      RemotePort    = $addrPort[-1]
      ProcessName   = $parts[1]
    }
  }

  # New DNS entries
  $preDns  = @($pre.DnsCache | ForEach-Object { $_.Name })
  $postDns = @($post.DnsCache | ForEach-Object { $_.Name })
  $Monitor.Deltas.NewDnsEntries = @($postDns | Where-Object { $preDns -notcontains $_ })

  # -- Generate findings -------------------------------------------------------
  if ($Monitor.Deltas.NewRemoteIps.Count -gt 0) {
    $Monitor.Findings.Add("New remote IPs after triage: $($Monitor.Deltas.NewRemoteIps -join ', ')")
  }
  if ($Monitor.Deltas.NewProcesses.Count -gt 0) {
    $Monitor.Findings.Add("New processes spawned: $($Monitor.Deltas.NewProcesses -join ', ')")
  }
  if ($Monitor.Deltas.NewConnections.Count -gt 5) {
    $Monitor.Findings.Add("Significant connection activity: $($Monitor.Deltas.NewConnections.Count) new connections post-triage")
  }
  if ($Monitor.Deltas.NewDnsEntries.Count -gt 10) {
    $Monitor.Findings.Add("Elevated DNS activity: $($Monitor.Deltas.NewDnsEntries.Count) new cache entries")
  }

  # Check for suspicious processes that appeared
  $suspiciousProcs = @('powershell','pwsh','cmd','wscript','cscript','mshta','certutil','bitsadmin','regsvr32','rundll32')
  foreach ($newProc in $Monitor.Deltas.NewProcesses) {
    if ($newProc.ToLowerInvariant() -in $suspiciousProcs) {
      $Monitor.Findings.Add("[ALERT] Suspicious process spawned during triage: $newProc")
    }
  }

  # Check for connections on unusual ports
  $unusualPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345)
  foreach ($nc in $Monitor.Deltas.NewConnections) {
    if ([int]$nc.RemotePort -in $unusualPorts) {
      $Monitor.Findings.Add("[ALERT] Connection to suspicious port $($nc.RemotePort) by $($nc.ProcessName)")
    }
  }

  $duration = ($Monitor.StopTime - $Monitor.StartTime).TotalSeconds
  Write-Host "[RoninEnvironment] Monitor complete. Duration: $([math]::Round($duration, 1))s" -ForegroundColor Green
  Write-Host "[RoninEnvironment] Delta: +$($Monitor.Deltas.NewRemoteIps.Count) IPs, +$($Monitor.Deltas.NewProcesses.Count) processes, +$($Monitor.Deltas.NewConnections.Count) connections" -ForegroundColor $(if($Monitor.Findings.Count -gt 0){"Yellow"}else{"Green"})

  return $Monitor
}

# -- Console Display ----------------------------------------------------------

function Show-RoninEnvironment {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Monitor)

  "=== RoninEnvironment ==="
  "Monitor Duration: {0:N1}s" -f ($Monitor.StopTime - $Monitor.StartTime).TotalSeconds
  ""

  "Pre-Triage Baseline ({0:HH:mm:ss}):" -f $Monitor.PreSnapshot.Timestamp
  "  Connections: {0}  |  Processes: {1}  |  Unique Remote IPs: {2}" -f `
    $Monitor.PreSnapshot.ConnectionCount, $Monitor.PreSnapshot.ProcessCount, $Monitor.PreSnapshot.UniqueRemoteIps.Count
  ""

  if ($Monitor.DuringSnapshots.Count -gt 0) {
    "During-Triage Snapshots: {0}" -f $Monitor.DuringSnapshots.Count
    foreach ($snap in $Monitor.DuringSnapshots) {
      "  [{0:HH:mm:ss}] {1}: {2} connections, {3} processes" -f $snap.Timestamp, $snap.Label, $snap.ConnectionCount, $snap.ProcessCount
    }
    ""
  }

  "Post-Triage Snapshot ({0:HH:mm:ss}):" -f $Monitor.PostSnapshot.Timestamp
  "  Connections: {0}  |  Processes: {1}  |  Unique Remote IPs: {2}" -f `
    $Monitor.PostSnapshot.ConnectionCount, $Monitor.PostSnapshot.ProcessCount, $Monitor.PostSnapshot.UniqueRemoteIps.Count
  ""

  "Deltas:"
  "  New Remote IPs:     {0}" -f $Monitor.Deltas.NewRemoteIps.Count
  if ($Monitor.Deltas.NewRemoteIps.Count -gt 0) {
    foreach ($ip in $Monitor.Deltas.NewRemoteIps) { "    + $ip" }
  }
  "  New Processes:      {0}" -f $Monitor.Deltas.NewProcesses.Count
  if ($Monitor.Deltas.NewProcesses.Count -gt 0) {
    foreach ($p in $Monitor.Deltas.NewProcesses) { "    + $p" }
  }
  "  Lost Processes:     {0}" -f $Monitor.Deltas.LostProcesses.Count
  "  New Connections:    {0}" -f $Monitor.Deltas.NewConnections.Count
  if ($Monitor.Deltas.NewConnections.Count -gt 0 -and $Monitor.Deltas.NewConnections.Count -le 20) {
    foreach ($nc in $Monitor.Deltas.NewConnections) {
      "    + {0}:{1} ({2})" -f $nc.RemoteAddress, $nc.RemotePort, $nc.ProcessName
    }
  }
  "  New DNS Entries:    {0}" -f $Monitor.Deltas.NewDnsEntries.Count
  ""

  if ($Monitor.Findings.Count -gt 0) {
    "Environment Findings:"
    foreach ($f in $Monitor.Findings) { "  - $f" }
  } else {
    "Environment Findings: None (clean)"
  }
}

Export-ModuleMember -Function Start-RoninEnvironment, Add-RoninEnvironmentSnapshot, Stop-RoninEnvironment, Show-RoninEnvironment, Get-RoninSystemSnapshot
