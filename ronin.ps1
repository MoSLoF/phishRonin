<#
.SYNOPSIS
  phishRonin - PowerShell CLI for phishing triage (headers, docs, IOCs, OSINT, M365 quarantine)

.DESCRIPTION
  This is a safe-by-default triage tool. It performs static analysis only unless you
  explicitly invoke M365 actions (quarantine/move) with credentials configured.

  Commands:
    triage      End-to-end triage: headers + OSINT + doc + score + report
    headers     Parse headers for SPF/DKIM/DMARC + Received chain
    doc         Extract suspicious artifacts from DOCX/OLE and URLs
    hunt        Export IOCs and generate hunting queries (KQL/Splunk/Regex)
    osint       OSINT sender investigation: IP profiling, WHOIS, threat classification
    quarantine  M365 Graph workflow to move/quarantine a message (dry-run default)
    config      Show effective configuration (no secrets)

.NOTES
  Requires: PowerShell 7+ recommended (works on 5.1 for most features except some TLS defaults)
#>

[CmdletBinding()]
param(
  [Parameter(Position=0)]
  [ValidateSet('triage','headers','doc','hunt','osint','quarantine','config','help')]
  [string]$Command = 'help',

  # Common inputs
  [string]$Eml,
  [string]$HeadersFile,
  [string]$DocPath,

  # Output
  [switch]$Json,
  [string]$OutDir = ".\out",
  [switch]$HtmlReport,
  [string]$ReportPath,

  # Triage knobs
  [switch]$Offline,
  [switch]$Strict,

  # Quarantine knobs
  [string]$Mailbox,
  [string]$MessageId,
  [ValidateSet('MoveToJunk','MoveToQuarantineFolder','SoftDelete')]
  [string]$Action = 'MoveToJunk',
  [switch]$DryRun = $true,

  # Hunt knobs
  [ValidateSet('MDE','Defender','Sentinel','Splunk','Generic')]
  [string]$Provider = 'Generic'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Ronin {
  param([string]$Msg, [ValidateSet('INFO','WARN','ERR','OK')][string]$Level='INFO')
  $ts = (Get-Date).ToString("s")
  switch ($Level) {
    'INFO' { Write-Host "[$ts] [*] $Msg" }
    'OK'   { Write-Host "[$ts] [+] $Msg" -ForegroundColor Green }
    'WARN' { Write-Host "[$ts] [!] $Msg" -ForegroundColor Yellow }
    'ERR'  { Write-Host "[$ts] [x] $Msg" -ForegroundColor Red }
  }
}

# Load modules
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here "modules\RoninHeaders.psm1") -Force
Import-Module (Join-Path $here "modules\RoninImage.psm1") -Force
Import-Module (Join-Path $here "modules\RoninMimeForensics.psm1") -Force
Import-Module (Join-Path $here "modules\RoninDoc.psm1") -Force
Import-Module (Join-Path $here "modules\RoninHunt.psm1") -Force
Import-Module (Join-Path $here "modules\RoninOsint.psm1") -Force
Import-Module (Join-Path $here "modules\RoninTriage.psm1") -Force
Import-Module (Join-Path $here "modules\RoninQuarantine.psm1") -Force
Import-Module (Join-Path $here "modules\RoninEnvironment.psm1") -Force
Import-Module (Join-Path $here "modules\RoninWayback.psm1") -Force
Import-Module (Join-Path $here "modules\RoninGodMode.psm1") -Force

# Config
$configPath = Join-Path $here "config\ronin.config.json"
$config = Get-RoninConfig -Path $configPath

if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

switch ($Command) {
  'help' {
@"
phishRonin usage:

  .\ronin.ps1 triage     -Eml .\message.eml -DocPath .\attach.docx -HtmlReport -OutDir .\out
  .\ronin.ps1 headers    -HeadersFile .\headers.txt
  .\ronin.ps1 doc        -DocPath .\PlaybackAudioDocs.docx
  .\ronin.ps1 hunt       -Eml .\message.eml -Provider MDE -Json
  .\ronin.ps1 osint      -Eml .\message.eml [-Offline]
  .\ronin.ps1 quarantine -Mailbox user@domain -MessageId <id> -Action MoveToJunk -DryRun

Options:
  -Offline     Disables DNS lookups and any network calls (safe mode, still generates pivot links)
  -Strict      Fails triage if authentication evidence is missing/inconclusive
  -Json        Output JSON objects to stdout
  -HtmlReport  Emit an HTML report (templates/triage-report.html)
"@
    exit 0
  }

  'config' {
    $safe = $config.PSObject.Copy()
    # Hide secrets if present
    if ($safe.graph.clientSecret) { $safe.graph.clientSecret = "***" }
    if ($safe.osint.abuseIpDbKey) { $safe.osint.abuseIpDbKey = "***" }
    if ($safe.osint.shodanKey) { $safe.osint.shodanKey = "***" }
    if ($safe.osint.virusTotalKey) { $safe.osint.virusTotalKey = "***" }
    if ($Json) { $safe | ConvertTo-Json -Depth 8 }
    else { $safe | Format-List * }
    exit 0
  }

  'headers' {
    if (-not $HeadersFile -and -not $Eml) { throw "Provide -HeadersFile or -Eml" }
    $evidence = New-RoninEvidence -Config $config
    if ($Eml) { $evidence = Import-RoninEml -Evidence $evidence -Path $Eml }
    if ($HeadersFile) {
      $raw = Get-Content -Raw -Path $HeadersFile
      $evidence.Raw.Headers = $raw
    }
    $evidence = Invoke-RoninHeaders -Evidence $evidence -Config $config -Offline:$Offline -Strict:$Strict
    if ($Json) { $evidence | ConvertTo-Json -Depth 10 }
    else { Show-RoninHeaders -Evidence $evidence }
    exit 0
  }

  'doc' {
    if (-not $DocPath) { throw "Provide -DocPath" }
    $evidence = New-RoninEvidence -Config $config
    $evidence = Invoke-RoninDoc -Evidence $evidence -Path $DocPath
    if ($Json) { $evidence | ConvertTo-Json -Depth 10 }
    else { Show-RoninDoc -Evidence $evidence }
    exit 0
  }

  'hunt' {
    $evidence = New-RoninEvidence -Config $config
    if ($Eml) { $evidence = Import-RoninEml -Evidence $evidence -Path $Eml }
    if ($HeadersFile) { $evidence.Raw.Headers = Get-Content -Raw -Path $HeadersFile }
    if ($DocPath) { $evidence = Invoke-RoninDoc -Evidence $evidence -Path $DocPath }

    # Auto-analyze MIME-extracted attachments
    if ($evidence.Raw.ContainsKey('ExtractedAttachments') -and $evidence.Raw.ExtractedAttachments) {
      foreach ($att in $evidence.Raw.ExtractedAttachments) {
        $ext = [IO.Path]::GetExtension($att.Path).ToLowerInvariant()
        if (-not $DocPath -and ($ext -eq '.docx' -or $ext -eq '.doc')) {
          Write-Ronin "Auto-analyzing extracted attachment: $($att.Filename)" "INFO"
          $evidence = Invoke-RoninDoc -Evidence $evidence -Path $att.Path
        }
        elseif ($ext -match '\.(png|jpe?g|gif|bmp)$') {
          Write-Ronin "Auto-analyzing extracted image: $($att.Filename)" "INFO"
          $evidence = Invoke-RoninImage -Evidence $evidence -Path $att.Path
        }
      }
    }

    if (-not $evidence.Raw.Headers -and -not $evidence.Raw.Body -and -not $evidence.Attachments.Count) {
      Write-Ronin "No evidence loaded. Provide -Eml, -HeadersFile, and/or -DocPath." "WARN"
    }

    $evidence = Invoke-RoninHeaders -Evidence $evidence -Config $config -Offline:$Offline -Strict:$false
    $bundle = Export-RoninIocs -Evidence $evidence -OutDir $OutDir
    $queries = New-RoninHuntQueries -IocBundle $bundle -Provider $Provider
    if ($Json) {
      [PSCustomObject]@{ iocs=$bundle; queries=$queries } | ConvertTo-Json -Depth 10
    } else {
      $queries | Format-List *
    }
    exit 0
  }

  'osint' {
    $evidence = New-RoninEvidence -Config $config
    if ($Eml) { $evidence = Import-RoninEml -Evidence $evidence -Path $Eml }
    if ($HeadersFile) { $evidence.Raw.Headers = Get-Content -Raw -Path $HeadersFile }
    if ($DocPath) { $evidence = Invoke-RoninDoc -Evidence $evidence -Path $DocPath }

    # Auto-analyze MIME-extracted attachments
    if ($evidence.Raw.ContainsKey('ExtractedAttachments') -and $evidence.Raw.ExtractedAttachments) {
      foreach ($att in $evidence.Raw.ExtractedAttachments) {
        $ext = [IO.Path]::GetExtension($att.Path).ToLowerInvariant()
        if (-not $DocPath -and ($ext -eq '.docx' -or $ext -eq '.doc')) {
          Write-Ronin "Auto-analyzing extracted attachment: $($att.Filename)" "INFO"
          $evidence = Invoke-RoninDoc -Evidence $evidence -Path $att.Path
        }
        elseif ($ext -match '\.(png|jpe?g|gif|bmp)$') {
          Write-Ronin "Auto-analyzing extracted image: $($att.Filename)" "INFO"
          $evidence = Invoke-RoninImage -Evidence $evidence -Path $att.Path
        }
      }
    }

    if (-not $evidence.Raw.Headers -and -not $evidence.Raw.Body) {
      Write-Ronin "No evidence loaded. Provide -Eml or -HeadersFile." "WARN"
    }

    $evidence = Invoke-RoninHeaders -Evidence $evidence -Config $config -Offline:$Offline -Strict:$false
    Write-Ronin "Running OSINT investigation..." "INFO"
    $evidence = Invoke-RoninOsint -Evidence $evidence -Offline:$Offline
    if ($Json) { $evidence | ConvertTo-Json -Depth 12 }
    else { Show-RoninOsint -Evidence $evidence }
    exit 0
  }

  'quarantine' {
    if (-not $Mailbox -or -not $MessageId) { throw "Provide -Mailbox and -MessageId" }
    $result = Invoke-RoninQuarantine -Config $config -Mailbox $Mailbox -MessageId $MessageId -Action $Action -DryRun:$DryRun
    if ($Json) { $result | ConvertTo-Json -Depth 10 }
    else { $result | Format-List * }
    exit 0
  }

  'triage' {
    $evidence = New-RoninEvidence -Config $config
    if ($Eml) { $evidence = Import-RoninEml -Evidence $evidence -Path $Eml }
    if ($HeadersFile) { $evidence.Raw.Headers = Get-Content -Raw -Path $HeadersFile }
    if ($DocPath) { $evidence = Invoke-RoninDoc -Evidence $evidence -Path $DocPath }

    # Auto-analyze MIME-extracted attachments (DOCX, OLE, images)
    if ($evidence.Raw.ContainsKey('ExtractedAttachments') -and $evidence.Raw.ExtractedAttachments) {
      foreach ($att in $evidence.Raw.ExtractedAttachments) {
        $ext = [IO.Path]::GetExtension($att.Path).ToLowerInvariant()
        if (-not $DocPath -and ($ext -eq '.docx' -or $ext -eq '.doc')) {
          Write-Ronin "Auto-analyzing extracted attachment: $($att.Filename)" "INFO"
          $evidence = Invoke-RoninDoc -Evidence $evidence -Path $att.Path
        }
        elseif ($ext -match '\.(png|jpe?g|gif|bmp)$') {
          Write-Ronin "Auto-analyzing extracted image: $($att.Filename)" "INFO"
          $evidence = Invoke-RoninImage -Evidence $evidence -Path $att.Path
        }
      }
    }

    $evidence = Invoke-RoninHeaders -Evidence $evidence -Config $config -Offline:$Offline -Strict:$Strict

    # MIME Forensics (boundary fingerprinting, body evasion, EOP headers)
    Write-Ronin "Running MIME forensics..." "INFO"
    $evidence = Invoke-RoninMimeForensics -Evidence $evidence

    Write-Ronin "Running OSINT investigation..." "INFO"
    $evidence = Invoke-RoninOsint -Evidence $evidence -Offline:$Offline

    # Wayback Machine archive lookup (online only)
    if (-not $Offline) {
      Write-Ronin "Querying Internet Archive (Wayback)..." "INFO"
      $evidence = Invoke-RoninWayback -Evidence $evidence -IncludeSubdomains

      # OSINT-GodMode phone number intelligence (online only)
      Write-Ronin "Running phone number intelligence (GodMode)..." "INFO"
      $evidence = Invoke-RoninGodMode -Evidence $evidence -Depth quick
    }

    $evidence = Invoke-RoninTriage -Evidence $evidence -Config $config

    if ($HtmlReport -or $ReportPath) {
      if (-not $ReportPath) {
        $ReportPath = Join-Path $OutDir ("ronin-triage-{0}.html" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
      }
      $null = New-RoninHtmlReport -Evidence $evidence -TemplatePath (Join-Path $here "templates\triage-report.html") -OutPath $ReportPath
      Write-Ronin "HTML report written: $ReportPath" "OK"
    }

    if ($Json) { $evidence | ConvertTo-Json -Depth 12 }
    else { Show-RoninTriage -Evidence $evidence }
    exit 0
  }
}
