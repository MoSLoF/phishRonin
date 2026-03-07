param(
  [Parameter(Mandatory=$true)][string]$EmlPath,
  [string]$OutDir = ".\out",
  [int]$EnvironmentSoakSeconds = 60,
  [switch]$Online
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- Logging -----------------------------------------------------------------------
function Write-Step {
  param([string]$Msg, [string]$Level='INFO')
  $ts = (Get-Date).ToString("HH:mm:ss.fff")
  $prefix = switch ($Level) {
    'OK'   { "[+]" }
    'WARN' { "[!]" }
    'ERR'  { "[x]" }
    default { "[*]" }
  }
  $color = switch ($Level) {
    'OK'   { "Green" }
    'WARN' { "Yellow" }
    'ERR'  { "Red" }
    default { "Cyan" }
  }
  Write-Host "  $ts $prefix $Msg" -ForegroundColor $color
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host ""
Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
Write-Host "  |            phishRonin Triage Pipeline v2.0                   |" -ForegroundColor DarkCyan
Write-Host "  |   QR/Quishing + MIME Forensics + Binary Analysis + OSINT    |" -ForegroundColor DarkCyan
Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
Write-Host ""
Write-Step "Target: $EmlPath"
Write-Step "Output: $OutDir"
Write-Host ""

# -- Phase 0: Environment Monitor (Pre-Triage) ------------------------------------
Write-Host "  -- Phase 0: Environment Monitor (Pre-Triage) --" -ForegroundColor White
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here "modules\RoninEnvironment.psm1") -Force
$envMonitor = Start-RoninEnvironment
Write-Step "Pre-triage baseline captured" "OK"
Write-Host ""

# -- Phase 1: Module Loading -------------------------------------------------------
Write-Host "  -- Phase 1: Module Loading --" -ForegroundColor White
$modules = @("RoninHeaders","RoninImage","RoninMimeForensics","RoninDoc","RoninOsint","RoninTriage","RoninWayback","RoninGodMode")
foreach ($mod in $modules) {
  $modPath = Join-Path $here "modules\$mod.psm1"
  Write-Step "Loading $mod..."
  Import-Module $modPath -Force
  Write-Step "$mod loaded" "OK"
}

$configPath = Join-Path $here "config\ronin.config.json"
Write-Step "Loading config: $configPath"
$config = Get-RoninConfig -Path $configPath
Write-Step "Config loaded (thresholds: suspicious=$($config.scoring.suspiciousThreshold), malicious=$($config.scoring.maliciousThreshold))" "OK"
Write-Host ""

if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# -- Phase 2: EML Ingestion -------------------------------------------------------
Write-Host "  -- Phase 2: EML Ingestion --" -ForegroundColor White
Write-Step "Initializing evidence object..."
$evidence = New-RoninEvidence -Config $config
Write-Step "CaseId: $($evidence.Meta.CaseId)"

Write-Step "Reading EML file..."
$evidence = Import-RoninEml -Evidence $evidence -Path $EmlPath
Write-Step "EML parsed" "OK"
Write-Step "  Subject:     $($evidence.Message.Subject)"
Write-Step "  From:        $($evidence.Message.From)"
if ($evidence.Message.To.Count -gt 0) { Write-Step "  To:          $($evidence.Message.To -join ', ')" }
Write-Step "  Date:        $($evidence.Message.Date)"
Write-Step "  Message-ID:  $($evidence.Message.MessageId)"
Write-Step "  Reply-To:    $($evidence.Message.ReplyTo)"
Write-Step "  Return-Path: $($evidence.Message.ReturnPath)"

# Body status
if ($evidence.Raw.IsEmptyHtmlBody) { Write-Step "  HTML Body:   EMPTY" "WARN" }
if ($evidence.Raw.IsEmptyTextBody) { Write-Step "  Text Body:   EMPTY" "WARN" }
if ($evidence.Raw.MimeBoundaries.Count -gt 0) {
  Write-Step "  MIME Boundaries: $($evidence.Raw.MimeBoundaries.Count)"
  foreach ($b in $evidence.Raw.MimeBoundaries) { Write-Step "    $b" }
}

$hasExtracted = $evidence.Raw.ContainsKey('ExtractedAttachments') -and $evidence.Raw.ExtractedAttachments
if ($hasExtracted) {
  Write-Step "MIME extracted $($evidence.Raw.ExtractedAttachments.Count) attachment(s):" "WARN"
  foreach ($att in $evidence.Raw.ExtractedAttachments) {
    Write-Step "  -> $($att.Filename) ($([math]::Round($att.Size/1024,1)) KB) [$($att.MimeType)]"
  }
} else {
  Write-Step "No MIME attachments extracted"
}
Write-Host ""

# -- Phase 3: Document Analysis (with Image/QR extraction) -------------------------
Write-Host "  -- Phase 3: Document + Image Analysis --" -ForegroundColor White
$docCount = 0
$imgCount = 0
if ($hasExtracted) {
  foreach ($att in $evidence.Raw.ExtractedAttachments) {
    $ext = [IO.Path]::GetExtension($att.Path).ToLowerInvariant()
    if ($ext -eq '.docx' -or $ext -eq '.doc') {
      $docCount++
      Write-Step "Analyzing: $($att.Filename) ($ext)"
      Write-Step "  Unzipping DOCX structure..."
      $evidence = Invoke-RoninDoc -Evidence $evidence -Path $att.Path
      $lastAtt = $evidence.Attachments | Where-Object { $_.Type -eq 'docx' } | Select-Object -Last 1
      if ($lastAtt -and $lastAtt.Type -eq 'docx') {
        Write-Step "  SHA256:              $($lastAtt.Findings.Sha256)"
        Write-Step "  External rels:       $($lastAtt.Findings.ExternalRelationships)" $(if($lastAtt.Findings.ExternalRelationships -gt 0){"WARN"}else{"OK"})
        Write-Step "  Embedded objects:    $($lastAtt.Findings.EmbeddedObjects)" $(if($lastAtt.Findings.EmbeddedObjects -gt 0){"WARN"}else{"OK"})
        Write-Step "  Payload URLs:        $($lastAtt.Findings.SuspiciousUrls)" $(if($lastAtt.Findings.SuspiciousUrls -gt 0){"WARN"}else{"OK"})
        if ($lastAtt.Findings.ContainsKey('QrCodesFound')) {
          Write-Step "  QR Codes:            $($lastAtt.Findings.QrCodesFound)" $(if($lastAtt.Findings.QrCodesFound -gt 0){"ERR"}else{"OK"})
          if ($lastAtt.Findings.QrCodesFound -gt 0) {
            foreach ($img in $lastAtt.Findings.Images) {
              if ($img.HasQR) { Write-Step "    QR in $($img.Name): $($img.QrPayload)" "ERR" }
            }
          }
        }
        if ($lastAtt.Findings.ContainsKey('Images')) {
          Write-Step "  Images found:        $($lastAtt.Findings.Images.Count)"
        }
        if ($lastAtt.Findings.ContainsKey('MetadataZeroed')) {
          if ($lastAtt.Findings.MetadataZeroed) { Write-Step "  Metadata:            ZEROED (sanitized)" "WARN" }
        }
        if ($lastAtt.Findings.ContainsKey('LureKeywords')) {
          if ($lastAtt.Findings.LureKeywords.Count -gt 0) {
            $categories = @($lastAtt.Findings.LureKeywords | ForEach-Object { $_.Category } | Select-Object -Unique)
            Write-Step "  Lure keywords:       $($lastAtt.Findings.LureKeywords.Count) hits [$($categories -join ', ')]" "WARN"
          }
        }
        if ($lastAtt.Findings.ContainsKey('ZipStructure')) {
          $zs = $lastAtt.Findings.ZipStructure
          if ($zs.OverlayBytes -gt 0) { Write-Step "  ZIP overlay:         $($zs.OverlayBytes) bytes" "ERR" }
        }
        if (($lastAtt.Artifacts.Urls | Measure-Object).Count -gt 0) {
          Write-Step "  Extracted URLs:" "WARN"
          foreach ($u in $lastAtt.Artifacts.Urls) { Write-Step "    $u" "WARN" }
        }
      }
      Write-Step "Document analysis complete" "OK"
    }
    elseif ($ext -match '\.(png|jpe?g|gif|bmp)$') {
      $imgCount++
      Write-Step "Analyzing image: $($att.Filename)"
      $evidence = Invoke-RoninImage -Evidence $evidence -Path $att.Path
      $lastImg = $evidence.Attachments | Where-Object { $_.Type -eq 'image' } | Select-Object -Last 1
      if ($lastImg) {
        if ($lastImg.Findings.HasQrCode) {
          Write-Step "  [QR CODE] $($lastImg.Findings.QrPayloadType): $($lastImg.Findings.QrPayload)" "ERR"
        }
        $validPe = @($lastImg.Findings.MzSignatures | Where-Object { $_.IsValidPE })
        if ($validPe.Count -gt 0) { Write-Step "  [CRITICAL] Embedded PE executable!" "ERR" }
        if ($lastImg.Findings.HasTrailingData) { Write-Step "  [STEGO] Trailing data: $($lastImg.Findings.TrailingDataBytes) bytes" "WARN" }
      }
    }
  }
}
if ($docCount -eq 0) { Write-Step "No DOCX/DOC attachments to analyze" }
if ($imgCount -eq 0 -and $docCount -eq 0) { Write-Step "No standalone image attachments" }

# Image analysis summary
$imageAttachments = @($evidence.Attachments | Where-Object { $_.Type -eq 'image' })
if ($imageAttachments.Count -gt 0) {
  $qrImages = @($imageAttachments | Where-Object { $_.Findings.HasQrCode })
  $peImages = @($imageAttachments | Where-Object { @($_.Findings.MzSignatures | Where-Object { $_.IsValidPE }).Count -gt 0 })
  $stegoImages = @($imageAttachments | Where-Object { $_.Findings.HasTrailingData })
  Write-Step "Image summary: $($imageAttachments.Count) images, $($qrImages.Count) QR, $($peImages.Count) PE, $($stegoImages.Count) stego" $(if($qrImages.Count -gt 0 -or $peImages.Count -gt 0){"ERR"}elseif($stegoImages.Count -gt 0){"WARN"}else{"OK"})
}
Write-Host ""

# During-triage environment snapshot
$envMonitor = Add-RoninEnvironmentSnapshot -Monitor $envMonitor -Label 'after-doc-analysis'

# -- Phase 4: Header Analysis -----------------------------------------------------
Write-Host "  -- Phase 4: Header Analysis --" -ForegroundColor White
Write-Step "Parsing Authentication-Results, Received chain, IOCs..."
$evidence = Invoke-RoninHeaders -Evidence $evidence -Config $config -Offline -Strict:$false

$spfColor  = if($evidence.Auth.Spf  -eq 'pass'){"OK"}elseif($evidence.Auth.Spf  -eq 'fail'){"ERR"}else{"WARN"}
$dkimColor = if($evidence.Auth.Dkim -eq 'pass'){"OK"}elseif($evidence.Auth.Dkim -eq 'fail'){"ERR"}else{"WARN"}
$dmarcColor= if($evidence.Auth.Dmarc-eq 'pass'){"OK"}elseif($evidence.Auth.Dmarc-eq 'fail'){"ERR"}else{"WARN"}
Write-Step "  SPF:   $($evidence.Auth.Spf)"   $spfColor
Write-Step "  DKIM:  $($evidence.Auth.Dkim)"  $dkimColor
Write-Step "  DMARC: $($evidence.Auth.Dmarc)" $dmarcColor
Write-Step "  Received hops: $($evidence.Received.Hops.Count)"
Write-Step "  Origin IP:     $($evidence.Received.OriginIp)"
Write-Step "  Origin host:   $($evidence.Received.OriginHost)"
Write-Step "  IOCs found - IPs: $(@($evidence.Iocs.Ips).Count), Domains: $(@($evidence.Iocs.Domains).Count), URLs: $(@($evidence.Iocs.Urls).Count)"
Write-Step "Headers parsed" "OK"
Write-Host ""

# -- Phase 5: MIME Forensics -------------------------------------------------------
Write-Host "  -- Phase 5: MIME Forensics --" -ForegroundColor White
Write-Step "Boundary fingerprinting, body evasion, EOP headers..."
$evidence = Invoke-RoninMimeForensics -Evidence $evidence

if ($evidence.PSObject.Properties.Name -contains 'MimeForensics') {
  $mf = $evidence.MimeForensics
  if ($mf.BoundaryFingerprints.Count -gt 0) {
    foreach ($bf in $mf.BoundaryFingerprints) {
      $bfColor = if($bf.Classification -in @('standard','exchange')){"OK"}else{"WARN"}
      Write-Step ("  Boundary [{0}]: {1}" -f $bf.Classification, $bf.Boundary) $bfColor
    }
  }
  Write-Step "  Bodyless email:   $($mf.IsBodylessEmail)" $(if($mf.IsBodylessEmail){"ERR"}else{"OK"})
  Write-Step "  Image-only body:  $($mf.HasImageOnlyBody)" $(if($mf.HasImageOnlyBody){"WARN"}else{"OK"})
  Write-Step "  Attachment-only:  $($mf.AttachmentOnlyDelivery)" $(if($mf.AttachmentOnlyDelivery){"WARN"}else{"OK"})
  Write-Step "  Self-addressed:   $($mf.SelfAddressed)" $(if($mf.SelfAddressed){"WARN"}else{"OK"})
  if ($mf.HiddenDataAfterBoundary) { Write-Step "  Hidden data: $($mf.HiddenDataBytes) bytes after MIME boundary" "ERR" }
  if ($mf.EopScl -ne -2) {
    Write-Step "  EOP SCL: $($mf.EopScl)  Category: $($mf.EopCategory)  SFV: $($mf.EopSfv)"
  }
  if ($mf.Compauth.Result) {
    $caColor = if($mf.Compauth.Reason -match '^0'){"ERR"}else{"OK"}
    Write-Step "  Compauth: $($mf.Compauth.Result) (reason=$($mf.Compauth.Reason): $($mf.Compauth.Description))" $caColor
  }
  if ($mf.HtmlFindings.Count -gt 0) {
    Write-Step "  HTML findings: $($mf.HtmlFindings.Count)" "WARN"
    foreach ($hf in $mf.HtmlFindings) { Write-Step "    $hf" "WARN" }
  }
  if ($mf.Findings.Count -gt 0) {
    Write-Step "  Forensic findings: $($mf.Findings.Count)" "WARN"
  }
}
Write-Step "MIME forensics complete" "OK"
Write-Host ""

# -- Phase 6: OSINT Investigation -------------------------------------------------
$osintMode = if ($Online) { "Online" } else { "Offline" }
Write-Host "  -- Phase 6: OSINT Investigation ($osintMode) --" -ForegroundColor White
Write-Step "Generating pivot links and threat classification..."
$evidence = Invoke-RoninOsint -Evidence $evidence -Offline:(-not $Online)
$ipCount = ($evidence.Osint.IpProfiles | Measure-Object).Count
$domCount = ($evidence.Osint.DomainProfiles | Measure-Object).Count
$pivotCount = ($evidence.Osint.PivotLinks | Measure-Object).Count
Write-Step "  IP profiles:     $ipCount"
Write-Step "  Domain profiles: $domCount"
Write-Step "  Pivot links:     $pivotCount"
Write-Step "  Threat class:    $($evidence.Osint.ThreatClassification.OverallType) ($($evidence.Osint.ThreatClassification.Confidence))"
Write-Step "OSINT complete" "OK"
Write-Host ""

# -- Phase 6b: Internet Archive (Wayback) -- Online only --------------------------
if ($Online) {
  Write-Host "  -- Phase 6b: Internet Archive (Wayback) --" -ForegroundColor White
  Write-Step "Querying Wayback Machine CDX API for archived snapshots..."
  $evidence = Invoke-RoninWayback -Evidence $evidence -IncludeSubdomains
  if ($evidence.PSObject.Properties.Name -contains 'Wayback') {
    $wb = $evidence.Wayback
    foreach ($d in $wb.Domains) {
      Write-Step "  $($d.Domain): $($d.TotalSnapshots) snapshot(s)" $(if($d.TotalSnapshots -gt 0){"OK"}else{"WARN"})
      if ($d.FirstSeen) { Write-Step "    First seen: $(Format-WaybackDate $d.FirstSeen)  |  Last seen: $(Format-WaybackDate $d.LastSeen)" }
      if (@($d.PhishPagesFound).Count -gt 0) {
        Write-Step "    Phishing paths: $(@($d.PhishPagesFound).Count) hit(s)" "ERR"
        foreach ($pp in $d.PhishPagesFound) {
          Write-Step "      [$($pp.Date)] $($pp.Path) (HTTP $($pp.StatusCode))" "ERR"
          Write-Step "        -> $($pp.WaybackUrl)" "WARN"
        }
      }
      if (@($d.SubdomainsFound).Count -gt 0) {
        Write-Step "    Subdomains: $($d.SubdomainsFound -join ', ')" "WARN"
      }
      if ($d.ConfigExposed) { Write-Step "    [!] Config/env files found in archive!" "ERR" }
    }
    Write-Step "$($wb.Summary)" "OK"
  }
  Write-Host ""
} else {
  Write-Host "  -- Phase 6b: Internet Archive (Wayback) [SKIPPED - use -Online] --" -ForegroundColor DarkGray
  Write-Host ""
}

# -- Phase 6c: OSINT-GodMode Phone Intelligence -- Online only --------------------
if ($Online) {
  Write-Host "  -- Phase 6c: Phone Intelligence (OSINT-GodMode) --" -ForegroundColor White
  Write-Step "Extracting phone numbers and querying intelligence..."
  $evidence = Invoke-RoninGodMode -Evidence $evidence -Depth quick
  if ($evidence.PSObject.Properties.Name -contains 'GodMode') {
    $gm = $evidence.GodMode
    Write-Step "  Phone numbers found: $($gm.TotalFound)"
    if ($gm.TotalFound -gt 0) {
      foreach ($p in $gm.PhoneNumbers) {
        Write-Step "    $($p.Normalized) (from $($p.Source))"
      }
    }
    foreach ($inv in $gm.Investigations) {
      if ($inv.Success) {
        $repInfo = ""
        if ($inv.Data.reputation) {
          $spam = if ($inv.Data.reputation.spam_score) { "$($inv.Data.reputation.spam_score)/10" } else { "N/A" }
          $fraud = if ($inv.Data.reputation.fraud_risk) { $inv.Data.reputation.fraud_risk } else { "unknown" }
          $repInfo = "spam=$spam fraud=$fraud"
        }
        $carrierInfo = ""
        if ($inv.Data.carrier_info -and $inv.Data.carrier_info.carrier) {
          $lineType = if ($inv.Data.carrier_info.line_type) { $inv.Data.carrier_info.line_type } else { "?" }
          $carrierInfo = "$($inv.Data.carrier_info.carrier) ($lineType)"
        }
        $invColor = if ($inv.Data.reputation -and $inv.Data.reputation.is_scam) { "ERR" } else { "OK" }
        Write-Step "  $($inv.PhoneNumber): $repInfo  $carrierInfo" $invColor
        if ($inv.Data.reputation -and $inv.Data.reputation.is_scam) {
          Write-Step "    [!] SCAM NUMBER DETECTED" "ERR"
        }
        if ($inv.Data.carrier_info -and $inv.Data.carrier_info.line_type -match '(?i)voip') {
          Write-Step "    [!] VoIP/Burner line detected" "WARN"
        }
        if ($inv.Data.breach_data -and $inv.Data.breach_data.found_in_breaches) {
          Write-Step "    [!] Found in $($inv.Data.breach_data.breach_count) breach(es)" "WARN"
        }
      }
    }
    Write-Step "$($gm.Summary)" "OK"
  }
  Write-Host ""
} else {
  Write-Host "  -- Phase 6c: Phone Intelligence (OSINT-GodMode) [SKIPPED - use -Online] --" -ForegroundColor DarkGray
  Write-Host ""
}

# -- Phase 7: Scoring & Verdict ---------------------------------------------------
Write-Host "  -- Phase 7: Triage Scoring --" -ForegroundColor White
Write-Step "Computing risk score..."
$evidence = Invoke-RoninTriage -Evidence $evidence -Config $config

$verdictColor = switch ($evidence.Score.Verdict) {
  'malicious'  { "ERR" }
  'suspicious' { "WARN" }
  default      { "OK" }
}
Write-Host ""
Write-Step "==================================================" $verdictColor
Write-Step "  VERDICT: $($evidence.Score.Verdict.ToUpper())  |  SCORE: $($evidence.Score.Total)/100" $verdictColor
Write-Step "==================================================" $verdictColor
Write-Host ""
Write-Step "Scoring reasons:"
foreach ($r in $evidence.Score.Reasons) { Write-Step "  $r" }
Write-Host ""
if ($evidence.Actions.Suggested.Count -gt 0) {
  Write-Step "Suggested actions:" "WARN"
  foreach ($a in $evidence.Actions.Suggested) { Write-Step "  -> $a" "WARN" }
  Write-Host ""
}

# -- Phase 8: Report Generation ---------------------------------------------------
Write-Host "  -- Phase 8: Report Generation --" -ForegroundColor White
$ts = Get-Date -Format "yyyyMMdd-HHmmss"

$reportPath = Join-Path $OutDir "ronin-triage-$ts.html"
Write-Step "Generating HTML report..."
$null = New-RoninHtmlReport -Evidence $evidence -TemplatePath (Join-Path $here "templates\triage-report.html") -OutPath $reportPath
Write-Step "HTML report: $reportPath" "OK"

$jsonPath = Join-Path $OutDir "ronin-triage-$ts.json"
Write-Step "Writing JSON evidence..."
$evidence | ConvertTo-Json -Depth 12 | Set-Content -Path $jsonPath -Encoding UTF8
Write-Step "JSON output: $jsonPath" "OK"
Write-Host ""

# -- Phase 9: Environment Monitor (Post-Triage) -----------------------------------
Write-Host "  -- Phase 9: Environment Monitor (Post-Triage) --" -ForegroundColor White
Write-Step "Waiting $EnvironmentSoakSeconds seconds for post-triage observation..."
$envMonitor = Stop-RoninEnvironment -Monitor $envMonitor -DelaySeconds $EnvironmentSoakSeconds

# Save environment monitor data
$envPath = Join-Path $OutDir "ronin-environment-$ts.json"
$envMonitor | ConvertTo-Json -Depth 10 | Set-Content -Path $envPath -Encoding UTF8
Write-Step "Environment data: $envPath" "OK"

if ($envMonitor.Findings.Count -gt 0) {
  Write-Step "Environment findings:" "WARN"
  foreach ($f in $envMonitor.Findings) { Write-Step "  $f" "WARN" }
} else {
  Write-Step "No anomalous environment activity detected" "OK"
}
Write-Host ""

$sw.Stop()
Write-Host ""
Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
Write-Host "  |  Pipeline complete in $([math]::Round($sw.Elapsed.TotalSeconds,2))s                              |" -ForegroundColor DarkCyan
Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
Write-Host ""
