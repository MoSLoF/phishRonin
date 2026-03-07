Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── ZXing.NET Loader ─────────────────────────────────────────────────────────

$script:ZXingAvailable = $false
$zxingPath = Join-Path $PSScriptRoot '..\lib\ZXing.Net\zxing.dll'
if (Test-Path $zxingPath) {
  try {
    Add-Type -Path $zxingPath
    $script:ZXingAvailable = $true
  } catch {
    Write-Warning "RoninImage: ZXing.NET load failed: $_"
  }
}

# ── Known malware/tool signatures ────────────────────────────────────────────

$script:MalwarePatterns = @(
  'mimikatz', 'sekurlsa', 'kerberos::', 'lsadump', 'dpapi::',
  'wdigest', 'logonpasswords', 'privilege::debug', 'token::elevate',
  'crypto::capi', 'vault::cred', 'lsass', 'gentilkiwi', 'benjamin delpy',
  'mimilib', 'mimidrv', 'kuhl_m', 'kull_m'
)
$script:ScriptPatterns = @(
  'powershell', 'cmd\.exe', 'wscript', 'cscript', 'mshta',
  'certutil', 'bitsadmin', 'regsvr32', 'rundll32',
  'Invoke-Expression', 'DownloadString', 'DownloadFile',
  'FromBase64String', 'EncodedCommand', 'IEX\('
)

# ── Main Entry Point ─────────────────────────────────────────────────────────

function Invoke-RoninImage {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Evidence,
    [Parameter(Mandatory=$true)][string]$Path
  )
  if (!(Test-Path $Path)) {
    $Evidence.Auth.Notes += "Image not found: $Path"
    return $Evidence
  }

  $bytes = [IO.File]::ReadAllBytes($Path)
  $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
  $hash = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
  $fileName = [IO.Path]::GetFileName($Path)

  # Determine image format
  $format = 'unknown'
  if ($ext -in @('.png'))          { $format = 'png' }
  elseif ($ext -in @('.jpg','.jpeg')) { $format = 'jpeg' }
  elseif ($ext -in @('.gif'))      { $format = 'gif' }
  elseif ($ext -in @('.bmp'))      { $format = 'bmp' }
  elseif ($ext -in @('.tif','.tiff')) { $format = 'tiff' }

  # Initialize findings
  $findings = @{
    HasQrCode          = $false
    QrPayload          = ''
    QrPayloadType      = 'none'
    QrDomainMismatch   = $false
    ImageFormat        = $format
    ImageSizeBytes     = $bytes.Length
    Sha256             = $hash
    FileName           = $fileName
    HasTrailingData    = $false
    TrailingDataBytes  = 0
    TrailingDataMagic  = 'none'
    PngChunks          = @()
    SuspiciousPngChunks = @()
    MzSignatures       = @()
    MalwareStrings     = @()
    ScriptPatterns     = @()
    Note               = ''
  }
  $qrUrls = @()
  $qrDomains = @()

  # ── 1. QR Code Decode ──────────────────────────────────────────────────
  if ($script:ZXingAvailable) {
    try {
      $bitmap = [System.Drawing.Bitmap]::FromFile($Path)
      $reader = New-Object ZXing.BarcodeReader
      $reader.Options.TryHarder = $true
      $result = $reader.Decode($bitmap)
      $bitmap.Dispose()

      if ($result) {
        $findings.HasQrCode = $true
        $findings.QrPayload = $result.Text

        # Classify payload type
        if ($result.Text -match '(?i)^https?://') {
          $findings.QrPayloadType = 'url'
          $qrUrls += $result.Text
          try {
            $uri = [uri]$result.Text
            if ($uri.Host) { $qrDomains += $uri.Host.ToLowerInvariant() }
          } catch {}

          # Check domain mismatch with sender
          if ($Evidence.Message.From) {
            $fromMatch = [regex]::Match($Evidence.Message.From, '@([a-z0-9.\-]+\.[a-z]{2,63})')
            if ($fromMatch.Success -and $qrDomains.Count -gt 0) {
              $senderDomain = $fromMatch.Groups[1].Value.ToLowerInvariant()
              if ($qrDomains[0] -ne $senderDomain) {
                $findings.QrDomainMismatch = $true
              }
            }
          }
        }
        elseif ($result.Text -match '(?i)^BEGIN:VCARD') { $findings.QrPayloadType = 'vcard' }
        elseif ($result.Text -match '(?i)^WIFI:')       { $findings.QrPayloadType = 'wifi' }
        elseif ($result.Text -match '(?i)^mailto:')     { $findings.QrPayloadType = 'url' }
        else { $findings.QrPayloadType = 'text' }
      }
    } catch {
      $findings.Note = "QR decode error: $_"
    }
  } else {
    $findings.Note = "QR decode unavailable (ZXing.NET not found in lib/)"
  }

  # ── 2. Image Structure Forensics ───────────────────────────────────────
  if ($format -eq 'jpeg') {
    $findings = Test-RoninJpegStructure -Bytes $bytes -Findings $findings
  }
  elseif ($format -eq 'png') {
    $findings = Test-RoninPngStructure -Bytes $bytes -Findings $findings
  }

  # ── 3. PE/MZ Signature Scan ────────────────────────────────────────────
  $findings = Find-RoninMzSignatures -Bytes $bytes -Findings $findings

  # ── 4. Malware/Script String Scan ──────────────────────────────────────
  $findings = Find-RoninMalwareStrings -Bytes $bytes -Findings $findings

  # ── 5. Build attachment record ─────────────────────────────────────────
  $Evidence.Attachments += [PSCustomObject]@{
    Path      = $Path
    Type      = 'image'
    Findings  = $findings
    Artifacts = @{
      QrUrls    = $qrUrls
      QrDomains = $qrDomains
      Hashes    = @($hash)
    }
  }

  # Add to global IOC bag
  $Evidence.Iocs.Hashes += $hash
  if ($qrUrls.Count -gt 0)    { $Evidence.Iocs.Urls    += $qrUrls }
  if ($qrDomains.Count -gt 0) { $Evidence.Iocs.Domains += $qrDomains }

  return $Evidence
}

# ── JPEG Structure Analysis ──────────────────────────────────────────────────

function Test-RoninJpegStructure {
  param([byte[]]$Bytes, [hashtable]$Findings)

  # Find last FFD9 (JPEG end-of-image marker)
  for ($i = $Bytes.Length - 2; $i -ge 0; $i--) {
    if ($Bytes[$i] -eq 0xFF -and $Bytes[$i+1] -eq 0xD9) {
      $trailing = $Bytes.Length - ($i + 2)
      if ($trailing -gt 0) {
        $Findings.HasTrailingData   = $true
        $Findings.TrailingDataBytes = $trailing
        $trailStart = $i + 2
        # Check magic bytes of trailing data
        if ($trailing -ge 2) {
          if ($Bytes[$trailStart] -eq 0x4D -and $Bytes[$trailStart+1] -eq 0x5A) {
            $Findings.TrailingDataMagic = 'MZ'
          }
          elseif ($Bytes[$trailStart] -eq 0x50 -and $Bytes[$trailStart+1] -eq 0x4B) {
            $Findings.TrailingDataMagic = 'PK'
          }
          else {
            $Findings.TrailingDataMagic = 'unknown'
          }
        }
      }
      break
    }
  }
  return $Findings
}

# ── PNG Structure Analysis ───────────────────────────────────────────────────

function Test-RoninPngStructure {
  param([byte[]]$Bytes, [hashtable]$Findings)

  $chunks = @()
  $suspiciousChunks = @()

  # Walk PNG chunks (skip 8-byte PNG signature)
  $pos = 8
  while ($pos -lt $Bytes.Length - 12) {
    # Chunk length is big-endian 4 bytes
    $chunkLen = ([int]$Bytes[$pos] -shl 24) -bor ([int]$Bytes[$pos+1] -shl 16) -bor ([int]$Bytes[$pos+2] -shl 8) -bor [int]$Bytes[$pos+3]
    if ($chunkLen -lt 0 -or ($pos + 12 + $chunkLen) -gt $Bytes.Length) { break }

    $chunkType = [Text.Encoding]::ASCII.GetString($Bytes, $pos+4, 4)
    $chunks += [PSCustomObject]@{ Type = $chunkType; Length = $chunkLen; Offset = $pos }

    # Flag suspicious text chunks
    if ($chunkType -in @('tEXt', 'zTXt', 'iTXt')) {
      $preview = ''
      if ($chunkLen -lt 500 -and $chunkLen -gt 0) {
        $preview = [Text.Encoding]::ASCII.GetString($Bytes, $pos+8, $chunkLen) -replace '[^\x20-\x7E]','.'
      }
      $suspiciousChunks += [PSCustomObject]@{
        Type    = $chunkType
        Length  = $chunkLen
        Offset  = $pos
        Preview = $preview
      }
    }

    $pos += $chunkLen + 12  # 4 len + 4 type + data + 4 CRC
    if ($chunkType -eq 'IEND') { break }
  }

  $Findings.PngChunks = $chunks
  $Findings.SuspiciousPngChunks = $suspiciousChunks

  # Check for trailing data after IEND
  $iendSig = @(0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82)
  for ($i = $Bytes.Length - 8; $i -ge 0; $i--) {
    $match = $true
    for ($j = 0; $j -lt 8; $j++) {
      if ($Bytes[$i+$j] -ne $iendSig[$j]) { $match = $false; break }
    }
    if ($match) {
      $trailing = $Bytes.Length - ($i + 8)
      if ($trailing -gt 0) {
        $Findings.HasTrailingData   = $true
        $Findings.TrailingDataBytes = $trailing
        $trailStart = $i + 8
        if ($trailing -ge 2) {
          if ($Bytes[$trailStart] -eq 0x4D -and $Bytes[$trailStart+1] -eq 0x5A) {
            $Findings.TrailingDataMagic = 'MZ'
          }
          elseif ($Bytes[$trailStart] -eq 0x50 -and $Bytes[$trailStart+1] -eq 0x4B) {
            $Findings.TrailingDataMagic = 'PK'
          }
          else { $Findings.TrailingDataMagic = 'unknown' }
        }
      }
      break
    }
  }

  return $Findings
}

# ── PE/MZ Signature Scanner ──────────────────────────────────────────────────

function Find-RoninMzSignatures {
  param([byte[]]$Bytes, [hashtable]$Findings)

  $mzHits = @()
  # Skip first 2 bytes (could be the image header itself)
  for ($i = 2; $i -lt $Bytes.Length - 64; $i++) {
    if ($Bytes[$i] -eq 0x4D -and $Bytes[$i+1] -eq 0x5A) {
      $pePointer = [BitConverter]::ToInt32($Bytes, $i + 60)
      $isValidPe = $false
      $details = "e_lfanew=$pePointer"

      if ($pePointer -gt 0 -and $pePointer -lt 4096) {
        $peAbsolute = $i + $pePointer
        if (($peAbsolute + 4) -lt $Bytes.Length) {
          if ($Bytes[$peAbsolute] -eq 0x50 -and $Bytes[$peAbsolute+1] -eq 0x45 -and
              $Bytes[$peAbsolute+2] -eq 0x00 -and $Bytes[$peAbsolute+3] -eq 0x00) {
            $isValidPe = $true
            $machineType = [BitConverter]::ToUInt16($Bytes, $peAbsolute + 4)
            $machineStr = switch ($machineType) {
              0x014C { "x86" }
              0x8664 { "x64" }
              0x01C0 { "ARM" }
              0xAA64 { "ARM64" }
              default { "0x{0:X4}" -f $machineType }
            }
            $numSections = [BitConverter]::ToUInt16($Bytes, $peAbsolute + 6)
            $timestamp = [BitConverter]::ToUInt32($Bytes, $peAbsolute + 8)
            $details = "VALID PE: $machineStr, $numSections sections, timestamp=$timestamp"
          } else {
            $details = "e_lfanew=$pePointer, PE sig not found at offset $peAbsolute (coincidental MZ)"
          }
        }
      } else {
        $details = "e_lfanew=$pePointer out of range (coincidental MZ in compressed data)"
      }

      $mzHits += [PSCustomObject]@{
        Offset    = $i
        IsValidPE = $isValidPe
        Details   = $details
      }
    }
  }
  $Findings.MzSignatures = $mzHits
  return $Findings
}

# ── Malware/Script String Scanner ────────────────────────────────────────────

function Find-RoninMalwareStrings {
  param([byte[]]$Bytes, [hashtable]$Findings)

  $asciiStr = [Text.Encoding]::ASCII.GetString($Bytes)
  $asciiLower = $asciiStr.ToLowerInvariant()

  # Also check UTF-16LE (common in Windows binaries)
  $utf16Str = ''
  try { $utf16Str = [Text.Encoding]::Unicode.GetString($Bytes).ToLowerInvariant() } catch {}

  $malwareHits = @()
  foreach ($pat in $script:MalwarePatterns) {
    $patLower = $pat.ToLowerInvariant()
    if ($asciiLower.Contains($patLower)) {
      $idx = $asciiLower.IndexOf($patLower)
      $malwareHits += [PSCustomObject]@{ Pattern=$pat; Encoding='ASCII'; ByteOffset=$idx }
    }
    if ($utf16Str -and $utf16Str.Contains($patLower)) {
      $idx = $utf16Str.IndexOf($patLower)
      $malwareHits += [PSCustomObject]@{ Pattern=$pat; Encoding='UTF-16LE'; CharOffset=$idx }
    }
  }
  $Findings.MalwareStrings = $malwareHits

  $scriptHits = @()
  foreach ($pat in $script:ScriptPatterns) {
    if ($asciiStr -match $pat) {
      $scriptHits += [PSCustomObject]@{ Pattern=$pat; Encoding='ASCII' }
    }
  }
  $Findings.ScriptPatterns = $scriptHits

  return $Findings
}

# ── Console Display ──────────────────────────────────────────────────────────

function Show-RoninImage {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Evidence)

  "=== RoninImage ==="
  foreach ($a in $Evidence.Attachments) {
    if ($a.Type -ne 'image') { continue }
    $f = $a.Findings
    "File: {0} ({1}) [{2:N0} bytes]" -f $f.FileName, $f.ImageFormat, $f.ImageSizeBytes
    "  SHA256: {0}" -f $f.Sha256

    if ($f.HasQrCode) {
      "  [QR CODE DETECTED] Type: {0}" -f $f.QrPayloadType
      "  QR Payload: {0}" -f $f.QrPayload
      if ($f.QrDomainMismatch) {
        "  [ALERT] QR domain differs from sender domain!"
      }
    } else {
      "  No QR code detected"
    }

    if ($f.HasTrailingData) {
      "  [STEGO] {0} bytes trailing data (magic: {1})" -f $f.TrailingDataBytes, $f.TrailingDataMagic
    }

    if ($f.SuspiciousPngChunks.Count -gt 0) {
      "  [SUSPICIOUS] {0} text chunk(s) in PNG:" -f $f.SuspiciousPngChunks.Count
      foreach ($c in $f.SuspiciousPngChunks) {
        "    {0} ({1} bytes)" -f $c.Type, $c.Length
      }
    }

    $validPe = @($f.MzSignatures | Where-Object { $_.IsValidPE })
    $coincidental = @($f.MzSignatures | Where-Object { -not $_.IsValidPE })
    if ($validPe.Count -gt 0) {
      "  [CRITICAL] {0} EMBEDDED PE(s) found!" -f $validPe.Count
      foreach ($pe in $validPe) { "    Offset {0}: {1}" -f $pe.Offset, $pe.Details }
    }
    if ($coincidental.Count -gt 0) {
      "  MZ byte patterns: {0} (all coincidental in compressed data)" -f $coincidental.Count
    }

    if ($f.MalwareStrings.Count -gt 0) {
      "  [MALWARE] {0} known tool signature(s):" -f $f.MalwareStrings.Count
      foreach ($m in $f.MalwareStrings) { "    {0} ({1})" -f $m.Pattern, $m.Encoding }
    }
    if ($f.ScriptPatterns.Count -gt 0) {
      "  [SCRIPT] {0} execution pattern(s):" -f $f.ScriptPatterns.Count
      foreach ($s in $f.ScriptPatterns) { "    {0}" -f $s.Pattern }
    }

    if ($f.Note) { "  Note: {0}" -f $f.Note }
    ""
  }
}

Export-ModuleMember -Function Invoke-RoninImage, Show-RoninImage
