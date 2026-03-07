Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- Schema namespace URIs to filter from URL counts (not payload URLs) --------
$script:SchemaFilters = @(
  'schemas.openxmlformats.org',
  'schemas.microsoft.com',
  'purl.org',
  'www.w3.org',
  'purl.oclc.org',
  'xmlpull.org'
)

# -- Lure keyword sets for document text scanning -----------------------------
$script:LureKeywords = @{
  CredentialHarvest = @('sign-in','sign in','verify your account','confirm your account','password','credentials','log in','login','authenticate')
  QrLure           = @('scan','qr code','scan to view','scan below','use your phone','scan the code','point your camera')
  Urgency          = @('immediate','urgent','expires','within 24 hours','action required','time-sensitive','respond now','deadline')
  Authority        = @('it department','helpdesk','administrator','security team','human resources','hr department','compliance')
}

function Invoke-RoninDoc {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Evidence,
    [Parameter(Mandatory=$true)][string]$Path
  )
  if (!(Test-Path $Path)) { throw "Doc not found: $Path" }
  $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
  if ($ext -ne ".docx") {
    $Evidence.Attachments += [PSCustomObject]@{
      Path = (Resolve-Path $Path).Path
      Type = 'unknown'
      Findings = @{ Note = "Unsupported file type: $ext" }
      Artifacts = @{ Urls=@(); Domains=@(); Hashes=@(); Files=@() }
    }
    return $Evidence
  }

  $docxPath = (Resolve-Path $Path).Path
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ronin-docx-" + [guid]::NewGuid().ToString())
  New-Item -ItemType Directory -Path $tmp | Out-Null

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  try {
    [System.IO.Compression.ZipFile]::ExtractToDirectory($docxPath, $tmp)
  } catch {
    $hash = (Get-FileHash -Algorithm SHA256 -Path $docxPath).Hash.ToLowerInvariant()
    $Evidence.Attachments += [PSCustomObject]@{
      Path = $docxPath
      Type = 'docx'
      Findings = @{
        ExternalRelationships = 0
        EmbeddedObjects       = 0
        SuspiciousUrls        = 0
        Sha256                = $hash
        Note                  = "ZIP extraction failed: $_  (file may be weaponized/obfuscated)"
        QrCodesFound          = 0
        Images                = @()
        DocumentText          = ''
        DocumentMetadata      = @{}
        MetadataZeroed        = $false
        TrackingPixels        = @()
        ZipStructure          = @{}
        LureKeywords          = @()
      }
      Artifacts = @{ ExternalRelationships=@(); Urls=@(); Domains=@(); Hashes=@($hash); Files=@() }
    }
    $Evidence.Iocs.Hashes += $hash
    try { Remove-Item -Recurse -Force -Path $tmp } catch {}
    return $Evidence
  }

  # -- Analyze relationships for external targets --------------------------------
  $rels = Get-ChildItem -Path $tmp -Recurse -Filter "*.rels" -ErrorAction SilentlyContinue
  $external = @()
  $urls = @()
  $trackingPixels = @()
  foreach ($r in $rels) {
    $xml = Get-Content -Raw -Path $r.FullName
    # External relationship targets
    $matches = [regex]::Matches($xml, 'TargetMode="External"[^>]*Target="([^"]+)"')
    foreach ($m in $matches) {
      $t = $m.Groups[1].Value
      $external += [PSCustomObject]@{ File=$r.FullName; Target=$t }
      if ($t -match "(?i)^https?://") { $urls += $t }
    }
    # Also check for Target before TargetMode (attribute order can vary)
    $matches1b = [regex]::Matches($xml, 'Target="([^"]+)"[^>]*TargetMode="External"')
    foreach ($m in $matches1b) {
      $t = $m.Groups[1].Value
      if ($external.Target -notcontains $t) {
        $external += [PSCustomObject]@{ File=$r.FullName; Target=$t }
        if ($t -match "(?i)^https?://") { $urls += $t }
      }
    }

    # Detect external image references (tracking pixels)
    $imgRels = [regex]::Matches($xml, 'Type="[^"]*image"[^>]*TargetMode="External"[^>]*Target="([^"]+)"')
    foreach ($m in $imgRels) { $trackingPixels += $m.Groups[1].Value }
    $imgRels2 = [regex]::Matches($xml, 'TargetMode="External"[^>]*Type="[^"]*image"[^>]*Target="([^"]+)"')
    foreach ($m in $imgRels2) {
      if ($trackingPixels -notcontains $m.Groups[1].Value) { $trackingPixels += $m.Groups[1].Value }
    }

    # Capture http(s) URLs anywhere in rels (best-effort)
    $urlPat = '(?i)\bhttps?://[^\s<>\]"' + "'" + ']+'
    $matches2 = [regex]::Matches($xml, $urlPat)
    foreach ($m in $matches2) { $urls += $m.Value.TrimEnd(')','.', ';', ',') }
  }

  # Filter schema namespace URLs from suspicious URL list
  $payloadUrls = @()
  foreach ($u in ($urls | Select-Object -Unique)) {
    $isSchema = $false
    foreach ($sf in $script:SchemaFilters) {
      if ($u -match [regex]::Escape($sf)) { $isSchema = $true; break }
    }
    if (-not $isSchema) { $payloadUrls += $u }
  }

  # Embedded objects
  $embeddings = Get-ChildItem -Path (Join-Path $tmp "word\embeddings") -ErrorAction SilentlyContinue
  $embeddedCount = if ($embeddings) { $embeddings.Count } else { 0 }

  # -- Domain extraction from payload URLs ----------------------------------------
  $domains = @()
  foreach ($u in $payloadUrls) {
    try {
      $uri = [uri]$u
      if ($uri.Host) { $domains += $uri.Host.ToLowerInvariant() }
    } catch {}
  }
  $domains = $domains | Select-Object -Unique

  # Hash the doc
  $hash = (Get-FileHash -Algorithm SHA256 -Path $docxPath).Hash.ToLowerInvariant()

  # -- Document Text Extraction (word/document.xml) --------------------------------
  $docText = ''
  $docXmlPath = Join-Path $tmp "word\document.xml"
  if (Test-Path $docXmlPath) {
    try {
      [xml]$docXml = Get-Content -Raw -Path $docXmlPath
      $nsMgr = New-Object System.Xml.XmlNamespaceManager($docXml.NameTable)
      $nsMgr.AddNamespace('w', 'http://schemas.openxmlformats.org/wordprocessingml/2006/main')
      $tNodes = $docXml.SelectNodes('//w:t', $nsMgr)
      $textParts = @()
      foreach ($node in $tNodes) {
        if ($node.InnerText) { $textParts += $node.InnerText }
      }
      $docText = ($textParts -join ' ').Trim()
    } catch {
      $docText = "(parse error: $_)"
    }
  }

  # -- Document Metadata Extraction -----------------------------------------------
  $metadata = @{
    Title          = ''
    Creator        = ''
    Description    = ''
    LastModifiedBy = ''
    Revision       = ''
    Created        = ''
    Modified       = ''
    Application    = ''
    AppVersion     = ''
    Pages          = -1
    Words          = -1
    Characters     = -1
  }
  $metadataZeroed = $false

  # docProps/core.xml
  $corePath = Join-Path $tmp "docProps\core.xml"
  if (Test-Path $corePath) {
    try {
      [xml]$coreXml = Get-Content -Raw -Path $corePath
      $nsMgr = New-Object System.Xml.XmlNamespaceManager($coreXml.NameTable)
      $nsMgr.AddNamespace('dc', 'http://purl.org/dc/elements/1.1/')
      $nsMgr.AddNamespace('cp', 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties')
      $nsMgr.AddNamespace('dcterms', 'http://purl.org/dc/terms/')

      $titleNode = $coreXml.SelectSingleNode('//dc:title', $nsMgr)
      if ($titleNode) { $metadata.Title = $titleNode.InnerText }
      $creatorNode = $coreXml.SelectSingleNode('//dc:creator', $nsMgr)
      if ($creatorNode) { $metadata.Creator = $creatorNode.InnerText }
      $descNode = $coreXml.SelectSingleNode('//dc:description', $nsMgr)
      if ($descNode) { $metadata.Description = $descNode.InnerText }
      $lmbNode = $coreXml.SelectSingleNode('//cp:lastModifiedBy', $nsMgr)
      if ($lmbNode) { $metadata.LastModifiedBy = $lmbNode.InnerText }
      $revNode = $coreXml.SelectSingleNode('//cp:revision', $nsMgr)
      if ($revNode) { $metadata.Revision = $revNode.InnerText }
      $createdNode = $coreXml.SelectSingleNode('//dcterms:created', $nsMgr)
      if ($createdNode) { $metadata.Created = $createdNode.InnerText }
      $modNode = $coreXml.SelectSingleNode('//dcterms:modified', $nsMgr)
      if ($modNode) { $metadata.Modified = $modNode.InnerText }
    } catch {}
  }

  # docProps/app.xml
  $appPath = Join-Path $tmp "docProps\app.xml"
  if (Test-Path $appPath) {
    try {
      [xml]$appXml = Get-Content -Raw -Path $appPath
      $nsUri = 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'
      $nsMgr = New-Object System.Xml.XmlNamespaceManager($appXml.NameTable)
      $nsMgr.AddNamespace('ep', $nsUri)

      $appNode = $appXml.SelectSingleNode('//ep:Application', $nsMgr)
      if ($appNode) { $metadata.Application = $appNode.InnerText }
      $verNode = $appXml.SelectSingleNode('//ep:AppVersion', $nsMgr)
      if ($verNode) { $metadata.AppVersion = $verNode.InnerText }
      $pagesNode = $appXml.SelectSingleNode('//ep:Pages', $nsMgr)
      if ($pagesNode) { $metadata.Pages = [int]$pagesNode.InnerText }
      $wordsNode = $appXml.SelectSingleNode('//ep:Words', $nsMgr)
      if ($wordsNode) { $metadata.Words = [int]$wordsNode.InnerText }
      $charsNode = $appXml.SelectSingleNode('//ep:Characters', $nsMgr)
      if ($charsNode) { $metadata.Characters = [int]$charsNode.InnerText }
    } catch {}
  }

  # Detect zeroed-out metadata (deliberately sanitized)
  if ($metadata.Pages -eq 0 -and $metadata.Words -eq 0) { $metadataZeroed = $true }

  # -- Image Extraction + QR Analysis (word/media/) -------------------------------
  $imageFindings = @()
  $qrCount = 0
  $mediaDir = Join-Path $tmp "word\media"
  if (Test-Path $mediaDir) {
    $imageFiles = Get-ChildItem $mediaDir -File | Where-Object { $_.Extension -match '\.(png|jpe?g|gif|bmp|tiff?)$' }
    foreach ($img in $imageFiles) {
      try {
        $Evidence = Invoke-RoninImage -Evidence $Evidence -Path $img.FullName
        # Get the image findings from the last attachment added
        $lastImg = $Evidence.Attachments | Where-Object { $_.Type -eq 'image' } | Select-Object -Last 1
        if ($lastImg) {
          $imgInfo = @{
            Name    = $img.Name
            Size    = $img.Length
            Format  = $lastImg.Findings.ImageFormat
            HasQR   = $lastImg.Findings.HasQrCode
            QrPayload = $lastImg.Findings.QrPayload
          }
          $imageFindings += [PSCustomObject]$imgInfo
          if ($lastImg.Findings.HasQrCode) { $qrCount++ }
        }
      } catch {
        $imageFindings += [PSCustomObject]@{
          Name    = $img.Name
          Size    = $img.Length
          Format  = 'error'
          HasQR   = $false
          QrPayload = ''
        }
      }
    }
  }

  # -- ZIP Structure Forensics ---------------------------------------------------
  $zipStructure = @{
    EntryCount   = 0
    EocdOffset   = -1
    OverlayBytes = 0
    Anomalies    = @()
  }
  try {
    $docBytes = [IO.File]::ReadAllBytes($docxPath)

    # Count PK local file headers (PK 03 04)
    $pkCount = 0
    for ($i = 0; $i -lt $docBytes.Length - 4; $i++) {
      if ($docBytes[$i] -eq 0x50 -and $docBytes[$i+1] -eq 0x4B -and $docBytes[$i+2] -eq 0x03 -and $docBytes[$i+3] -eq 0x04) {
        $pkCount++
      }
    }
    $zipStructure.EntryCount = $pkCount

    # Find End of Central Directory (PK 05 06)
    for ($i = $docBytes.Length - 22; $i -ge 0; $i--) {
      if ($docBytes[$i] -eq 0x50 -and $docBytes[$i+1] -eq 0x4B -and $docBytes[$i+2] -eq 0x05 -and $docBytes[$i+3] -eq 0x06) {
        $zipStructure.EocdOffset = $i
        # Parse EOCD: comment length at offset+20 (2 bytes)
        $commentLen = [BitConverter]::ToUInt16($docBytes, $i + 20)
        $expectedEnd = $i + 22 + $commentLen
        if ($expectedEnd -lt $docBytes.Length) {
          $zipStructure.OverlayBytes = $docBytes.Length - $expectedEnd
          $zipStructure.Anomalies += "Overlay: $($zipStructure.OverlayBytes) bytes after ZIP end"
        }
        break
      }
    }
  } catch {
    $zipStructure.Anomalies += "ZIP parse error: $_"
  }

  # -- Lure Keyword Detection in Document Text -----------------------------------
  $lureHits = @()
  if ($docText -and $docText.Length -gt 0) {
    $docLower = $docText.ToLowerInvariant()
    foreach ($category in $script:LureKeywords.Keys) {
      foreach ($kw in $script:LureKeywords[$category]) {
        if ($docLower.Contains($kw.ToLowerInvariant())) {
          $lureHits += [PSCustomObject]@{ Category=$category; Keyword=$kw }
        }
      }
    }
  }

  # -- Build findings ---------------------------------------------------------------
  $findings = @{
    ExternalRelationships = ($external | Measure-Object).Count
    EmbeddedObjects       = $embeddedCount
    SuspiciousUrls        = ($payloadUrls | Measure-Object).Count
    Sha256                = $hash
    QrCodesFound          = $qrCount
    Images                = $imageFindings
    DocumentText          = $docText
    DocumentMetadata      = $metadata
    MetadataZeroed        = $metadataZeroed
    TrackingPixels        = $trackingPixels
    ZipStructure          = $zipStructure
    LureKeywords          = $lureHits
  }

  $Evidence.Attachments += [PSCustomObject]@{
    Path = $docxPath
    Type = 'docx'
    Findings = $findings
    Artifacts = @{
      ExternalRelationships = $external
      Urls = $payloadUrls
      Domains = $domains
      Hashes = @($hash)
      Files = @(
        (Get-ChildItem -Path $tmp -Recurse -File | Select-Object -First 200 | ForEach-Object { $_.FullName })
      )
    }
  }

  # Add to global IOC bag
  $Evidence.Iocs.Hashes += $hash
  $Evidence.Iocs.Urls    += $payloadUrls
  $Evidence.Iocs.Domains += $domains

  # Cleanup
  try { Remove-Item -Recurse -Force -Path $tmp } catch {}

  return $Evidence
}

function Show-RoninDoc {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Evidence)

  "=== RoninDoc ==="
  foreach ($a in $Evidence.Attachments) {
    if ($a.Type -ne 'docx') {
      if ($a.Type -eq 'image') { continue }  # shown by Show-RoninImage
      "File: {0} ({1})" -f $a.Path, $a.Type
      "  Note: {0}" -f $a.Findings.Note
      continue
    }
    "File: {0} ({1})" -f $a.Path, $a.Type
    "  SHA256: {0}" -f $a.Findings.Sha256
    "  ExternalRelationships: {0}" -f $a.Findings.ExternalRelationships
    "  EmbeddedObjects: {0}" -f $a.Findings.EmbeddedObjects
    "  Payload URLs: {0}" -f $a.Findings.SuspiciousUrls
    if ($a.Artifacts.Urls.Count -gt 0) {
      "  URL list:"
      foreach ($u in $a.Artifacts.Urls) { "   - $u" }
    }
    ""
    # Document metadata
    $meta = $a.Findings.DocumentMetadata
    if ($meta) {
      "  Metadata:"
      if ($meta.Creator)        { "    Creator:        {0}" -f $meta.Creator }
      if ($meta.LastModifiedBy) { "    LastModifiedBy:  {0}" -f $meta.LastModifiedBy }
      if ($meta.Application)    { "    Application:     {0} {1}" -f $meta.Application, $meta.AppVersion }
      if ($meta.Created)        { "    Created:         {0}" -f $meta.Created }
      if ($meta.Modified)       { "    Modified:        {0}" -f $meta.Modified }
      "    Pages: {0}  Words: {1}  Chars: {2}" -f $meta.Pages, $meta.Words, $meta.Characters
      if ($a.Findings.MetadataZeroed) {
        "    [ALERT] Metadata zeroed out (Pages=0, Words=0) -- deliberately sanitized"
      }
    }

    # QR codes / images
    if ($a.Findings.QrCodesFound -gt 0) {
      ""
      "  [QR CODES] {0} QR code(s) found in document images:" -f $a.Findings.QrCodesFound
      foreach ($img in $a.Findings.Images) {
        if ($img.HasQR) {
          "    {0}: {1}" -f $img.Name, $img.QrPayload
        }
      }
    } elseif ($a.Findings.Images.Count -gt 0) {
      "  Images: {0} (no QR codes)" -f $a.Findings.Images.Count
    }

    # Tracking pixels
    if ($a.Findings.TrackingPixels.Count -gt 0) {
      ""
      "  [TRACKING] {0} external image reference(s):" -f $a.Findings.TrackingPixels.Count
      foreach ($tp in $a.Findings.TrackingPixels) { "    $tp" }
    }

    # Document text snippet
    if ($a.Findings.DocumentText -and $a.Findings.DocumentText.Length -gt 0) {
      ""
      $preview = $a.Findings.DocumentText
      if ($preview.Length -gt 300) { $preview = $preview.Substring(0, 300) + '...' }
      "  Document Text Preview:"
      "    $preview"
    }

    # Lure keywords
    if ($a.Findings.LureKeywords.Count -gt 0) {
      ""
      "  [LURE] Social engineering keywords detected:"
      foreach ($lk in $a.Findings.LureKeywords) {
        "    [{0}] {1}" -f $lk.Category, $lk.Keyword
      }
    }

    # ZIP structure
    $zs = $a.Findings.ZipStructure
    if ($zs -and $zs.EntryCount -gt 0) {
      ""
      "  ZIP Structure: {0} entries, EOCD at offset {1}" -f $zs.EntryCount, $zs.EocdOffset
      if ($zs.OverlayBytes -gt 0) {
        "  [ALERT] ZIP overlay: {0} bytes after expected end" -f $zs.OverlayBytes
      }
      if ($zs.Anomalies.Count -gt 0) {
        foreach ($an in $zs.Anomalies) { "  [ANOMALY] $an" }
      }
    }
    ""
  }
}

Export-ModuleMember -Function Invoke-RoninDoc, Show-RoninDoc
