# phishRonin -- Deep Inspection Upgrade Plan
## Quishing Detection, Binary Forensics, MIME Forensics, AMSI-Level Analysis

### Context

Two phishing EMLs targeting invokehoneybadger.com used a **quishing** attack:
- DOCX with embedded QR code image as the sole payload
- Empty HTML body (evasion technique bypasses body scanners)
- No macros, no external rels, no OLE -- 100% image-based weaponization
- Python-generated MIME boundaries (phishing kit fingerprint)
- VirusTotal scored 3/100 "Non Malicious" on both
- AMSI flagged as Trojan:Win32/Mimikatz (false positive from MZ bytes in PNG IDAT data)
- Different QR codes per email (per-target tracking URLs)

Current phishRonin scored 55/100 SUSPICIOUS -- only from header signals. It had **zero awareness** of QR codes, empty body evasion, MIME fingerprinting, binary anomalies, or steganography. Target: 100/100 MALICIOUS.

Every technique below was manually performed during this investigation session and is now being codified into the pipeline.

---

## Phase 1: New Module -- `RoninImage.psm1` (QR Code + Image Forensics)

### QR Code Detection
Use **ZXing.NET** (.NET Framework 4.x build). Ship DLL in `lib/ZXing.Net/zxing.dll`. Graceful fallback if absent.

**`Invoke-RoninImage`** (exported)
- Load image via `[System.Drawing.Bitmap]::FromFile($Path)`
- Decode with `BarcodeReader.Decode()` (TryHarder=true)
- Classify QR payload: 'url' | 'text' | 'vcard' | 'wifi' | 'other'
- If URL: parse domain, add to `Evidence.Iocs.Urls` and `Evidence.Iocs.Domains`
- Compare QR URL domain against sender domain for cross-domain phishing detection

### Image Binary Forensics (from hunt-mimikatz.ps1 investigation)

**JPEG analysis:**
- Find JPEG end marker (FFD9)
- Detect trailing data after FFD9 (steganography / appended payloads)
- If trailing data: check for MZ (PE), PK (ZIP), or other magic bytes
- Hash JPEG content

**PNG analysis:**
- Walk PNG chunk structure: IHDR, IDAT, IEND, tEXt, zTXt, iTXt, etc.
- Flag suspicious text chunks (tEXt/zTXt/iTXt) -- can hide encoded commands
- Detect trailing data after IEND chunk
- Report chunk inventory (type + length)

**PE/Executable scanning (from inspect-mz.ps1 investigation):**
- Scan all image bytes for MZ signatures (0x4D 0x5A)
- For each MZ hit: validate e_lfanew pointer and check for PE\0\0 signature
- Distinguish real embedded PE vs coincidental byte patterns in compressed data
- If valid PE found: extract machine type, section count, compile timestamp, optional header type
- Report: "Coincidental MZ in IDAT" vs "CONFIRMED EMBEDDED PE"

**Mimikatz/malware string scanning:**
- Scan image binary for known tool signatures: mimikatz, sekurlsa, kerberos, lsadump, dpapi, wdigest, logonpasswords, privilege::debug, token::elevate, gentilkiwi, kuhl_m, kull_m
- Scan in both ASCII and UTF-16LE encodings
- Scan for script execution patterns: powershell, cmd.exe, wscript, cscript, mshta, certutil, bitsadmin, regsvr32, rundll32, IEX(, Invoke-Expression, DownloadString, FromBase64String, EncodedCommand

### Evidence Object Addition
```
Type = 'image'
Findings = {
  HasQrCode         : bool
  QrPayload         : string (decoded URL/text)
  QrPayloadType     : 'url' | 'text' | 'vcard' | 'wifi' | 'other'
  QrDomainMismatch  : bool (QR domain != sender domain)
  ImageFormat        : 'png' | 'jpeg' | 'gif' | 'bmp'
  ImageSizeBytes     : int
  Sha256             : string
  HasTrailingData    : bool
  TrailingDataBytes  : int
  TrailingDataMagic  : string ('MZ' | 'PK' | 'none' | 'unknown')
  PngChunks          : @() (list of {Type, Length})
  SuspiciousPngChunks: @() (tEXt/zTXt/iTXt with content)
  MzSignatures       : @() (list of {Offset, IsValidPE, Details})
  MalwareStrings     : @() (any malware signature string matches)
  ScriptPatterns     : @() (any script execution pattern matches)
  Note               : string
}
Artifacts = {
  QrUrls    : @()
  QrDomains : @()
  Hashes    : @()
}
```

**`Show-RoninImage`** (exported) -- console display with color-coded alerts

---

## Phase 2: New Module -- `RoninMimeForensics.psm1` (Deep MIME/Body Analysis)

Codifies every MIME-level technique from our investigation.

### MIME Structure Analysis

**Boundary fingerprinting (from EML investigation):**
- Python email lib: `^={15,}\d{18,22}={2}$` --> `'python-email'`
- PHP mailer: `----=_Part_` prefix --> `'php-mailer'`
- .NET: GUID-like boundaries --> `'dotnet'`
- Standard/unknown: anything else

**Empty body detection (the key evasion technique we found):**
- Check if text/html part is declared but empty/whitespace-only
- Check if text/plain part exists at all
- Detect "bodyless email" -- both empty, payload-only delivery
- Detect image-only HTML body (only `<img>` tags, no text)

**Attachment-only delivery detection:**
- Count content parts vs attachment parts
- Flag if attachment is the sole content vehicle (no text/html with real content)

### MIME Boundary Content Inspection (from hunt-mimikatz.ps1 Part 5)

**Hidden data outside MIME boundaries:**
- Check for content AFTER the final `--boundary--` terminator
- Check for content BETWEEN boundaries that isn't part of any declared part
- Check for preamble content before the first boundary

**Inner/nested boundary analysis:**
- Identify all boundaries (outer and nested)
- Classify each boundary pattern independently
- Detect mismatched boundary patterns (outer=standard, inner=python = mixed kit)

### Email Body Content Inspection

**HTML body analysis (if present):**
- Extract and catalog all `<script>` tags
- Extract all `<iframe>` sources
- Extract all `<a href>` links
- Extract all `<form action>` targets
- Detect obfuscation: base64 data URIs, javascript: links, on* event handlers
- Extract `<meta http-equiv="refresh">` redirects

**Base64 blob detection in body/headers:**
- Scan for large base64 blobs (100+ chars) outside of expected attachment locations
- Attempt decode, check for MZ/PK/script signatures in decoded content

### EOP/Exchange Header Deep Parse (from VT investigation)

**X-Microsoft-Antispam header:**
- Parse `BCL:` (Bulk Complaint Level)
- Parse ARA rule IDs (Adaptive Rules Applied)
- Cross-reference known ARA rule IDs with descriptions where possible

**X-MS-Exchange-Organization-SCL:**
- Extract SCL (Spam Confidence Level) 0-9 scale
- Interpret: -1=trusted, 0-1=not spam, 5-6=spam, 9=high confidence spam

**X-Forefront-Antispam-Report:**
- Parse `SFV:` (Spam Filter Verdict)
- Parse `CAT:` (Category -- SPM, PHSH, MALW, etc.)
- Parse `SCL:` from this header as secondary source

**X-MS-Exchange-Organization-AuthSource/AuthAs:**
- Identify auth mechanism used by Exchange
- Detect `AuthAs=Anonymous` (unauthenticated sender)

**Compauth (Composite Authentication):**
- Parse `compauth=` reason codes
- Map reason codes: 000=explicit fail, 001=implicit fail, 2xx=softfail, 3xx=pass, 4xx=none

### Evidence Object Addition
```
Evidence.MimeForensics = {
  BoundaryFingerprints  : @() (list of {Boundary, Pattern, Classification})
  IsEmptyHtmlBody       : bool
  IsEmptyTextBody       : bool
  IsBodylessEmail       : bool
  HasImageOnlyBody      : bool
  AttachmentOnlyDelivery: bool
  HiddenDataAfterBoundary: bool
  HiddenDataBytes       : int
  PreambleContent       : string (content before first boundary)
  HtmlFindings          : @() (scripts, iframes, forms, redirects found)
  Base64Blobs           : @() (unexpected base64 blobs found)
  EopScl                : int (-1 to 9)
  EopCategory           : string (SPM, PHSH, MALW, NONE, etc.)
  EopAraRules           : @() (ARA rule IDs)
  Compauth              : @{Result=''; Reason=''; Description=''}
  Findings              : @() (list of finding strings)
}
```

---

## Phase 3: Enhance `RoninDoc.psm1` -- Deep DOCX Forensics

### Image Extraction + QR Detection (from our manual DOCX investigation)
After DOCX unzip, scan `word/media/` and run `Invoke-RoninImage` on each image:
```
$mediaDir = Join-Path $tmp "word\media"
if (Test-Path $mediaDir) {
  $imageFiles = Get-ChildItem $mediaDir -File |
    Where-Object { $_.Extension -match '\.(png|jpe?g|gif|bmp|tiff?)$' }
  foreach ($img in $imageFiles) {
    $Evidence = Invoke-RoninImage -Evidence $Evidence -Path $img.FullName
  }
}
```

### Document XML Text Extraction (from read-docx-text.ps1)
- Parse `word/document.xml` for all `<w:t>` text nodes
- Reconstruct the document's visible text content
- Store as `Evidence.Attachments[-1].Findings.DocumentText`
- Enables keyword matching on DOCX body content (e.g., "scan to view", "sign-in steps")

### Document Metadata Extraction (from VT report)
- Parse `docProps/core.xml` for: title, creator, description, lastModifiedBy, revision, created, modified
- Parse `docProps/app.xml` for: Application, AppVersion, Pages, Words, Characters
- Flag zeroed-out metadata (Pages=0, Words=0 = deliberately sanitized)
- Flag mismatched Application version (old Word version generating modern DOCX)

### Relationship Deep Analysis (already partial, enhance)
- Existing: find TargetMode="External" in .rels
- Add: categorize relationship types (image, hyperlink, oleObject, etc.)
- Add: detect `r:link` (external linked images -- not embedded, fetched on open)
- Add: flag external image references that could be tracking pixels

### OpenXML Schema URL Filtering (retroactive fix)
- Filter `schemas.openxmlformats.org` and `schemas.microsoft.com` from SuspiciousUrls count
- These are structural namespace URIs, not payload URLs
- Prevents +15 false positive on every clean DOCX

### ZIP Structure Forensics (from inspect-mz.ps1 Part 7)
- Count and catalog all PK local file headers (PK 03 04) with offsets
- Find End of Central Directory (PK 05 06)
- Parse ZIP comment length
- Detect overlay data (bytes after expected ZIP end)
- Report: entry count, EOCD offset, overlay bytes

### DOCX Findings Enhancement
```
Findings = {
  ...existing...
  QrCodesFound      : int
  Images            : @() ({Name, Size, HasQR, QrPayload, Format})
  DocumentText      : string (reconstructed visible text)
  DocumentMetadata  : @{Title, Creator, Application, AppVersion, Pages, Words, Revision}
  MetadataZeroed    : bool
  TrackingPixels    : @() (external image refs)
  ZipStructure      : @{EntryCount, EocdOffset, OverlayBytes, Anomalies}
  LureKeywords      : @() (matched social engineering keywords in doc text)
}
```

### Lure Keyword Detection in Document Text
Scan DocumentText for social engineering keywords:
- Credential harvesting: "sign-in", "verify", "confirm your account", "password", "credentials"
- QR lure: "scan", "qr code", "scan to view", "scan below", "use your phone"
- Urgency: "immediate", "urgent", "expires", "within 24 hours", "action required"
- Authority: "IT department", "helpdesk", "administrator", "security team"

---

## Phase 4: Enhance `RoninHeaders.psm1` -- MIME-Level Enrichment

### Changes to `Import-RoninEml`
After boundary extraction, store raw boundary for forensics:
```
$Evidence.Raw.MimeBoundaries = @()  # all boundaries found (outer + nested)
```

After body extraction, flag empty body:
```
$Evidence.Raw.IsEmptyHtmlBody = [string]::IsNullOrWhiteSpace($Evidence.Raw.BodyHtml)
$Evidence.Raw.IsEmptyTextBody = [string]::IsNullOrWhiteSpace($Evidence.Raw.BodyText)
```

### Changes to `Invoke-RoninHeaders`
Extract additional Exchange/EOP headers:
- `X-MS-Exchange-Organization-SCL`
- `X-Forefront-Antispam-Report`
- `X-Microsoft-Antispam`
- `X-MS-Exchange-Organization-AuthSource`
- `X-MS-Exchange-Organization-AuthAs`

Store parsed results in `Evidence.Auth` for the scoring engine and MimeForensics module.

### To addresses
Currently `Evidence.Message.To` is `@()` -- parse the `To:` header to populate recipient list.
Also parse `Cc:` and `Bcc:` if present.
Detect self-addressed emails (From == To) as a spoofing indicator.

---

## Phase 5: Enhance Scoring Engine (`RoninTriage.psm1`)

### New Scoring Signals

**Quishing signals:**
| Indicator | Points | Rationale |
|---|---|---|
| QR code found in DOCX image | +25 | Core quishing indicator |
| QR code payload is a URL | +10 | QR is weaponized with a link |
| QR URL domain differs from sender domain | +10 | Cross-domain phishing |
| Multiple QR codes in single doc | +5 | Redundancy/fallback technique |
| Document text contains lure keywords | +5 | Social engineering language detected |

**Body/MIME evasion signals:**
| Indicator | Points | Rationale |
|---|---|---|
| Empty HTML body (bodyless email) | +15 | Known evasion technique |
| Attachment-only content delivery | +10 | Payload isolation pattern |
| Python-email MIME boundary | +10 | Phishing kit fingerprint |
| Hidden data after MIME boundary | +15 | Content stuffing attack |
| Self-addressed email (From==To) | +10 | Spoofing indicator |

**Binary forensics signals:**
| Indicator | Points | Rationale |
|---|---|---|
| Valid PE embedded in image | +30 | Executable hidden in image |
| Trailing data after image end marker | +20 | Steganography / appended payload |
| Suspicious PNG text chunks | +10 | Data hiding in metadata |
| Malware strings found in binary | +25 | Known tool signatures |
| Script execution patterns in binary | +20 | Embedded command execution |

**Document forensics signals:**
| Indicator | Points | Rationale |
|---|---|---|
| Zeroed-out document metadata | +10 | Deliberately sanitized |
| ZIP overlay data | +15 | Hidden payload after ZIP |
| External tracking pixel refs | +10 | Beacon/tracking |
| DOCX lure keywords (credential terms) | +5 | Credential harvesting language |

**Retroactive fix:**
| Change | Effect |
|---|---|
| Filter OpenXML schema URLs from SuspiciousUrls | Removes +15 false positive |

### Adjusted Scoring for HR Lay-Off EMLs

| Signal | Points |
|---|---|
| DMARC fail | +30 |
| Subject "hr" | +5 |
| Subject "meeting" | +5 |
| QR code in DOCX | +25 |
| QR payload is URL | +10 |
| QR domain != sender domain | +10 |
| Empty HTML body | +15 |
| Attachment-only delivery | +10 |
| Python-email boundary | +10 |
| Self-addressed (From==To) | +10 |
| Zeroed metadata (Words=0, Pages=0) | +10 |
| Doc text: "scan to view" + "sign-in" | +5 |
| ~~DOCX URLs~~ (filtered schemas) | ~~+15~~ -> 0 |
| **TOTAL** | **145 -> clamped to 100** |
| **Verdict** | **MALICIOUS** |

### New Suggested Actions
Quishing-specific:
- "QR code detected -- decode and inspect target URL before any interaction"
- "Block QR payload domain at web proxy / DNS filter"
- "Alert SOC: quishing campaign -- QR code in DOCX attachment"

Binary-specific (if PE/malware found):
- "CRITICAL: Embedded executable detected in image -- isolate immediately"
- "Submit extracted PE to sandbox for dynamic analysis"
- "Engage incident response: potential malware delivery"

MIME evasion:
- "Email uses phishing kit delivery patterns (empty body + Python MIME)"
- "Review DMARC policy -- enforce p=reject to block sender spoofing"

---

## Phase 6: Pipeline Integration

### `ronin.ps1` changes
1. Import new modules:
   ```
   Import-Module (Join-Path $here "modules\RoninImage.psm1") -Force
   Import-Module (Join-Path $here "modules\RoninMimeForensics.psm1") -Force
   ```

2. In auto-analysis loop, add image handling for standalone image attachments:
   ```
   foreach ($att in $evidence.Raw.ExtractedAttachments) {
     $ext = [IO.Path]::GetExtension($att.Path).ToLowerInvariant()
     if ($ext -match '\.(png|jpe?g|gif|bmp)$') {
       $evidence = Invoke-RoninImage -Evidence $evidence -Path $att.Path
     }
   }
   ```

3. Insert `Invoke-RoninMimeForensics` call after `Invoke-RoninHeaders` and before `Invoke-RoninTriage`

4. Insert `Invoke-RoninBodyAnalysis` (if kept separate from MimeForensics)

### `run-triage.ps1` changes
Add new instrumented phases:
- Phase 3b: "Image Analysis" (QR decode + binary forensics)
- Phase 3c: "MIME Forensics" (body evasion + boundary fingerprint + EOP headers)

---

## Phase 7: ZXing.NET Dependency Setup

### Acquire the DLL
- Download ZXing.Net NuGet package (v0.16.x)
- Extract `lib/net4x/zxing.dll` (the .NET Framework 4.x build)
- Place at `H:\Development\Repos\phishRonin\lib\ZXing.Net\zxing.dll`

This build includes `System.Drawing.Bitmap` support natively -- works in Windows PowerShell 5.1.

### Loading strategy in `RoninImage.psm1`
```powershell
$zxingPath = Join-Path $PSScriptRoot '..\lib\ZXing.Net\zxing.dll'
$script:ZXingAvailable = $false
if (Test-Path $zxingPath) {
  try {
    Add-Type -Path $zxingPath
    $script:ZXingAvailable = $true
  } catch {
    Write-Warning "ZXing.NET load failed: $_"
  }
}
```

---

## File Summary

| File | Action | Description |
|---|---|---|
| `modules/RoninImage.psm1` | **NEW** | QR decode + image binary forensics + stego detection + PE/malware scanning |
| `modules/RoninMimeForensics.psm1` | **NEW** | MIME boundary fingerprinting, empty body detection, hidden data, EOP header parsing |
| `modules/RoninDoc.psm1` | MODIFY | DOCX image extraction, document text extraction, metadata analysis, schema URL filtering, ZIP forensics, lure keyword detection |
| `modules/RoninHeaders.psm1` | MODIFY | Store MIME boundaries, empty body flags, To/Cc/Bcc parsing, self-addressed detection, EOP header extraction |
| `modules/RoninTriage.psm1` | MODIFY | 15+ new scoring signals, binary forensics scoring, quishing actions, MIME evasion scoring |
| `ronin.ps1` | MODIFY | Import new modules, image auto-analysis, MIME forensics integration |
| `run-triage.ps1` | MODIFY | Add Image Analysis and MIME Forensics instrumented phases |
| `lib/ZXing.Net/zxing.dll` | **NEW** | Vendored ZXing.NET dependency for QR decode |

---

## Execution Order
1. Phase 7 (acquire ZXing DLL) -- foundation dependency
2. Phase 1 (RoninImage.psm1) -- QR + image forensics
3. Phase 4 (RoninHeaders.psm1 enhancements) -- MIME enrichment + To/Cc parsing
4. Phase 2 (RoninMimeForensics.psm1) -- deep MIME/body analysis
5. Phase 3 (RoninDoc.psm1 enhancements) -- DOCX deep inspection
6. Phase 5 (RoninTriage.psm1) -- scoring engine overhaul
7. Phase 6 (pipeline integration) -- wire everything together
8. Re-run triage on both EMLs to validate scoring hits 100/100 MALICIOUS
