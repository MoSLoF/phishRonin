$destDir = Join-Path $PSScriptRoot 'ZXing.Net'
New-Item -ItemType Directory -Path $destDir -Force | Out-Null

$nugetUrl = 'https://www.nuget.org/api/v2/package/ZXing.Net/0.16.9'
$nupkg = Join-Path ([IO.Path]::GetTempPath()) 'zxing.net.0.16.9.nupkg'

Write-Host "Downloading ZXing.NET 0.16.9 from NuGet..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $nugetUrl -OutFile $nupkg -UseBasicParsing
Write-Host "Downloaded: $nupkg ($((Get-Item $nupkg).Length) bytes)"

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($nupkg)

# List all DLLs in the package
Write-Host "`nAvailable DLLs in NuGet package:" -ForegroundColor Yellow
$zip.Entries | Where-Object { $_.FullName -like '*.dll' } | ForEach-Object {
    Write-Host "  $($_.FullName)  ($($_.Length) bytes)"
}

# Prefer net40 build (works in Windows PowerShell 5.1 with System.Drawing)
$targetPaths = @('lib/net40/zxing.dll', 'lib/net45/zxing.dll', 'lib/net461/zxing.dll', 'lib/netstandard2.0/zxing.dll')
$extracted = $false

foreach ($target in $targetPaths) {
    $entry = $zip.Entries | Where-Object { $_.FullName -eq $target }
    if ($entry) {
        $dest = Join-Path $destDir 'zxing.dll'
        $stream = $entry.Open()
        $fs = [IO.File]::Create($dest)
        $stream.CopyTo($fs)
        $fs.Close()
        $stream.Close()
        $hash = (Get-FileHash $dest -Algorithm SHA256).Hash
        Write-Host "`nExtracted from: $target" -ForegroundColor Green
        Write-Host "Destination: $dest" -ForegroundColor Green
        Write-Host "Size: $((Get-Item $dest).Length) bytes" -ForegroundColor Green
        Write-Host "SHA256: $hash" -ForegroundColor Green
        $extracted = $true
        break
    }
}

if (-not $extracted) {
    Write-Host "`n[ERROR] Could not find a suitable DLL target" -ForegroundColor Red
}

$zip.Dispose()

# Verify it loads
try {
    Add-Type -Path (Join-Path $destDir 'zxing.dll')
    $reader = New-Object ZXing.BarcodeReader
    Write-Host "`nZXing.NET loaded and verified successfully!" -ForegroundColor Green
    Write-Host "BarcodeReader type: $($reader.GetType().FullName)" -ForegroundColor Green
} catch {
    Write-Host "`n[WARN] ZXing.NET load test failed: $_" -ForegroundColor Yellow
}
