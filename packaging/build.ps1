# MCP app - full Windows build.
#
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -Python "py -3.13"
#
# Steps: build venv -> dependencies -> cloudflared.exe -> icon/version -> PyInstaller
#        -> selftest of the built exe -> portable zip -> Setup.exe (if Inno Setup 6 is installed).
# Output: dist\MCPApp\MCPApp.exe, dist\MCPApp-<ver>-portable.zip, dist\MCPApp-Setup-<ver>.exe
#
# Messages are in English on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI.

param(
    [string]$Python = "python",   # interpreter for the build venv, e.g. "py -3.13" or a full path
    [switch]$SkipInstaller,       # do not build Setup.exe even if Inno Setup is installed
    [switch]$UpdateCloudflared    # re-download cloudflared.exe even if bin\cloudflared.exe exists
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)" } }

$Version = (Select-String -Path "app\__init__.py" -Pattern '__version__\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
Write-Host "MCP app $Version" -ForegroundColor White

# ------------------------------------------------------------------ 1. venv
Step "Build environment (.venv-build)"
$Venv = Join-Path $Root ".venv-build"
$Py = Join-Path $Venv "Scripts\python.exe"
if (-not (Test-Path $Py)) {
    $parts = $Python -split " "
    $exe = $parts[0]
    $rest = @()
    if ($parts.Length -gt 1) { $rest = $parts[1..($parts.Length - 1)] }
    & $exe @rest -m venv $Venv
    Check "venv creation"
}
& $Py -c "import sys; print('Python', sys.version.split()[0])"
& $Py -m pip install --upgrade pip --quiet
Check "pip upgrade"

if (Test-Path "requirements.lock") {
    Write-Host "Using requirements.lock (pinned versions)"
    & $Py -m pip install -r requirements.lock -r requirements-build.txt --quiet
} else {
    Write-Host "requirements.lock not found - installing latest versions from requirements.txt" -ForegroundColor Yellow
    & $Py -m pip install -r requirements.txt -r requirements-build.txt --quiet
}
Check "dependency install"

# ------------------------------------------------------------------ 2. cloudflared
Step "cloudflared.exe"
$Cloudflared = Join-Path $Root "bin\cloudflared.exe"
if ($UpdateCloudflared -or -not (Test-Path $Cloudflared)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $Cloudflared) | Out-Null
    $Url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
    Write-Host "Downloading $Url"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Url -OutFile $Cloudflared -UseBasicParsing
}
$Signature = Get-AuthenticodeSignature $Cloudflared
if ($Signature.Status -ne "Valid" -or $Signature.SignerCertificate.Subject -notmatch "Cloudflare") {
    throw "bin\cloudflared.exe is not signed by Cloudflare ($($Signature.Status)). Delete it and run again."
}
& $Cloudflared --version
Check "cloudflared --version"

# ------------------------------------------------------------------ 3. icon + version resource
Step "Icon and version resource"
& $Py packaging\make_assets.py
Check "make_assets.py"

# ------------------------------------------------------------------ 4. PyInstaller
Step "PyInstaller"
if (Test-Path "dist\MCPApp") { Remove-Item -Recurse -Force "dist\MCPApp" }
& $Py -m PyInstaller packaging\mcp_app.spec --noconfirm --clean --distpath dist --workpath build\pyinstaller
Check "PyInstaller"

# ------------------------------------------------------------------ 5. selftest
Step "Selftest of the built exe"
$Exe = Join-Path $Root "dist\MCPApp\MCPApp.exe"
$Report = Join-Path $Root "build\selftest.txt"
if (Test-Path $Report) { Remove-Item $Report }
$proc = Start-Process -FilePath $Exe -ArgumentList @("--selftest", "`"$Report`"") -Wait -PassThru -WindowStyle Hidden
if (Test-Path $Report) { Get-Content $Report -Encoding UTF8 | ForEach-Object { Write-Host "  $_" } }
if ($proc.ExitCode -ne 0) { throw "Selftest failed (exit code $($proc.ExitCode)). See build\selftest.txt" }

# ------------------------------------------------------------------ 6. portable zip
Step "Portable zip"
$Zip = Join-Path $Root "dist\MCPApp-$Version-portable.zip"
if (Test-Path $Zip) { Remove-Item $Zip }
Compress-Archive -Path "dist\MCPApp" -DestinationPath $Zip
Write-Host $Zip

# ------------------------------------------------------------------ 7. installer
if (-not $SkipInstaller) {
    Step "Installer (Inno Setup 6)"
    $Iscc = (Get-Command "iscc.exe" -ErrorAction SilentlyContinue).Source
    if (-not $Iscc) {
        $candidates = @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
            "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
        )
        $Iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if ($Iscc) {
        & $Iscc "/DAppVersion=$Version" "packaging\installer.iss"
        Check "Inno Setup"
    } else {
        Write-Host "Inno Setup 6 not found - Setup.exe skipped. Install it: winget install --id JRSoftware.InnoSetup" -ForegroundColor Yellow
    }
}

Step "Done"
Get-ChildItem dist -File | ForEach-Object { Write-Host ("  {0}  ({1:N1} MB)" -f $_.Name, ($_.Length / 1MB)) }
Write-Host "  dist\MCPApp\MCPApp.exe"
