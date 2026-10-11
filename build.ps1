# Builds Bond: the Windows app and installer, and the Linux relay package.
#
#   .\build.ps1 [-Version 1.2.3] [-SkipTests] [-SkipInstaller]
#
# Needs Go (see go.mod) and, for the installer, Inno Setup 6
# (winget install JRSoftware.InnoSetup). Output goes to .\dist.
param(
    [string]$Version = "1.0.0",
    [switch]$SkipTests,
    [switch]$SkipInstaller
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$WintunUrl = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$WintunSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

function Run([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe $($arguments -join ' ') failed ($LASTEXITCODE)" }
}

Remove-Item dist -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory dist\app, dist\bond-server | Out-Null

if (-not $SkipTests) {
    Write-Host "== tests"
    Run go @("vet", "./...")
    Run go @("test", "./...")
}

Write-Host "== Windows app"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
Run go @("build", "-trimpath", "-ldflags", "-H windowsgui -s -w", "-o", "dist\app\Bond.exe", "./cmd/bond-gui")
Run go @("build", "-trimpath", "-ldflags", "-s -w", "-o", "dist\app\bond-client.exe", "./cmd/bond-client")

Write-Host "== Linux relay"
$env:GOOS = "linux"
foreach ($arch in "amd64", "arm64") {
    $env:GOARCH = $arch
    Run go @("build", "-trimpath", "-ldflags", "-s -w", "-o", "dist\bond-server\bond-server-$arch", "./cmd/bond-server")
}
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
Copy-Item deploy\* dist\bond-server\
Run tar @("-czf", "dist\bond-server-linux.tar.gz", "-C", "dist", "bond-server")

Write-Host "== Wintun"
$zip = Join-Path $env:TEMP "wintun-0.14.1.zip"
if (-not (Test-Path $zip) -or (Get-FileHash $zip -Algorithm SHA256).Hash -ne $WintunSha256) {
    Invoke-WebRequest $WintunUrl -OutFile $zip -UseBasicParsing
}
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne $WintunSha256) { throw "wintun zip hash mismatch" }
$tmp = Join-Path $env:TEMP "wintun-extract-$PID"
Expand-Archive $zip $tmp -Force
Copy-Item "$tmp\wintun\bin\amd64\wintun.dll" dist\app\
Copy-Item "$tmp\wintun\LICENSE.txt" dist\app\wintun-LICENSE.txt
Remove-Item $tmp -Recurse -Force

if (-not $SkipInstaller) {
    Write-Host "== installer"
    $iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
    if (-not $iscc) {
        $iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
            Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $iscc) { throw "Inno Setup 6 not found (winget install JRSoftware.InnoSetup), or use -SkipInstaller" }
    Run $iscc @("/Q", "/DAppVersion=$Version", "installer\bond.iss")
    # Keep a ready-to-run copy at the repository root.
    Copy-Item "dist\Bond-Setup-$Version.exe" "installer.exe" -Force
}

Write-Host "== done"
Get-ChildItem dist -File | Select-Object Name, @{n = "MB"; e = { [math]::Round($_.Length / 1MB, 1) } } | Format-Table -AutoSize
