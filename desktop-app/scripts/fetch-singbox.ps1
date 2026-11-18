$ErrorActionPreference = 'Stop'
$version = '1.14.3'
$url = "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip"
$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'resources\sing-box'
$zip = Join-Path $env:TEMP "sing-box-$version-windows-amd64.zip"
$extract = Join-Path $env:TEMP "singbox-$version-extract"

New-Item -ItemType Directory -Force $target | Out-Null
Invoke-WebRequest -Uri $url -OutFile $zip -TimeoutSec 180
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
Expand-Archive -Path $zip -DestinationPath $extract
$source = Get-ChildItem $extract -Directory | Select-Object -First 1
Copy-Item (Join-Path $source.FullName 'sing-box.exe') (Join-Path $target 'sing-box.exe') -Force
Copy-Item (Join-Path $source.FullName 'libcronet.dll') (Join-Path $target 'libcronet.dll') -Force
Copy-Item (Join-Path $source.FullName 'LICENSE') (Join-Path $target 'LICENSE') -Force
Write-Host "sing-box $version installed to $target"
