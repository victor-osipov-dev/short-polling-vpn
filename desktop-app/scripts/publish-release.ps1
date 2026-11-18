$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = Split-Path -Parent $PSScriptRoot
$pkg = Get-Content -Raw -Encoding UTF8 (Join-Path $root 'package.json') | ConvertFrom-Json
$version = $pkg.version
$tag = "v$version"
$exeName = "Short-Polling-VPN-$version-portable.exe"
$exe = Join-Path $root "release\$exeName"

if (-not (Test-Path $exe)) {
  throw "Release file not found: $exe. Run release.bat first."
}

$credText = "protocol=https`nhost=github.com`n`n" | git credential fill
$token = ''
foreach ($line in $credText) {
  if ($line -like 'password=*') { $token = $line.Substring(9) }
}
if (-not $token) { throw 'GitHub credential not found (git credential fill returned no password)' }

$headers = @{
  'Authorization' = "Bearer $token"
  'User-Agent' = 'short-polling-vpn-release'
  'Accept' = 'application/vnd.github+json'
}

# Derive owner/repo from the git remote so the script works on forks too.
$remote = git config --get remote.origin.url
if ($remote -match 'github\.com[:/]([^/]+)/([^\.]+)(\.git)?$') {
  $owner = $Matches[1]
  $repo = $Matches[2]
} else {
  throw "Cannot parse GitHub remote: $remote"
}
$api = "https://api.github.com/repos/$owner/$repo"

$notes = @"
## Short Polling VPN $version

Desktop client based on Electron + React + Vite + Tailwind with a headless Python backend.

- Load a subscription URL and pick a profile (country grouping, search, filters).
- Windows system proxy with backup/restore of previous settings.
- Real VPN TUN mode via sing-box (adapter ``custom-tun``), requires Administrator rights.
- Smart split routing from the subscription (``ru`` / ``non_ru`` / ``private``) and an all-traffic mode.
- Connection status, exit IP, traffic counters and a live log.

Download ``$exeName`` and run it. Use the ``(Admin)`` shortcut or "Run as administrator" for TUN mode.
"@

$body = @{
  tag_name = $tag
  name = "Short Polling VPN $version"
  body = $notes
  draft = $false
  prerelease = $false
} | ConvertTo-Json -Depth 5

$release = $null
try {
  $release = Invoke-RestMethod -Uri "$api/releases/tags/$tag" -Headers $headers -Method Get
  Write-Host "Updating existing release $tag..."
  $release = Invoke-RestMethod -Uri "$api/releases/$($release.id)" -Headers $headers -Method Patch -Body $body
} catch {
  Write-Host "Creating release $tag..."
  $release = Invoke-RestMethod -Uri "$api/releases" -Headers $headers -Method Post -Body $body
}

$assets = Invoke-RestMethod -Uri "$api/releases/$($release.id)/assets" -Headers $headers -Method Get
foreach ($asset in $assets) {
  if ($asset.name -eq $exeName) {
    Write-Host "Removing old asset $exeName..."
    Invoke-RestMethod -Uri "$api/releases/assets/$($asset.id)" -Headers $headers -Method Delete | Out-Null
  }
}

Write-Host "Uploading $exeName..."
$uploadHeaders = @{
  'Authorization' = "Bearer $token"
  'User-Agent' = 'short-polling-vpn-release'
  'Content-Type' = 'application/octet-stream'
}
$uploadUri = "https://uploads.github.com/repos/$owner/$repo/releases/$($release.id)/assets?name=$exeName"
$asset = Invoke-RestMethod -Uri $uploadUri -Headers $uploadHeaders -Method Post -InFile $exe

Write-Host "RELEASE_URL=$($release.html_url)"
Write-Host "ASSET_URL=$($asset.browser_download_url)"
