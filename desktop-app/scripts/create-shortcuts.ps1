$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Get-ChildItem (Join-Path $root 'release') -Filter 'Short-Polling-VPN-*-portable.exe' -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $exe) {
  throw 'Portable build not found. Run npm run dist first.'
}

$desktop = [Environment]::GetFolderPath('Desktop')
$shell = New-Object -ComObject WScript.Shell

$shortcut = $shell.CreateShortcut((Join-Path $desktop 'Short Polling VPN.lnk'))
$shortcut.TargetPath = $exe.FullName
$shortcut.WorkingDirectory = $exe.DirectoryName
$shortcut.IconLocation = $exe.FullName
$shortcut.Description = 'Short Polling VPN client'
$shortcut.Save()

$admin = $shell.CreateShortcut((Join-Path $desktop 'Short Polling VPN (Admin).lnk'))
$admin.TargetPath = 'powershell.exe'
$admin.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command Start-Process -FilePath '$($exe.FullName)' -Verb RunAs"
$admin.WorkingDirectory = $exe.DirectoryName
$admin.IconLocation = $exe.FullName
$admin.Description = 'Short Polling VPN client (Administrator, TUN mode)'
$admin.Save()

Write-Host "Shortcuts created on Desktop: $desktop"
