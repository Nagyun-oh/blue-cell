$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not $env:ADMIN_PASSWORD) {
    $blueAdminSecure = Read-Host 'Initial admin password (12+ characters)' -AsSecureString
    $env:ADMIN_PASSWORD = [System.Net.NetworkCredential]::new('', $blueAdminSecure).Password
}
if (-not $env:USER_PASSWORD) {
    $blueUserSecure = Read-Host 'Initial user password (12+ characters)' -AsSecureString
    $env:USER_PASSWORD = [System.Net.NetworkCredential]::new('', $blueUserSecure).Password
}
$env:LAB_XSS = '1'
$bluePython = Get-Command python -ErrorAction SilentlyContinue
if ($bluePython) { & $bluePython.Source server.py }
else {
    $blueBundled = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
    if (Test-Path -LiteralPath $blueBundled) { & $blueBundled server.py }
    else { throw 'Python 3.11 or newer is required.' }
}
