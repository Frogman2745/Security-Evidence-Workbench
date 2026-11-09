# Launch the local demonstration using the installed Python.
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'Python was not found. Install Python 3.11 or newer and reopen this terminal.'
}
python validate_feed.py
if ($LASTEXITCODE -ne 0) { throw 'Saved CISA snapshot failed validation.' }
python review_app.py check
if ($LASTEXITCODE -ne 0) { throw 'Decision log failed its integrity check.' }
$url = 'http://127.0.0.1:8765/'
Write-Host "Opening $url"
Start-Process $url
python review_app.py serve
