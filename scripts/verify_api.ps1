# verify_api.ps1 -- regenerates every piece of evidence for steps 2-3.
# Usage (from the project root, with the Flask app already running):
#     powershell -ExecutionPolicy Bypass -File .\scripts\verify_api.ps1
param(
    [string]$Base = "http://127.0.0.1:5000"
)

$ErrorActionPreference = "Stop"
$script:lines = @()

function Write-Section([string]$id, [string]$title) {
    $line = ""
    Write-Host ""
    Write-Host ("===== [$id] $title =====") -ForegroundColor Cyan
    $script:lines += ("===== [$id] $title =====")
}

function Write-Out([string]$text) {
    Write-Host $text
    $script:lines += $text
}

function Get-Status($err) {
    try { return [int]$err.Exception.Response.StatusCode } catch { return "?" }
}

Write-Host "Target : $Base"
Write-Host "Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# ---- 01 health ----
Write-Section "01" "GET /health"
$r = Invoke-RestMethod "$Base/health"
Write-Out ("status = " + $r.status)

# ---- 02 no token ----
Write-Section "02" "GET /api/data without token  (expect 401)"
try {
    Invoke-RestMethod "$Base/api/data" | Out-Null
    Write-Out "UNEXPECTED: request succeeded without a token"
} catch {
    Write-Out ("status = " + (Get-Status $_))
}

# ---- 03 SQL injection attempt ----
Write-Section "03" "POST /auth/login with SQLi payload  (expect 401)"
$sqli = '{"username":"alice'' OR ''1''=''1","password":"x"}'
Write-Out ("payload = " + $sqli)
try {
    Invoke-RestMethod "$Base/auth/login" -Method Post -ContentType "application/json" -Body $sqli | Out-Null
    Write-Out "UNEXPECTED: SQL injection logged in"
} catch {
    Write-Out ("status = " + (Get-Status $_))
}

# ---- 04 valid login ----
Write-Section "04" "POST /auth/login with valid credentials  (expect 200 + JWT)"
$good = '{"username":"alice","password":"AlicePassw0rd!"}'
$login = Invoke-RestMethod "$Base/auth/login" -Method Post -ContentType "application/json" -Body $good
$hdr = @{ Authorization = "Bearer $($login.token)" }
Write-Out ("token      = " + $login.token.Substring(0, 30) + "...")
Write-Out ("token_type = " + $login.token_type)
Write-Out ("expires_in = " + $login.expires_in + " seconds")

# ---- 05 authorised read ----
Write-Section "05" "GET /api/data with Bearer token  (expect 200 + users)"
$data = Invoke-RestMethod "$Base/api/data" -Headers $hdr
foreach ($u in $data.data) {
    Write-Out ("id=" + $u.id + "  username=" + $u.username + "  role=" + $u.role)
}

# ---- 06 XSS payload ----
Write-Section "06" "POST /api/posts with script payload  (expect escaped output)"
$xss = '{"title":"<script>alert(1)</script>","body":"xss test"}'
Write-Out ("payload = " + $xss)
$post = Invoke-RestMethod "$Base/api/posts" -Method Post -ContentType "application/json" -Headers $hdr -Body $xss
Write-Out ("returned title = " + $post.title)
if ($post.title -like "*&lt;script&gt;*") { Write-Out "RESULT: escaped -> OK" } else { Write-Out "RESULT: NOT escaped -> FAIL" }

# ---- 07 password storage ----
Write-Section "07" "password storage in SQLite  (expect bcrypt hash, no plaintext)"
$db = Join-Path (Split-Path $PSScriptRoot -Parent) "app.db"
if (Test-Path $db) {
    $code = "import sqlite3,sys; db=sys.argv[1]; [print(u, '->', h[:29] + '...') for u,h in sqlite3.connect(db).execute('select username,password_hash from users')]"
    & python -c $code $db | ForEach-Object { Write-Out $_ }
} else {
    Write-Out "app.db not found at $db (start the app once first)"
}

# ---- save log ----
$logDir = Join-Path (Split-Path $PSScriptRoot -Parent) "docs"
New-Item -ItemType Directory -Force $logDir | Out-Null
$logPath = Join-Path $logDir "verify.log"
$script:lines | Set-Content -Path $logPath -Encoding UTF8
Write-Host ""
Write-Host "Saved: $logPath" -ForegroundColor Green
