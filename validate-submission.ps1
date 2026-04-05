param (
    [Parameter(Mandatory=$true)]
    [string]$PingUrl,
    
    [string]$RepoDir = "."
)

# Colors
$RED = "DarkRed"
$GREEN = "DarkGreen"
$YELLOW = "DarkYellow"

function Log-Msg {
    param([string]$Message)
    $time = (Get-Date).ToUniversalTime().ToString("HH:mm:ss")
    Write-Host "[$time] $Message"
}

function Pass {
    param([string]$Message)
    $time = (Get-Date).ToUniversalTime().ToString("HH:mm:ss")
    Write-Host "[$time] " -NoNewline
    Write-Host "PASSED" -ForegroundColor Green -NoNewline
    Write-Host " -- $Message"
}

function Fail {
    param([string]$Message)
    $time = (Get-Date).ToUniversalTime().ToString("HH:mm:ss")
    Write-Host "[$time] " -NoNewline
    Write-Host "FAILED" -ForegroundColor Red -NoNewline
    Write-Host " -- $Message"
}

function Hint {
    param([string]$Message)
    Write-Host "  Hint: " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Stop-At {
    param([string]$Step)
    Write-Host ""
    Write-Host "Validation stopped at $Step. Fix the above before continuing." -ForegroundColor Red
    exit 1
}

# Ensure directory exists
$fullRepoDir = Resolve-Path $RepoDir -ErrorAction SilentlyContinue
if (-not $fullRepoDir) {
    Write-Host "Error: directory '$RepoDir' not found" -ForegroundColor Red
    exit 1
}
$RepoDir = $fullRepoDir.Path
$PingUrl = $PingUrl.TrimEnd("/")

Write-Host ""
Write-Host "========================================" -Style Bold
Write-Host "  OpenEnv Submission Validator" -Style Bold
Write-Host "========================================" -Style Bold
Log-Msg "Repo:     $RepoDir"
Log-Msg "Ping URL: $PingUrl"
Write-Host ""

Log-Msg "Step 1/3: Pinging HF Space ($PingUrl/reset) ..."

try {
    $response = Invoke-WebRequest -Uri "$PingUrl/reset" -Method POST -ContentType "application/json" -Body "{}" -TimeoutSec 30 -ErrorAction Stop
    $statusCode = $response.StatusCode
} catch {
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
    } else {
        $statusCode = 000
    }
}

if ($statusCode -eq 200) {
    Pass "HF Space is live and responds to /reset"
} elseif ($statusCode -eq 000) {
    Fail "HF Space not reachable (connection failed or timed out)"
    Hint "Check your network connection and that the Space is running."
    Hint "Try: curl -s -o /dev/null -w '%{http_code}' -X POST $PingUrl/reset"
    Stop-At "Step 1"
} else {
    Fail "HF Space /reset returned HTTP $statusCode (expected 200)"
    Hint "Make sure your Space is running and the URL is correct."
    Hint "Try opening $PingUrl in your browser first."
    Stop-At "Step 1"
}

Log-Msg "Step 2/3: Running docker build ..."

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "docker command not found"
    Hint "Install Docker: https://docs.docker.com/get-docker/"
    Stop-At "Step 2"
}

if (Test-Path "$RepoDir\Dockerfile") {
    $DockerContext = $RepoDir
} elseif (Test-Path "$RepoDir\server\Dockerfile") {
    $DockerContext = "$RepoDir\server"
} else {
    Fail "No Dockerfile found in repo root or server/ directory"
    Stop-At "Step 2"
}

Log-Msg "  Found Dockerfile in $DockerContext"

try {
    # Run Docker build
    $buildOutput = & docker build $DockerContext 2>&1
    if ($LASTEXITCODE -eq 0) {
        Pass "Docker build succeeded"
    } else {
        Fail "Docker build failed"
        $buildOutput | Select-Object -Last 20
        Stop-At "Step 2"
    }
} catch {
    Fail "Docker build failed"
    Stop-At "Step 2"
}

Log-Msg "Step 3/3: Running openenv validate ..."

if (-not (Get-Command openenv -ErrorAction SilentlyContinue)) {
    Fail "openenv command not found"
    Hint "Install it: pip install openenv-core"
    Stop-At "Step 3"
}

try {
    $currentDir = Get-Location
    Set-Location $RepoDir
    $env:PING_URL = $PingUrl
    $validateOutput = & openenv validate 2>&1
    if ($LASTEXITCODE -eq 0) {
        Pass "openenv validate passed"
        if ($validateOutput) { Log-Msg "  $validateOutput" }
    } else {
        Fail "openenv validate failed"
        $validateOutput
        Stop-At "Step 3"
    }
    Set-Location $currentDir
} catch {
    Fail "openenv validate failed"
    Stop-At "Step 3"
}

Write-Host ""
Write-Host "========================================"
Write-Host "  All 3/3 checks passed!" -ForegroundColor Green
Write-Host "  Your submission is ready to submit." -ForegroundColor Green
Write-Host "========================================"
Write-Host ""
exit 0
