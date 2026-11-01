<#
.SYNOPSIS
    EviGraph AI Network Forensic Framework & Console Runner

.DESCRIPTION
    Launches the EviGraph forensic REST API server and the Next.js Forensic Operations Console,
    or executes the end-to-end forensic pipeline.

.PARAMETER Pipeline
    Run the complete end-to-end detection, graph reconstruction, and forensic reasoning pipeline.

.PARAMETER Agent
    Invoke the LLM forensic reasoning agent during pipeline execution.

.PARAMETER Port
    Port for the REST API server (default: 8000).

.PARAMETER ConsolePort
    Port for the Next.js Console (default: 3000).

.PARAMETER HostIP
    Interface for the REST API server (default: 127.0.0.1).

.PARAMETER ApiOnly
    Launch only the Python FastAPI server.

.PARAMETER ConsoleOnly
    Launch only the Next.js Forensic Operations Console.

.PARAMETER Test
    Run the Python test suite with pytest.

.EXAMPLE
    .\run.ps1
    Starts both the REST API server (http://127.0.0.1:8000) and Next.js Console (http://localhost:3000)

.EXAMPLE
    .\run.ps1 -Pipeline -Agent
    Executes the complete forensic detection pipeline with LLM agent reasoning.

.EXAMPLE
    .\run.ps1 -ApiOnly
    Starts only the FastAPI backend on port 8000.
#>

[CmdletBinding()]
param(
    [switch]$Pipeline,
    [switch]$Agent,
    [int]$Port = 8000,
    [int]$ConsolePort = 3000,
    [string]$HostIP = "127.0.0.1",
    [switch]$ApiOnly,
    [switch]$ConsoleOnly,
    [switch]$Test
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host ""
Write-Host " ================================================================" -ForegroundColor Cyan
Write-Host "   EVIGRAPH - EVIDENCE-GROUNDED NETWORK FORENSIC PLATFORM" -ForegroundColor White
Write-Host "   Explainable GNN & Multi-Model Forensic Operations Console" -ForegroundColor Gray
Write-Host " ================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
try {
    $pythonVer = & python --version 2>&1
    Write-Host " [+] Python Environment: $pythonVer" -ForegroundColor Green
} catch {
    Write-Host " [!] ERROR: Python 3.11+ is required but not detected in PATH." -ForegroundColor Red
    exit 1
}

# 2. Check Node
if (-not $ApiOnly) {
    try {
        $nodeVer = & node --version 2>&1
        Write-Host " [+] Node.js Environment: $nodeVer" -ForegroundColor Green
    } catch {
        Write-Host " [!] WARNING: Node.js is required for the Next.js console." -ForegroundColor Yellow
    }
}

# 3. Run Test Suite if requested
if ($Test) {
    Write-Host " [*] Executing pytest test suite..." -ForegroundColor Cyan
    & pytest tests/
    exit $LASTEXITCODE
}

# 4. Run Pipeline if requested
if ($Pipeline) {
    Write-Host " [*] Running end-to-end forensic detection pipeline..." -ForegroundColor Cyan
    $argsList = @("main.py")
    if ($Agent) {
        $argsList += "--agent"
    }
    & python @argsList
    exit $LASTEXITCODE
}

# 5. Launch Services
$env:EVIGRAPH_HOST = $HostIP
$env:EVIGRAPH_PORT = $Port.ToString()
$ServerUrl = "http://$HostIP`:$Port"
$ConsoleUrl = "http://localhost:$ConsolePort"

if ($ConsoleOnly) {
    Write-Host " [*] Launching Next.js Forensic Operations Console on $ConsoleUrl..." -ForegroundColor Cyan
    Set-Location (Join-Path $ScriptDir "console")
    & npm run dev
    exit 0
}

if ($ApiOnly) {
    Write-Host ""
    Write-Host " ================================================================" -ForegroundColor Green
    Write-Host "   REST API SERVER ACTIVE AT: $ServerUrl" -ForegroundColor Yellow
    Write-Host "   Health Endpoint          : $ServerUrl/api/health" -ForegroundColor White
    Write-Host "   Incidents Endpoint       : $ServerUrl/api/incidents" -ForegroundColor White
    Write-Host " ================================================================" -ForegroundColor Green
    Write-Host ""
    & python -m api.server
    exit 0
}

# Default: Start both API and Console
Write-Host ""
Write-Host " ================================================================" -ForegroundColor Green
Write-Host "   EVIGRAPH FORENSIC SERVICES STARTING" -ForegroundColor White
Write-Host "   - FastAPI Backend Server : $ServerUrl" -ForegroundColor Yellow
Write-Host "   - Forensic Web Console   : $ConsoleUrl" -ForegroundColor Cyan
Write-Host " ================================================================" -ForegroundColor Green
Write-Host ""

$apiJob = Start-Job -ScriptBlock {
    param($dir, $hostIp, $portNum)
    Set-Location $dir
    $env:EVIGRAPH_HOST = $hostIp
    $env:EVIGRAPH_PORT = $portNum
    & python -m api.server
} -ArgumentList $ScriptDir, $HostIP, $Port.ToString()

Write-Host " [+] API server started in background (Job ID: $($apiJob.Id))" -ForegroundColor Green
Write-Host " [+] Starting Next.js Forensic Console..." -ForegroundColor Cyan
Write-Host " [i] Press Ctrl+C to terminate both services." -ForegroundColor Gray
Write-Host ""

try {
    Set-Location (Join-Path $ScriptDir "console")
    & npm run dev
} finally {
    Write-Host "`n [!] Shutting down background API server..." -ForegroundColor Yellow
    Stop-Job -Id $apiJob.Id -ErrorAction SilentlyContinue
    Remove-Job -Id $apiJob.Id -ErrorAction SilentlyContinue
    Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*api.server*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host " [+] Services terminated cleanly." -ForegroundColor Green
}
