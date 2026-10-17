# Build the Agent Vault image and verify it end-to-end inside Docker.
#
#   powershell -File agent_vault/test_docker.ps1
#
# Steps: build -> run smoke test in container -> start server -> probe /healthz.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$image = "aegis-agent-vault"

Write-Host "==> Building image '$image' (context: $root)"
docker build -t $image -f (Join-Path $PSScriptRoot "Dockerfile") $root
if ($LASTEXITCODE -ne 0) { throw "docker build failed" }

Write-Host "==> Running smoke test inside the container"
docker run --rm $image python -m agent_vault.smoke_test
if ($LASTEXITCODE -ne 0) { throw "smoke test failed" }

Write-Host "==> Starting server and probing /healthz"
$cid = docker run -d -p 18080:8080 $image
if ($LASTEXITCODE -ne 0) { throw "docker run failed" }
try {
    $ok = $false
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Seconds 1
        try {
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:18080/healthz" `
                -TimeoutSec 2
            Write-Host "healthz: $($resp | ConvertTo-Json -Compress)"
            $ok = $true
            break
        } catch {
            Write-Host "  waiting for server... ($i)"
        }
    }
    if (-not $ok) { throw "server did not become healthy" }
} finally {
    docker rm -f $cid | Out-Null
}

Write-Host "==> Docker build test: PASS"
