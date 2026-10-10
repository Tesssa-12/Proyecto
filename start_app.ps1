$ErrorActionPreference = 'Stop'

$existingListener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($existingListener) {
    Write-Host 'Peya Tools ya está escuchando en http://127.0.0.1:8000/'
    exit 0
}

$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    Write-Error 'No se encontró .venv\Scripts\python.exe. Consulta README.md para preparar el entorno.'
    exit 1
}

$random = [Security.Cryptography.RandomNumberGenerator]::Create()
$secretBytes = New-Object byte[] 48
$random.GetBytes($secretBytes)
$env:SESSION_SECRET = [Convert]::ToBase64String($secretBytes)
$random.Dispose()
$env:SQLSERVER_SERVER = if ($env:SQLSERVER_SERVER) { $env:SQLSERVER_SERVER } else { 'localhost' }
$env:SQLSERVER_DATABASE = if ($env:SQLSERVER_DATABASE) { $env:SQLSERVER_DATABASE } else { 'AuditoriaDatos' }

Set-Location -LiteralPath $PSScriptRoot
Write-Host 'Peya Tools iniciará en http://127.0.0.1:8000/. Mantén esta ventana abierta.'
& $python -m uvicorn main:app --host 127.0.0.1 --port 8000
exit $LASTEXITCODE
