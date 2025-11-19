# restart_spooler.ps1
# Este script para e inicia o serviço de Spooler de Impressão.

# --- Bloco de verificação de privilégios de administrador ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process PowerShell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"`$scriptPath`""
    exit
}
# --- Fim do bloco de verificação de privilégios de administrador ---

param(
    [string]$ServiceName
)

if (-not $ServiceName) {
    Write-Error "O nome do serviço não foi fornecido. Uso: .\restart_service.ps1 -ServiceName <NomeDoServico>"
    exit 1
}

$serviceName = $ServiceName

Write-Host "Tentando parar o serviço '$serviceName'..."
try {
    Stop-Service -Name $serviceName -Force -ErrorAction Stop
    Write-Host "Serviço '$serviceName' parado com sucesso."
} catch {
    Write-Error "Erro ao parar o serviço '$serviceName': $($_.Exception.Message)"
    exit 1
}

Write-Host "Aguardando 2 segundos antes de iniciar o serviço..."
Start-Sleep -Seconds 2

Write-Host "Tentando iniciar o serviço '$serviceName'..."
try {
    Start-Service -Name $serviceName -ErrorAction Stop
    Write-Host "Serviço '$serviceName' iniciado com sucesso."
} catch {
    Write-Error "Erro ao iniciar o serviço '$serviceName': $($_.Exception.Message)"
    exit 1
}

exit 0