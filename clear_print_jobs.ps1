param(
    [string]$RemoteHost,
    [string]$Username,
    [string]$Password
)

if (-not $RemoteHost) {
    Write-Error "O nome do host remoto não foi fornecido."
    exit 1
}

$credential = New-Object System.Management.Automation.PSCredential($Username, (ConvertTo-SecureString $Password -AsPlainText -Force))

try {
    Write-Host "Conectando ao host remoto $RemoteHost para limpar trabalhos de impressão..."

    # Obter todos os trabalhos de impressão
    $printJobs = Get-WmiObject -Class Win32_PrintJob -ComputerName $RemoteHost -Credential $credential -ErrorAction Stop

    $cleanedJobs = 0
    foreach ($job in $printJobs) {
        # Status 0 = Other, 1 = Paused, 2 = Error, 3 = Deleting, 4 = Spooling, 5 = Printing, 6 = Offline, 7 = PaperOut, 8 = Printed, 9 = Deleted, 10 = Blocked, 11 = UserIntervention
        # Vamos focar em Paused (1) e Error (2) e Blocked (10)
        if ($job.JobStatus -eq 1 -or $job.JobStatus -eq 2 -or $job.JobStatus -eq 10) {
            Write-Host "Removendo trabalho de impressão: $($job.Document) na impressora $($job.Name) com status $($job.JobStatus)"
            $job.Delete()
            $cleanedJobs++
        }
    }

    Write-Host "Limpeza de trabalhos de impressão concluída. $cleanedJobs trabalhos removidos."
    exit 0
}
catch {
    Write-Error "Erro ao limpar trabalhos de impressão no host remoto $RemoteHost : ${_}"
    exit 1
}