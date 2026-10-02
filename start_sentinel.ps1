# Sentinel Bot - Auto-start script
# Attend que Docker Desktop soit pret puis lance les conteneurs

$projectPath = "C:\Users\2653474\Desktop\sentinel\sentinel"
$logFile = "$projectPath\sentinel_autostart.log"
$maxWait = 120  # secondes max d'attente pour Docker

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $logFile -Append
}

Write-Log "Demarrage du script Sentinel autostart..."

# Attendre que le daemon Docker soit operationnel
$elapsed = 0
$dockerReady = $false

while ($elapsed -lt $maxWait) {
    try {
        $result = & docker info 2>&1
        if ($LASTEXITCODE -eq 0) {
            $dockerReady = $true
            Write-Log "Docker est pret apres ${elapsed}s."
            break
        }
    } catch {
        # Docker pas encore pret
    }
    Start-Sleep -Seconds 5
    $elapsed += 5
    Write-Log "Attente Docker... (${elapsed}s / ${maxWait}s)"
}

if (-not $dockerReady) {
    Write-Log "ERREUR: Docker n'a pas demarre apres ${maxWait}s. Abandon."
    exit 1
}

# Lancer docker compose
Write-Log "Lancement de docker compose up -d..."
Set-Location $projectPath
$output = & docker compose up -d 2>&1
Write-Log "Resultat: $output"

if ($LASTEXITCODE -eq 0) {
    Write-Log "Sentinel demarre avec succes!"
} else {
    Write-Log "ERREUR au demarrage: code $LASTEXITCODE"
}
