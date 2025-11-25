# Monitoreo automatico GitHub Actions
$repo = "Coreymillia/Bruce-Shark-Bait-M5StackC-Plus2-WiFi-Defense"
$maxAttempts = 20
$attemptDelay = 45

Write-Host "=========================================="
Write-Host "  Monitoreo Automatico GitHub Actions"
Write-Host "=========================================="
Write-Host ""

for ($i = 1; $i -le $maxAttempts; $i++) {
    Write-Host "[$i/$maxAttempts] Verificando... $(Get-Date -Format 'HH:mm:ss')"
    
    try {
        $apiUrl = "https://api.github.com/repos/$repo/actions/runs?per_page=5"
        $runs = Invoke-RestMethod -Uri $apiUrl -Headers @{"Accept" = "application/vnd.github+json"}
        
        $latestRun = $runs.workflow_runs | Where-Object { $_.name -eq "Build Bruce Firmware" } | Select-Object -First 1
        
        if ($latestRun) {
            $status = $latestRun.status
            $conclusion = $latestRun.conclusion
            $runId = $latestRun.id
            
            Write-Host "  Estado: $status"
            if ($conclusion) { Write-Host "  Resultado: $conclusion" }
            
            if ($status -eq "completed" -and $conclusion -eq "success") {
                Write-Host ""
                Write-Host "=========================================="
                Write-Host "  COMPILACION EXITOSA!"
                Write-Host "=========================================="
                Write-Host ""
                Write-Host "Abriendo pagina de descarga..."
                Start-Process "https://github.com/$repo/actions/runs/$runId"
                Write-Host ""
                Write-Host "INSTRUCCIONES:"
                Write-Host "1. Baja hasta 'Artifacts'"
                Write-Host "2. Click en 'firmware-m5stack-cplus2'"
                Write-Host "3. Extrae el firmware.bin a: C:\Bruce\firmware_descargado\"
                Write-Host ""
                Write-Host "Presiona ENTER cuando termines de descargar..."
                $null = Read-Host
                
                $firmwarePath = "C:\Bruce\firmware_descargado\firmware.bin"
                if (Test-Path $firmwarePath) {
                    Write-Host ""
                    Write-Host "Firmware encontrado. Iniciando flasheo..."
                    & powershell -ExecutionPolicy Bypass -File "C:\Bruce\flashear_firmware.ps1"
                } else {
                    Write-Host ""
                    Write-Host "Firmware no encontrado. Ejecuta manualmente:"
                    Write-Host "  .\flashear_firmware.ps1"
                }
                exit 0
            }
            elseif ($status -eq "completed" -and $conclusion -eq "failure") {
                Write-Host ""
                Write-Host "COMPILACION FALLO"
                Write-Host "Ver logs: https://github.com/$repo/actions/runs/$runId"
                exit 1
            }
            else {
                Write-Host "  Aun en progreso..."
            }
        } else {
            Write-Host "  No se encontro workflow"
        }
    }
    catch {
        Write-Host "  Error: $_"
    }
    
    if ($i -lt $maxAttempts) {
        Write-Host "  Esperando $attemptDelay segundos..."
        Write-Host ""
        Start-Sleep -Seconds $attemptDelay
    }
}

Write-Host ""
Write-Host "Tiempo maximo alcanzado"
Write-Host "Verifica manualmente: https://github.com/$repo/actions"
