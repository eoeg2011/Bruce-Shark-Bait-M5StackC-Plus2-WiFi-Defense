# Script para descargar firmware de GitHub Actions
$repo = "Coreymillia/Bruce-Shark-Bait-M5StackC-Plus2-WiFi-Defense"
$workflowName = "Build Bruce Firmware"
$artifactName = "firmware-m5stack-cplus2"
$outputDir = "C:\Bruce\firmware_descargado"

Write-Host "=========================================="
Write-Host "Descargador de Firmware GitHub Actions"
Write-Host "=========================================="
Write-Host ""

# Crear directorio de salida
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "[1/3] Obteniendo último workflow ejecutado..."
$apiUrl = "https://api.github.com/repos/$repo/actions/runs?status=completed&per_page=1"

try {
    $runs = Invoke-RestMethod -Uri $apiUrl -Headers @{
        "Accept" = "application/vnd.github+json"
    }
    
    if ($runs.workflow_runs.Count -eq 0) {
        Write-Host "No se encontraron workflows completados. Espera a que termine la compilación."
        Write-Host "Verifica en: https://github.com/$repo/actions"
        exit 1
    }
    
    $latestRun = $runs.workflow_runs[0]
    $runId = $latestRun.id
    $status = $latestRun.status
    $conclusion = $latestRun.conclusion
    
    Write-Host "  Run ID: $runId"
    Write-Host "  Estado: $status"
    Write-Host "  Resultado: $conclusion"
    Write-Host ""
    
    if ($conclusion -ne "success") {
        Write-Host "La compilación no fue exitosa. Estado: $conclusion"
        Write-Host "Revisa los logs en: $($latestRun.html_url)"
        exit 1
    }
    
    Write-Host "[2/3] Obteniendo artifacts..."
    $artifactsUrl = "https://api.github.com/repos/$repo/actions/runs/$runId/artifacts"
    $artifacts = Invoke-RestMethod -Uri $artifactsUrl -Headers @{
        "Accept" = "application/vnd.github+json"
    }
    
    $artifact = $artifacts.artifacts | Where-Object { $_.name -eq $artifactName }
    
    if (-not $artifact) {
        Write-Host "No se encontró el artifact '$artifactName'"
        Write-Host "Artifacts disponibles:"
        $artifacts.artifacts | ForEach-Object { Write-Host "  - $($_.name)" }
        exit 1
    }
    
    Write-Host "  Artifact encontrado: $($artifact.name)"
    Write-Host "  Tamaño: $([math]::Round($artifact.size_in_bytes / 1MB, 2)) MB"
    Write-Host ""
    
    Write-Host "[3/3] Descargando firmware..."
    Write-Host "  NOTA: GitHub requiere autenticación para descargar artifacts."
    Write-Host "  Descarga manual desde: https://github.com/$repo/actions/runs/$runId"
    Write-Host ""
    Write-Host "O usa GitHub CLI:"
    Write-Host "  gh run download $runId -n $artifactName -D $outputDir"
    Write-Host ""
    
} catch {
    Write-Host "Error: $_"
    Write-Host "Descarga manual: https://github.com/$repo/actions"
}

Write-Host "=========================================="
