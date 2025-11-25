# Script para flashear firmware al M5StickC Plus2
$firmwarePath = "C:\Bruce\firmware_descargado\firmware.bin"
$port = "COM8"
$baud = "1500000"

Write-Host "=========================================="
Write-Host "  Flash Firmware a M5StickC Plus2"
Write-Host "=========================================="
Write-Host ""

# Verificar que existe el firmware
if (-not (Test-Path $firmwarePath)) {
    Write-Host "ERROR: No se encontró el firmware en $firmwarePath"
    Write-Host "Primero ejecuta: .\descargar_firmware.ps1"
    exit 1
}

$firmwareSize = (Get-Item $firmwarePath).Length / 1MB
Write-Host "Firmware encontrado: $([math]::Round($firmwareSize, 2)) MB"
Write-Host "Puerto: $port"
Write-Host "Velocidad: $baud baudios"
Write-Host ""

# Buscar esptool
$esptool = "C:\Users\$env:USERNAME\AppData\Roaming\Python\Python39\Scripts\esptool.py"
if (-not (Test-Path $esptool)) {
    $esptool = Get-Command esptool.py -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
}

if (-not $esptool) {
    Write-Host "ERROR: esptool.py no encontrado"
    Write-Host "Instala con: pip install esptool"
    exit 1
}

Write-Host "Flasheando firmware..."
Write-Host ""

& python $esptool --chip esp32 --port $port --baud $baud `
    --before default_reset --after hard_reset `
    write_flash -z --flash_mode dio --flash_freq 80m --flash_size detect `
    0x0 $firmwarePath

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "  ✓ Firmware flasheado exitosamente"
    Write-Host "=========================================="
    Write-Host ""
    Write-Host "El M5StickC Plus2 debería reiniciarse automáticamente."
    Write-Host "Los menús ahora deberían aparecer en español."
} else {
    Write-Host ""
    Write-Host "ERROR: Falló el flasheo"
    Write-Host "Verifica que el dispositivo esté conectado en $port"
}
