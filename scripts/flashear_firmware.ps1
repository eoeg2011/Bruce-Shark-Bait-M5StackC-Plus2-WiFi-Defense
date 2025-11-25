Param(
  [string]$Port = 'COM8',
  [int]$Baud = 1500000,
  [string]$Tag = 'latest'
)
$ErrorActionPreference = 'Stop'
$repo = 'eoeg2011/Bruce-Shark-Bait-M5StackC-Plus2-WiFi-Defense'
$temp = Join-Path $env:TEMP "bruce_fw_$Tag"
New-Item -ItemType Directory -Force -Path $temp | Out-Null

# Descargar firmware del release "latest"
$api = "https://api.github.com/repos/$repo/releases/tags/$Tag"
$release = Invoke-RestMethod -Uri $api -UseBasicParsing
$asset = $release.assets | Where-Object { $_.name -like 'firmware.bin' -or $_.name -like '*m5stack-cplus2*.bin' } | Select-Object -First 1
if (-not $asset) { throw 'No se encontró firmware en el Release.' }
$binPath = Join-Path $temp $asset.name
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $binPath -UseBasicParsing

# Flashear con esptool.py (requiere Python y esptool en PATH)
Write-Host "Flasheando $($asset.name) en $Port a $Baud..."
$cmd = "esptool.py --chip esp32 --port $Port --baud $Baud write_flash -z 0x10000 `"$binPath`""
Write-Host $cmd
python -m esptool --chip esp32 --port $Port --baud $Baud write_flash -z 0x10000 "$binPath"
Write-Host 'Listo. Reinicia el dispositivo si no lo hace automáticamente.'
