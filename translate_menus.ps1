Param(
  [string]$Root = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)
$menuPath = Join-Path $Root 'src/core/menu_items'
if (-not (Test-Path $menuPath)) { Write-Error "No se encontró $menuPath"; exit 1 }

# Mapa de traducciones: solo cadenas visibles en menús. Mantener textos cortos.
$map = [ordered]@{
  'Disconnect'             = 'Desconectar'
  'Media Cmds'             = 'Comandos Multimedia'
  'BLE Scan'               = 'Escanear BLE'
  'iBeacon'                = 'iBeacon'
  'Bad BLE'                = 'BLE Malicioso'
  'BLE Keyboard'           = 'Teclado BLE'
  'Applejuice'             = 'Applejuice'
  'SourApple'              = 'SourApple'
  'Windows Spam'           = 'Spam Windows'
  'Samsung Spam'           = 'Spam Samsung'
  'Android Spam'           = 'Spam Android'
  'Spam All'               = 'Spam Todo'
  'Spam Custom'            = 'Spam Personalizado'
  'Ninebot'                = 'Ninebot'
  'Bluetooth'              = 'Bluetooth'

  'WiFi'                   = 'WiFi'
  'Starting a Wifi function will probably make the WebUI stop working' = 'Al iniciar una función WiFi, la WebUI puede dejar de funcionar'
  'Sel: to continue'       = 'Sel: continuar'
  'Any key: to Menu'       = 'Cualquier tecla: Menú'
  'Connect Wifi'           = 'Conectar WiFi'
  'WiFi AP'                = 'Punto de acceso'
  'pwd:'                   = 'clave:'
  'AP info'                = 'Info AP'
  'Wifi Atks'              = 'Ataques WiFi'
  'Evil Portal'            = 'Portal Maligno'
  'Listen TCP'             = 'Escuchar TCP'
  'Client TCP'             = 'Cliente TCP'
  'TelNET'                 = 'Telnet'
  'Sniffers'               = 'Sniffers'
  'Raw Sniffer'            = 'Sniffer Raw'
  'Probe Sniffer'          = 'Sniffer Probe'
  'WiFi Config'            = 'Config WiFi'
  'Add Evil Wifi'          = 'Agregar WiFi Maligno'
  'Remove Evil Wifi'       = 'Eliminar WiFi Maligno'
  'Change MAC'             = 'Cambiar MAC'
  'Back'                   = 'Atrás'

  'Config'                 = 'Config'
  'Brightness'             = 'Brillo'
  'Dim Time'               = 'Tiempo Atenuado'
  'Orientation'            = 'Orientación'
  'UI Color'               = 'Color UI'
  'UI Theme'               = 'Tema UI'
  'InstaBoot: ON'          = 'Arranque Rápido: ON'
  'InstaBoot: OFF'         = 'Arranque Rápido: OFF'
  'LED Color'              = 'Color LED'
  'LED Effect'             = 'Efecto LED'
  'LED Brightness'         = 'Brillo LED'
  'Led Blink On/Off'       = 'Parpadeo LED On/Off'
  'Sound On/Off'           = 'Sonido On/Off'
  'Sound Volume'           = 'Volumen'
  'Startup WiFi'           = 'WiFi al iniciar'
  'Startup App'            = 'App de inicio'
  'Hide/Show Apps'         = 'Ocultar/Mostrar Apps'
  'Network Creds'          = 'Credenciales Red'
  'Clock'                  = 'Reloj'
  'Sleep'                  = 'Suspender'
  'Factory Reset'          = 'Restablecer'
  'Restart'                = 'Reiniciar'
  'Turn-off'               = 'Apagar'
  'Deep Sleep'             = 'Deep Sleep'
  'Device Pin setting'     = 'Pines del dispositivo'
  'About'                  = 'Acerca de'
  'Dev Mode'               = 'Modo Desarrollador'
}

$files = Get-ChildItem -LiteralPath $menuPath -Filter *.cpp -File
if (-not $files) { Write-Error "No hay .cpp en $menuPath"; exit 1 }

$changes = 0
foreach ($f in $files) {
  $content = Get-Content -LiteralPath $f.FullName -Raw
  $original = $content

  foreach ($key in $map.Keys) {
    # Reemplazo literal entre comillas (no regex) para evitar problemas de operador -replace
    $content = $content.Replace('"' + $key + '"', '"' + $map[$key] + '"')
    $content = $content.Replace("'" + $key + "'", "'" + $map[$key] + "'")
  }

  if ($content -ne $original) {
    Set-Content -LiteralPath $f.FullName -Value $content -Encoding UTF8
    Write-Host "Traducido: $($f.Name)"
    $changes++
  }
}
Write-Host "Archivos modificados: $changes"