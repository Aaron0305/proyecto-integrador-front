# Script para arreglar RP_ID en BiometricSettings.jsx

$file = "src\components\Auth\BiometricSettings.jsx"

# Leer el contenido
$content = Get-Content $file -Raw

# Buscar y reemplazar el bloque RP_ID
$oldCode = @"
const RP_ID = (() => {
  try {
    return new URL(API_ENV.BASE_ORIGIN).hostname || 'localhost';
  } catch {
    return 'localhost';
  }
})();
"@

$newCode = @"
const RP_ID = (() => {
  try {
    const currentHostname = window.location.hostname;
    console.log('🔍 RP_ID:', currentHostname);
    if (currentHostname === 'localhost' || currentHostname === '127.0.0.1') {
      return 'localhost';
    }
    return currentHostname;
  } catch {
    return 'localhost';
  }
})();
"@

# Reemplazar
$content = $content.Replace($oldCode, $newCode)

# Guardar
$content | Set-Content $file -NoNewline

Write-Host "✅ Archivo reparado correctamente" -ForegroundColor Green
