# Report Windows limitations explicitly; never enter WSL, download GCC, or connect to a VM implicitly.
if ($MyInvocation.InvocationName -eq '.') { throw 'Execute this script; do not dot-source it.' }
$ErrorActionPreference = 'Stop'
$astraRoot = $PSScriptRoot
$astraCache = if ($env:ASTRA_CACHE_ROOT) { $env:ASTRA_CACHE_ROOT } else { Join-Path $astraRoot "build" }
$astraPython = Join-Path $astraCache 'tools/python-build/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $astraPython)) { $astraPython = 'python' }
& $astraPython -B (Join-Path $PSScriptRoot 'tools/build.py') @args
exit $LASTEXITCODE
