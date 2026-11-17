param([string]$JavaHome,[switch]$DeviceTests,[switch]$Tls12)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if (!$JavaHome) {
    $localJdk = Get-ChildItem (Join-Path $projectRoot '.tools\jdk-full') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'bin\javac.exe') } | Select-Object -First 1
    if ($localJdk) { $JavaHome = $localJdk.FullName } else { $JavaHome = $env:JAVA_HOME }
}
if (!$JavaHome -or !(Test-Path (Join-Path $JavaHome 'bin\javac.exe'))) {
    throw 'JDK lengkap belum ditemukan. Gunakan -JavaHome <path JDK 17>.'
}
$previousJava = $env:JAVA_HOME
try {
    $env:JAVA_HOME = $JavaHome
    Push-Location (Join-Path $projectRoot 'android')
    try {
        $transportArgs = @()
        if ($Tls12) { $transportArgs = @('-Dhttps.protocols=TLSv1.2','-Djdk.tls.client.protocols=TLSv1.2') }
        & .\gradlew.bat :core-crypto:test :recording-core:testDebugUnitTest :core-demo:assembleDebug :app:assembleDebug :recording-core:lintDebug :core-demo:lintDebug @transportArgs
        if ($LASTEXITCODE -ne 0) { throw "Build/test/lint gagal (exit $LASTEXITCODE)." }
        if ($DeviceTests) {
            & .\gradlew.bat :recording-core:connectedDebugAndroidTest :core-demo:connectedDebugAndroidTest @transportArgs
            if ($LASTEXITCODE -ne 0) { throw "Tes perangkat gagal (exit $LASTEXITCODE)." }
        }
    } finally { Pop-Location }
} finally { $env:JAVA_HOME = $previousJava }
