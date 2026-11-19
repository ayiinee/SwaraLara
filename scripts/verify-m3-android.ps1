param([string]$Adb = 'D:/Android/Sdk/platform-tools/adb.exe', [string]$Serial, [int]$Port = 8788)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$artifactDir = Join-Path $projectRoot '.tools/m3-integration'
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
if (!$Serial) {
    $physicalDevices = @(& $Adb devices | Select-String '^([^\s]+)\s+device$' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Where-Object { $_ -notlike 'emulator-*' })
    if ($physicalDevices.Count -ne 1) { throw 'Connect one physical ADB device or supply -Serial.' }
    $Serial = $physicalDevices[0]
}
if ($Serial -like 'emulator-*') { throw 'Use a physical ADB device. Emulators are not allowed.' }
$priorReverse = & $Adb -s $Serial reverse --list
if ($priorReverse -match "tcp:$Port\s") { throw "Port $Port is already reversed; choose another -Port." }
$priorPort = $env:SWL_FIXTURE_PORT
$priorOrigin = $env:SWL_FIXTURE_PUBLIC_ORIGIN
$priorState = $env:SWL_FIXTURE_STATE_FILE
$server = $null
$reversed = $false
try {
    $env:SWL_FIXTURE_PORT = "$Port"
    $env:SWL_FIXTURE_PUBLIC_ORIGIN = "http://127.0.0.1:$Port"
    $env:SWL_FIXTURE_STATE_FILE = '.tools/m3-integration/runtime.json'
    $started = Get-Date
    $server = Start-Process -FilePath (Get-Command node).Source -ArgumentList @('supabase/tests/contract-server.ts') -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $artifactDir 'server.log') -RedirectStandardError (Join-Path $artifactDir 'server.err')
    $stateFile = Join-Path $artifactDir 'runtime.json'
    $deadline = (Get-Date).AddSeconds(60)
    while (!(Test-Path -LiteralPath $stateFile) -or (Get-Item -LiteralPath $stateFile).LastWriteTime -lt $started) {
        if ($server.HasExited) { throw 'Local test fixture exited. Inspect .tools/m3-integration/server.err.' }
        if ((Get-Date) -gt $deadline) { throw 'Local test fixture startup timed out.' }
        Start-Sleep -Milliseconds 250
    }
    $fixture = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    & $Adb -s $Serial reverse "tcp:$Port" "tcp:$Port"
    if ($LASTEXITCODE -ne 0) { throw 'ADB reverse failed.' }; $reversed = $true
    foreach ($apk in @('android/app/build/outputs/apk/debug/app-debug.apk','android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk')) {
        & $Adb -s $Serial install -r (Join-Path $projectRoot $apk)
        if ($LASTEXITCODE -ne 0) { throw 'APK installation failed. Existing app data was not cleared.' }
    }
    # These ephemeral fixture credentials are read from an ignored file, never echoed.
    $result = & $Adb -s $Serial shell am instrument -w -e timeout_msec 180000 -e fixtureOrigin "http://127.0.0.1:$Port" -e fixturePassword $fixture.password -e fixturePublishableKey $fixture.key -e class id.swaralara.app.M3TransportIntegrationTest id.swaralara.app.test/androidx.test.runner.AndroidJUnitRunner
    $result | Set-Content -LiteralPath (Join-Path $artifactDir 'android-test.txt') -Encoding utf8
    $result
    if (($result -join "`n") -notmatch 'OK \(1 test\)') { throw 'M3 Android integration test did not pass.' }
} finally {
    if ($reversed) { & $Adb -s $Serial reverse --remove "tcp:$Port" }
    if ($server -and !$server.HasExited) { Stop-Process -Id $server.Id }
    $env:SWL_FIXTURE_PORT = $priorPort
    $env:SWL_FIXTURE_PUBLIC_ORIGIN = $priorOrigin
    $env:SWL_FIXTURE_STATE_FILE = $priorState
}
