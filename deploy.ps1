param(
    [string]$GhidraHome = "D:\ghidra_12.1_PUBLIC",
    [switch]$SkipRust,
    [switch]$SkipJava,
    [switch]$CloseGhidra,
    [switch]$KillGame
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($KillGame) {
    foreach ($name in @('thinclient', 'dro_client64')) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "Stopping game process $name ($($_.Id))"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

$appProps = Join-Path $GhidraHome "Ghidra\application.properties"
if (-not (Test-Path $appProps)) { throw "Not a Ghidra install (no application.properties): $GhidraHome" }
$props = Get-Content $appProps
$ver = ($props | Where-Object { $_ -match '^application\.version=' }) -replace '.*=', ''
$rel = ($props | Where-Object { $_ -match '^application\.release\.name=' }) -replace '.*=', ''
$verDir = "ghidra_${ver}_${rel}"

$userExtRoot = Join-Path $env:APPDATA "ghidra\$verDir\Extensions"
$installExtDir = Join-Path $GhidraHome "Extensions\Ghidra"

if (-not $SkipJava) {
    Write-Host "Building plugin..."
    if (Test-Path "$env:USERPROFILE\scoop\apps\temurin21-jdk\current") {
        $env:JAVA_HOME = "$env:USERPROFILE\scoop\apps\temurin21-jdk\current"
    }
    Push-Location (Join-Path $root "plugin")
    & mvn -q clean package -DskipTests
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "mvn failed" }
    Pop-Location

    $zip = (Get-ChildItem (Join-Path $root "plugin\target") -Filter "ghidra-mcp-plugin-*.zip")[0].FullName

    if ($CloseGhidra) {
        $procs = Get-CimInstance Win32_Process -Filter "Name = 'javaw.exe' OR Name = 'java.exe'" |
            Where-Object { $_.CommandLine -match 'ghidra' }
        foreach ($p in $procs) {
            Write-Host "Stopping Ghidra process $($p.ProcessId)"
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 800
    }

    $target = Join-Path $userExtRoot "ghidra-mcp-plugin"
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    New-Item -ItemType Directory -Force -Path $userExtRoot | Out-Null
    Expand-Archive -Path $zip -DestinationPath $userExtRoot -Force

    $extProps = Join-Path $target "extension.properties"
    (Get-Content $extProps) `
        -replace '^version=.*', "version=$ver" `
        -replace '^ghidraVersion=.*', "ghidraVersion=$ver" | Set-Content $extProps
    Write-Host "Extracted extension to $target (ghidraVersion=$ver)"

    if (Test-Path $installExtDir) {
        Get-ChildItem $installExtDir -Filter "ghidra-mcp-plugin-*.zip" -ErrorAction SilentlyContinue | Remove-Item -Force
        Copy-Item -Force $zip $installExtDir
        Write-Host "Copied zip to $installExtDir"
    }
    Write-Host "Restart Ghidra. First time only: File -> Configure -> Developer -> enable ghidra-mcp-plugin."
}

if (-not $SkipRust) {
    Write-Host "Killing any running ghidra-mcp.exe..."
    Get-Process ghidra-mcp -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 300
    Write-Host "Building Rust bridge..."
    Push-Location $root
    & cargo build --release
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cargo failed" }
    Pop-Location
    Write-Host "Rust binary at $root\target\release\ghidra-mcp.exe (restart Claude Desktop to reload)"
}

Write-Host "Done. Ghidra settings dir: $verDir"
