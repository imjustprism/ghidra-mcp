param(
    [string]$GhidraHome = "D:\ghidra_12.1_PUBLIC",
    [switch]$SkipRust,
    [switch]$SkipJava,
    [switch]$NoClose,
    [switch]$Relaunch,
    [switch]$KillGame,
    [string]$LogFile
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $NoClose -and -not (Test-Admin)) {
    $log = [System.IO.Path]::GetTempFileName()
    $passArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
        '-GhidraHome', $GhidraHome, '-LogFile', $log)
    if ($SkipRust) { $passArgs += '-SkipRust' }
    if ($SkipJava) { $passArgs += '-SkipJava' }
    if ($Relaunch) { $passArgs += '-Relaunch' }
    if ($KillGame) { $passArgs += '-KillGame' }
    Write-Host "Elevating to close Ghidra and free the extension lock (approve the UAC prompt)..."
    $p = Start-Process pwsh -Verb RunAs -ArgumentList $passArgs -PassThru -Wait
    if (Test-Path $log) {
        Get-Content $log
        Remove-Item $log -ErrorAction SilentlyContinue
    }
    Write-Host "DEPLOY_EXIT=$($p.ExitCode)"
    exit $p.ExitCode
}

if ($LogFile) { Start-Transcript -Path $LogFile -Append | Out-Null }
try {
    function Stop-Ghidra {
        $procs = Get-CimInstance Win32_Process -Filter "Name = 'javaw.exe' OR Name = 'java.exe'" |
            Where-Object { $_.CommandLine -match 'ghidra' }
        foreach ($p in $procs) {
            Write-Host "Stopping Ghidra process $($p.ProcessId)"
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }

    function Wait-Removed([string]$path, [int]$timeoutSec = 20) {
        if (-not (Test-Path $path)) { return $true }
        $deadline = (Get-Date).AddSeconds($timeoutSec)
        while ((Get-Date) -lt $deadline) {
            try {
                Remove-Item -Recurse -Force $path -ErrorAction Stop
                return $true
            } catch {
                Start-Sleep -Milliseconds 400
            }
        }
        return $false
    }

    if ($KillGame) {
        foreach ($name in @('thinclient', 'dro_client64', 'Alicia')) {
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

    if (-not $NoClose) { Stop-Ghidra }

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
        $target = Join-Path $userExtRoot "ghidra-mcp-plugin"
        if (-not (Wait-Removed $target)) { throw "extension jar still locked: $target (is Ghidra still running?)" }
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
    }

    if (-not $SkipRust) {
        Write-Host "Killing any running ghidra-mcp.exe..."
        Get-Process ghidra-mcp -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Milliseconds 300
        Write-Host "Building Rust bridge..."
        Push-Location $root
        $vcvars = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat" `
            -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($vcvars) {
            cmd /c "`"$($vcvars.FullName)`" >nul 2>&1 && cargo build --release"
        } else {
            & cargo build --release
        }
        if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cargo failed" }
        Pop-Location
        Write-Host "Rust binary at $root\target\release\ghidra-mcp.exe (restart Claude Desktop to reload)"
    }

    if ($Relaunch) {
        $launcher = Join-Path $GhidraHome "ghidraRun.bat"
        if (Test-Path $launcher) {
            Write-Host "Relaunching Ghidra..."
            Start-Process -FilePath $launcher
        }
    }

    Write-Host "Done. Ghidra settings dir: $verDir"
    if (-not $LogFile) { Write-Host "DEPLOY_EXIT=0" }
}
finally {
    if ($LogFile) { Stop-Transcript | Out-Null }
}
