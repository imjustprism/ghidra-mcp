#Requires -Version 7
<#
.SYNOPSIS
  Build + deploy ghidra-mcp (plugin zip + Rust bridge) — fast, kill-locks-first.

.EXAMPLE
  .\deploy.ps1
  .\deploy.ps1 -Relaunch
  .\deploy.ps1 -SkipRust
  .\deploy.ps1 -SkipJava -Relaunch
  .\deploy.ps1 -Clean          # force mvn clean
  .\deploy.ps1 -Dist           # full LTO rust profile (slow, ship builds)
#>
param(
    [string]$GhidraHome = "D:\ghidra_12.1_PUBLIC",
    [switch]$SkipRust,
    [switch]$SkipJava,
    [switch]$NoClose,
    [switch]$Relaunch,
    [switch]$KillGame,
    [switch]$Quiet,
    [switch]$Clean,   # mvn clean (default: incremental package only)
    [switch]$Dist,    # cargo --profile dist (fat LTO) instead of release
    [string]$LogFile
)

$ErrorActionPreference = "Stop"
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [Console]::OutputEncoding
} catch { }

$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:t0 = [System.Diagnostics.Stopwatch]::StartNew()
$script:phases = [System.Collections.Generic.List[object]]::new()

# truecolor palette (falls back fine on modern Windows Terminal / pwsh 7)
$C = @{
    dim    = "`e[2m"
    bold   = "`e[1m"
    reset  = "`e[0m"
    cyan   = "`e[38;2;94;234;212m"
    mint   = "`e[38;2;52;211;153m"
    pink   = "`e[38;2;244;114;182m"
    amber  = "`e[38;2;251;191;36m"
    slate  = "`e[38;2;148;163;184m"
    red    = "`e[38;2;248;113;113m"
    white  = "`e[38;2;248;250;252m"
    gray   = "`e[38;2;100;116;139m"
}

function _out([string]$msg) {
    if (-not $Quiet) { [Console]::WriteLine($msg) }
    if ($LogFile) { Add-Content -Path $LogFile -Value ($msg -replace "`e\[[0-9;]*m", "") }
}

function _ms([long]$ms) { "{0:N0}ms" -f $ms }

function _phase([string]$name, [scriptblock]$body) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    _out ("  {0}>{1} {2}{3}{1}" -f $C.cyan, $C.reset, $C.white, $name)
    try {
        & $body
        $sw.Stop()
        $script:phases.Add([pscustomobject]@{ Name = $name; Ms = $sw.ElapsedMilliseconds; Ok = $true })
        _out ("    {0}ok{1}  {2}{3}{1}" -f $C.mint, $C.reset, $C.gray, (_ms $sw.ElapsedMilliseconds))
    } catch {
        $sw.Stop()
        $script:phases.Add([pscustomobject]@{ Name = $name; Ms = $sw.ElapsedMilliseconds; Ok = $false })
        _out ("    {0}err{1} {2}{3}{1}  {0}{4}{1}" -f $C.red, $C.reset, $C.gray, (_ms $sw.ElapsedMilliseconds), $_.Exception.Message)
        throw
    }
}

function Resolve-Tool([string[]]$candidates, [string]$name) {
    foreach ($c in $candidates) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        # support simple globs in candidate paths
        if ($c -match '[\*\?]') {
            $hit = Get-Item -Path $c -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) { return $hit.FullName }
            continue
        }
        if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path }
    }
    foreach ($n in @($name, "$name.cmd", "$name.exe")) {
        $cmd = Get-Command $n -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { return $cmd.Source }
    }
    return $null
}

function Stop-NamedProcesses([string[]]$names) {
    $killed = 0
    foreach ($n in $names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction Stop
                $killed++
            } catch { }
        }
        # belt-and-suspenders
        & taskkill.exe /F /IM "$n.exe" /T 2>$null | Out-Null
    }
    return $killed
}

function Stop-GhidraJava {
    $killed = 0
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name = 'javaw.exe' OR Name = 'java.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -match 'ghidra|Ghidra' }
        foreach ($p in $procs) {
            try {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
                $killed++
            } catch { }
            & taskkill.exe /F /PID $p.ProcessId /T 2>$null | Out-Null
        }
    } catch { }
    return $killed
}

function Unlock-Path([string]$path, [int]$timeoutMs = 8000) {
    if (-not (Test-Path -LiteralPath $path)) { return $true }
    $deadline = [Environment]::TickCount64 + $timeoutMs
    $i = 0
    while ([Environment]::TickCount64 -lt $deadline) {
        try {
            if (Test-Path -LiteralPath $path -PathType Container) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            } else {
                # rename dance frees image-locked exes more reliably than delete
                $bak = "$path.yeet.$PID.$i"
                Move-Item -LiteralPath $path -Destination $bak -Force -ErrorAction Stop
                Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $path) {
                    # still there — delete original after rename of a copy attempt
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                }
            }
            return $true
        } catch {
            $i++
            Start-Sleep -Milliseconds ([Math]::Min(50 + $i * 40, 400))
        }
    }
    return -not (Test-Path -LiteralPath $path)
}

function Yeet-Locks {
    $report = @{ mcp = 0; ghidra = 0; game = 0; files = 0 }

    $report.mcp = Stop-NamedProcesses @('ghidra-mcp')
    # any stray with ghidra-mcp in path
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'ghidra-mcp' -or ($_.CommandLine -and $_.CommandLine -match 'ghidra-mcp\.exe') } |
        ForEach-Object {
            try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $report.mcp++ } catch { }
            & taskkill.exe /F /PID $_.ProcessId /T 2>$null | Out-Null
        }

    if (-not $NoClose) {
        $report.ghidra = Stop-GhidraJava
    }

    if ($KillGame) {
        $report.game = Stop-NamedProcesses @('thinclient', 'dro_client64', 'Alicia', 'AliciaOnline')
    }

    # brief settle so handles drop
    if (($report.mcp + $report.ghidra + $report.game) -gt 0) {
        Start-Sleep -Milliseconds 250
    }

    $rustExe = Join-Path $root "target\release\ghidra-mcp.exe"
    $rustPdb = Join-Path $root "target\release\ghidra_mcp.pdb"
    $yeet = @(
        $rustExe
        "$rustExe.old"
        $rustPdb
        (Join-Path $root "target\release\ghidra-mcp.exe.yeet*")
    )
    # also wipe previous yeet leftovers
    Get-ChildItem (Join-Path $root "target\release") -Filter "ghidra-mcp.exe.yeet*" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; $report.files++ }
    Get-ChildItem (Join-Path $root "target\release") -Filter "ghidra-mcp.exe.old*" -ErrorAction SilentlyContinue |
        ForEach-Object {
            if (Unlock-Path $_.FullName 1500) { $report.files++ }
        }

    if (Test-Path -LiteralPath $rustExe) {
        if (Unlock-Path $rustExe 6000) { $report.files++ }
        else {
            # last resort: move aside so cargo can write a new image
            $aside = "$rustExe.stale.$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
            try {
                Move-Item -LiteralPath $rustExe -Destination $aside -Force -ErrorAction Stop
                $report.files++
            } catch {
                throw "ghidra-mcp.exe still locked after kill — close MCP clients holding it and retry"
            }
        }
    }
    if (Test-Path -LiteralPath $rustPdb) { Unlock-Path $rustPdb 2000 | Out-Null }

    return $report
}

function Ensure-Toolchain {
    # JDK: prefer 21, else whatever is set / on PATH
    $jdkCandidates = @(
        "$env:USERPROFILE\scoop\apps\temurin21-jdk\current"
        "$env:USERPROFILE\scoop\apps\temurin-jdk\current"
        "C:\Program Files\Eclipse Adoptium\jdk-21*"
        $env:JAVA_HOME
    )
    foreach ($j in $jdkCandidates) {
        if ([string]::IsNullOrWhiteSpace($j)) { continue }
        $resolved = Get-Item $j -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($resolved -and (Test-Path (Join-Path $resolved.FullName "bin\javac.exe"))) {
            $env:JAVA_HOME = $resolved.FullName
            $env:Path = "$($env:JAVA_HOME)\bin;" + ($env:Path -replace [regex]::Escape("$($env:JAVA_HOME)\bin;"), "")
            break
        }
    }
    # fall back: keep existing JAVA_HOME / PATH java (e.g. Temurin 25)

    $mvn = Resolve-Tool @(
        "$env:USERPROFILE\apache-maven-3.9.16\bin\mvn.cmd"
        "$env:USERPROFILE\apache-maven-*\bin\mvn.cmd"
        "$env:USERPROFILE\apache-maven\bin\mvn.cmd"
        "$env:USERPROFILE\scoop\apps\maven\current\bin\mvn.cmd"
        "$env:MAVEN_HOME\bin\mvn.cmd"
        "C:\ProgramData\chocolatey\lib\maven\apache-maven-*\bin\mvn.cmd"
    ) "mvn"
    if (-not $mvn -and -not $SkipJava) {
        throw "mvn not found — install Maven or set PATH (looked in ~/apache-maven-*, scoop, MAVEN_HOME)"
    }

    $cargo = Resolve-Tool @(
        "$env:USERPROFILE\.cargo\bin\cargo.exe"
        "$env:CARGO_HOME\bin\cargo.exe"
    ) "cargo"
    if (-not $cargo -and -not $SkipRust) { throw "cargo not found — install Rust toolchain" }

    return @{ Mvn = $mvn; Cargo = $cargo; JavaHome = $env:JAVA_HOME }
}

# ── banner ───────────────────────────────────────────────────────────────────
_out ""
_out ("{0}{1}  ghidra-mcp{2}  {3}deploy{2}" -f $C.bold, $C.cyan, $C.reset, $C.slate)
_out ("{0}  -------------------------------{1}" -f $C.gray, $C.reset)

try {
    # ── 1. yeet ──────────────────────────────────────────────────────────────
    _phase "yeet locks / processes" {
        $r = Yeet-Locks
        $bits = @()
        if ($r.mcp)    { $bits += "mcp×$($r.mcp)" }
        if ($r.ghidra) { $bits += "ghidra×$($r.ghidra)" }
        if ($r.game)   { $bits += "game×$($r.game)" }
        if ($r.files)  { $bits += "files×$($r.files)" }
        if ($bits.Count -eq 0) { $bits = @("clean") }
        _out ("    {0}{1}{2}" -f $C.slate, ($bits -join "  ·  "), $C.reset)
    }

    # ── 2. env ───────────────────────────────────────────────────────────────
    $script:tools = $null
    _phase "toolchain" {
        $script:tools = Ensure-Toolchain
        $javaLabel = if ($script:tools.JavaHome) { Split-Path $script:tools.JavaHome -Leaf } else { "path-java" }
        $parts = @()
        if (-not $SkipJava) { $parts += "mvn" }
        if (-not $SkipRust) { $parts += "cargo" }
        $parts += $javaLabel
        _out ("    {0}{1}{2}" -f $C.slate, ($parts -join "  ·  "), $C.reset)
        if ($script:tools.Mvn) { _out ("    {0}{1}{2}" -f $C.dim, $script:tools.Mvn, $C.reset) }
    }
    $tools = $script:tools

    # ── ghidra paths ─────────────────────────────────────────────────────────
    $appProps = Join-Path $GhidraHome "Ghidra\application.properties"
    if (-not (Test-Path -LiteralPath $appProps)) {
        throw "not a Ghidra install: $GhidraHome"
    }
    $props = Get-Content -LiteralPath $appProps
    $ver = ($props | Where-Object { $_ -match '^application\.version=' }) -replace '.*=', ''
    $rel = ($props | Where-Object { $_ -match '^application\.release\.name=' }) -replace '.*=', ''
    $verDir = "ghidra_${ver}_${rel}"
    $userExtRoot = Join-Path $env:APPDATA "ghidra\$verDir\Extensions"
    $installExtDir = Join-Path $GhidraHome "Extensions\Ghidra"
    $extTarget = Join-Path $userExtRoot "ghidra-mcp-plugin"

    $rustProfile = if ($Dist) { "dist" } else { "release" }
    $rustOutDir = Join-Path $root "target\$rustProfile"
    $rustExe = Join-Path $rustOutDir "ghidra-mcp.exe"
    _out ("  {0}target{1}  ghidra {2}{3}{1}  ·  rust {2}{4}{1}  ·  {5}" -f `
        $C.slate, $C.reset, $C.white, $ver, $rustProfile, $verDir)

    # ── 3+4. parallel compile (java ∥ rust) ───────────────────────────────────
    # Biggest wall-clock win: mvn and cargo no longer wait on each other.
    _phase "compile  parallel" {
        # free the rust binary image before link (MCP clients hold locks)
        if (-not $SkipRust) {
            Stop-NamedProcesses @('ghidra-mcp') | Out-Null
            if (Test-Path -LiteralPath $rustExe) { Unlock-Path $rustExe 4000 | Out-Null }
            Get-ChildItem $rustOutDir -Filter "ghidra-mcp.exe*" -ErrorAction SilentlyContinue |
                ForEach-Object { Unlock-Path $_.FullName 1500 | Out-Null }
        }

        $env:CARGO_TERM_PROGRESS = "never"
        $env:CARGO_TERM_COLOR = "never"
        $env:CARGO_TERM_VERBOSE = "false"
        $env:CARGO_INCREMENTAL = "1"
        # use all cores; sccache if installed
        if (-not $env:CARGO_BUILD_JOBS) {
            $env:CARGO_BUILD_JOBS = [Environment]::ProcessorCount
        }
        if (-not $env:RUSTC_WRAPPER) {
            $sccache = Get-Command sccache -ErrorAction SilentlyContinue
            if ($sccache) { $env:RUSTC_WRAPPER = $sccache.Source }
        }

        $logDir = Join-Path $env:TEMP "ghidra-mcp-deploy"
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
        $mvnLog = Join-Path $logDir "mvn.log"
        $cargoLog = Join-Path $logDir "cargo.log"

        $procs = [System.Collections.Generic.List[object]]::new()

        if (-not $SkipJava) {
            $mvnArgs = [System.Collections.Generic.List[string]]::new()
            $mvnArgs.Add("-q")
            if ($Clean) { $mvnArgs.Add("clean") }
            $mvnArgs.AddRange([string[]]@("package", "-DskipTests", "--batch-mode", "-T", "1C"))
            _out ("    {0}mvn  {1}{2}" -f $C.slate, (($mvnArgs | Where-Object { $_ -notmatch '^-' }) -join ' '), $C.reset)
            $mvnOut = Join-Path $logDir "mvn.out.log"
            $mvnErr = Join-Path $logDir "mvn.err.log"
            $p = Start-Process -FilePath $tools.Mvn -ArgumentList $mvnArgs.ToArray() `
                -WorkingDirectory (Join-Path $root "plugin") `
                -NoNewWindow -PassThru `
                -RedirectStandardOutput $mvnOut -RedirectStandardError $mvnErr
            $procs.Add([pscustomobject]@{ Name = "mvn"; Proc = $p; Logs = @($mvnOut, $mvnErr) })
        }

        if (-not $SkipRust) {
            $cargoArgs = @("build", "--profile", $rustProfile, "--color", "never")
            # Prefer direct cargo — vcvars only if link.exe missing
            $needVc = -not (Get-Command link.exe -ErrorAction SilentlyContinue)
            $vcvars = $null
            if ($needVc) {
                $vcvars = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat" `
                    -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            _out ("    {0}cargo  profile={1}  jobs={2}{3}" -f $C.slate, $rustProfile, $env:CARGO_BUILD_JOBS, $C.reset)
            if ($vcvars) {
                $argLine = ($cargoArgs -join ' ')
                $cmd = "`"$($vcvars.FullName)`" >nul 2>&1 && `"$($tools.Cargo)`" $argLine >`"$cargoLog`" 2>&1"
                $p = Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", $cmd) `
                    -WorkingDirectory $root -NoNewWindow -PassThru
                $procs.Add([pscustomobject]@{ Name = "cargo"; Proc = $p; Logs = @($cargoLog) })
            } else {
                $cargoOut = Join-Path $logDir "cargo.out.log"
                $cargoErr = Join-Path $logDir "cargo.err.log"
                $p = Start-Process -FilePath $tools.Cargo -ArgumentList $cargoArgs `
                    -WorkingDirectory $root -NoNewWindow -PassThru `
                    -RedirectStandardOutput $cargoOut -RedirectStandardError $cargoErr
                $procs.Add([pscustomobject]@{ Name = "cargo"; Proc = $p; Logs = @($cargoOut, $cargoErr) })
            }
        }

        if ($procs.Count -eq 0) { return }

        # wait all
        $failed = @()
        foreach ($item in $procs) {
            $item.Proc.WaitForExit()
            if ($item.Proc.ExitCode -ne 0) {
                $failed += $item.Name
                _out ("    {0}--- {1} log (tail) ---{2}" -f $C.red, $item.Name, $C.reset)
                foreach ($log in $item.Logs) {
                    if (Test-Path $log) {
                        Get-Content $log -Tail 40 | ForEach-Object { _out ("    {0}" -f $_) }
                    }
                }
            }
        }
        if ($failed.Count -gt 0) { throw "build failed: $($failed -join ', ')" }

        if (-not $SkipJava) {
            $zip = Get-ChildItem (Join-Path $root "plugin\target") -Filter "ghidra-mcp-plugin-*.zip" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if (-not $zip) { throw "plugin zip missing under plugin/target" }
            _out ("    {0}plugin zip ok{1}" -f $C.slate, $C.reset)
        }
        if (-not $SkipRust) {
            if (-not (Test-Path -LiteralPath $rustExe)) { throw "missing $rustExe" }
            $mb = "{0:N1} MB" -f ((Get-Item $rustExe).Length / 1mb)
            _out ("    {0}{1}  {2}{3}" -f $C.slate, $mb, $rustExe.Replace($root + '\', ''), $C.reset)
        }
    }

    # ── 5. install plugin ────────────────────────────────────────────────────
    if (-not $SkipJava) {
        _phase "plugin  install extension" {
            $zip = Get-ChildItem (Join-Path $root "plugin\target") -Filter "ghidra-mcp-plugin-*.zip" |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if (-not $zip) { throw "plugin zip missing under plugin/target" }

            if (-not (Unlock-Path $extTarget 10000)) {
                Stop-GhidraJava | Out-Null
                Start-Sleep -Milliseconds 300
                if (-not (Unlock-Path $extTarget 8000)) {
                    throw "extension still locked: $extTarget"
                }
            }

            New-Item -ItemType Directory -Force -Path $userExtRoot | Out-Null
            Expand-Archive -Path $zip.FullName -DestinationPath $userExtRoot -Force

            $extProps = Join-Path $extTarget "extension.properties"
            (Get-Content -LiteralPath $extProps) `
                -replace '^version=.*', "version=$ver" `
                -replace '^ghidraVersion=.*', "ghidraVersion=$ver" |
                Set-Content -LiteralPath $extProps -Encoding utf8

            if (Test-Path -LiteralPath $installExtDir) {
                Get-ChildItem $installExtDir -Filter "ghidra-mcp-plugin-*.zip" -ErrorAction SilentlyContinue |
                    Remove-Item -Force -ErrorAction SilentlyContinue
                Copy-Item -Force $zip.FullName $installExtDir
            }

            $jar = Join-Path $extTarget "lib\ghidra-mcp-plugin.jar"
            $kb = if (Test-Path $jar) { [int]((Get-Item $jar).Length / 1kb) } else { 0 }
            _out ("    {0}{1} kb → Extensions/{2}{3}" -f $C.slate, $kb, (Split-Path $extTarget -Leaf), $C.reset)
        }
    }

    # ── 5. relaunch ──────────────────────────────────────────────────────────
    if ($Relaunch) {
        _phase "relaunch ghidra" {
            $launcher = Join-Path $GhidraHome "ghidraRun.bat"
            if (-not (Test-Path -LiteralPath $launcher)) { throw "missing $launcher" }
            # fire-and-forget via cmd start so we never inherit ghidra's lifetime
            Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", "start", '""', "/B", $launcher) -WindowStyle Hidden | Out-Null
        }
    }

    # ── summary ──────────────────────────────────────────────────────────────
    $script:t0.Stop()
    _out ("{0}  -------------------------------{1}" -f $C.gray, $C.reset)
    foreach ($ph in $script:phases) {
        $mark = if ($ph.Ok) { "{0}ok{1}" -f $C.mint, $C.reset } else { "{0}!!{1}" -f $C.red, $C.reset }
        _out ("  {0}  {1,-28} {2}{3,8}{4}" -f $mark, $ph.Name, $C.gray, (_ms $ph.Ms), $C.reset)
    }
    $total = $script:t0.ElapsedMilliseconds
    $color = if ($total -lt 15000) { $C.mint } elseif ($total -lt 60000) { $C.amber } else { $C.pink }
    _out ""
    _out ("  {0}{1}done{2}  {3}{4}{2}  {5}ghidra {6}{2}" -f $C.bold, $C.mint, $C.reset, $color, (_ms $total), $C.slate, $ver)
    _out ""
    if (-not $LogFile) { _out "DEPLOY_EXIT=0" }
    exit 0
}
catch {
    $script:t0.Stop()
    _out ""
    _out ("  {0}{1}failed{2}  {3}{4:N0}ms{2}" -f $C.bold, $C.red, $C.reset, $C.gray, $script:t0.ElapsedMilliseconds)
    _out ("  {0}{1}{2}" -f $C.red, $_.Exception.Message, $C.reset)
    _out ""
    if (-not $LogFile) { _out "DEPLOY_EXIT=1" }
    exit 1
}
