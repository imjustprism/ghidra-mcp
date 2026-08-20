#Requires -Version 7
<#
.SYNOPSIS
  Build and install the Ghidra plugin using javac only — no Maven required.

.DESCRIPTION
  deploy.ps1 drives Maven, which is the right tool when it is installed. This is
  the fallback for a machine that has a JDK and the staged jars in plugin/lib
  but no Maven: it compiles, jars, zips, and (with -Install) drops the jar into
  Ghidra's extracted extension directory.

  Produces exactly what the Maven build does apart from the META-INF/maven
  metadata, which Ghidra ignores.

.EXAMPLE
  .\plugin\build-javac.ps1                     # compile + jar + zip
  .\plugin\build-javac.ps1 -Install            # ...and install into Ghidra
  .\plugin\build-javac.ps1 -Install -Restart   # ...and relaunch Ghidra
#>
param(
    [string]$GhidraUserDir = "",
    [switch]$Install,
    [switch]$Restart,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$plugin = Join-Path $root "plugin"

function Say([string]$m) { if (-not $Quiet) { Write-Host $m } }
function Die([string]$m) { Write-Host "fail: $m" -ForegroundColor Red; exit 1 }

# --- prerequisites ---------------------------------------------------------

$javac = (Get-Command javac -ErrorAction SilentlyContinue)?.Source
if (-not $javac) { Die "javac not on PATH (install a JDK 21+ / Temurin)" }

$libs = Get-ChildItem -Path (Join-Path $plugin "lib") -Filter *.jar -ErrorAction SilentlyContinue
if (-not $libs) {
    Die "no jars in plugin/lib — run plugin\setup-libs.ps1 -GhidraHome <path> first"
}
Say "javac: $javac"
Say "jars:  $($libs.Count) staged"

$version = (Select-String -Path (Join-Path $plugin "extension.properties") `
    -Pattern '^ghidraVersion=(.+)$').Matches.Groups[1].Value
Say "target ghidra: $version"

# --- compile ---------------------------------------------------------------

$build = Join-Path ([System.IO.Path]::GetTempPath()) ("ghidra-mcp-build-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$classes = Join-Path $build "classes"
New-Item -ItemType Directory -Force -Path $classes | Out-Null

$sources = Get-ChildItem -Path (Join-Path $plugin "src\main\java") -Filter *.java -Recurse |
    Select-Object -ExpandProperty FullName
$srcList = Join-Path $build "sources.txt"
$sources | Set-Content -Path $srcList -Encoding utf8
Say "compiling $($sources.Count) source files..."

$cp = ($libs | Select-Object -ExpandProperty FullName) -join ";"
& $javac --release 21 -nowarn -cp $cp -d $classes "@$srcList"
if ($LASTEXITCODE -ne 0) { Die "javac failed" }

# The pom excludes App from the artifact; match that.
Remove-Item (Join-Path $classes "io\github\imjustprism\ghidra\mcp\App.class") `
    -ErrorAction SilentlyContinue

# Non-manifest resources ship alongside the classes, as maven-resources does.
$resources = Join-Path $plugin "src\main\resources"
if (Test-Path $resources) {
    Get-ChildItem -Path $resources -Recurse -File |
        Where-Object { $_.FullName -notmatch 'META-INF\\MANIFEST\.MF$' } |
        ForEach-Object {
            $rel = $_.FullName.Substring($resources.Length).TrimStart('\')
            $dest = Join-Path $classes $rel
            New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
            Copy-Item $_.FullName $dest -Force
        }
}

# --- jar -------------------------------------------------------------------

$jarTool = (Get-Command jar -ErrorAction SilentlyContinue)?.Source
if (-not $jarTool) { Die "jar not on PATH (it ships with the JDK)" }

$jarPath = Join-Path $build "ghidra-mcp-plugin.jar"
$manifest = Join-Path $resources "META-INF\MANIFEST.MF"
& $jarTool --create --file $jarPath --manifest $manifest -C $classes .
if ($LASTEXITCODE -ne 0) { Die "jar failed" }
Say "jar:   $([math]::Round((Get-Item $jarPath).Length / 1KB)) KB"

# --- zip (Ghidra extension layout) -----------------------------------------

$stage = Join-Path $build "ghidra-mcp-plugin"
New-Item -ItemType Directory -Force -Path (Join-Path $stage "lib") | Out-Null
Copy-Item $jarPath (Join-Path $stage "lib\ghidra-mcp-plugin.jar")
Copy-Item (Join-Path $plugin "extension.properties") $stage
Copy-Item (Join-Path $plugin "Module.manifest") $stage

$dist = Join-Path $plugin "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$zipPath = Join-Path $dist "ghidra-mcp-plugin-1.0-ghidra-$version.zip"
Remove-Item $zipPath -ErrorAction SilentlyContinue
Compress-Archive -Path $stage -DestinationPath $zipPath -CompressionLevel Optimal
Copy-Item $jarPath (Join-Path $dist "ghidra-mcp-plugin.jar") -Force
Say "zip:   $zipPath"

# --- install ---------------------------------------------------------------

if ($Install) {
    if (-not $GhidraUserDir) {
        $GhidraUserDir = Join-Path $env:APPDATA "ghidra\ghidra_${version}_PUBLIC"
    }
    $extDir = Join-Path $GhidraUserDir "Extensions\ghidra-mcp-plugin"
    if (-not (Test-Path $extDir)) {
        Write-Host "warn: $extDir not found — install the extension once via" -ForegroundColor Yellow
        Write-Host "      Ghidra > File > Install Extensions using $zipPath" -ForegroundColor Yellow
    } else {
        # Process-name matching is unreliable here: Ghidra runs as javaw/java, but
        # so does every language server and build daemon on the machine. Ask the
        # only question that matters instead — can we open the target for writing?
        $target = Join-Path $extDir "lib\ghidra-mcp-plugin.jar"
        $locked = $false
        if (Test-Path $target) {
            try {
                $fs = [System.IO.File]::Open($target, 'Open', 'Write', 'None')
                $fs.Close()
            } catch {
                $locked = $true
            }
        }
        Copy-Item $jarPath $target -Force
        Say "installed: $target"
        if ($locked) {
            # The file swap still succeeds on Windows; the point is that the JVM
            # already has the old classes loaded and will not reread them.
            Write-Host "note: Ghidra has the jar open — the new classes load on restart." `
                -ForegroundColor Yellow
        } else {
            Say "           (nothing held it open — loads on next Ghidra start)"
        }
    }

    # Keep the installable zip in the Ghidra install dir in step with the build,
    # so a later reinstall through the GUI picks up this same artifact.
    $ghidraHome = $env:GHIDRA_HOME
    if (-not $ghidraHome) {
        $candidates = @(
            (Join-Path $env:USERPROFILE "scoop\apps\ghidra\current"),
            "C:\ghidra_${version}_PUBLIC",
            "D:\ghidra_${version}_PUBLIC"
        )
        $ghidraHome = $candidates |
            Where-Object { Test-Path (Join-Path $_ "Extensions\Ghidra") } |
            Select-Object -First 1
    }
    if ($ghidraHome) {
        $installZip = Join-Path $ghidraHome "Extensions\Ghidra\ghidra-mcp-plugin-1.0.zip"
        Copy-Item $zipPath $installZip -Force
        Say "refreshed:  $installZip"
    } else {
        Say "note:  set GHIDRA_HOME to also refresh the installable zip in the Ghidra install dir"
    }
}

Remove-Item $build -Recurse -Force -ErrorAction SilentlyContinue
Say ""
Say "done. Restart Ghidra to load the new classes."
