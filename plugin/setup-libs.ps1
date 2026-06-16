param(
    [string]$GhidraHome = "$env:USERPROFILE\scoop\apps\ghidra\current"
)

$ErrorActionPreference = "Stop"

# Required jars (hard-fail if missing).
$requiredJars = @(
    "Ghidra\Features\Base\lib\Base.jar",
    "Ghidra\Features\Decompiler\lib\Decompiler.jar",
    "Ghidra\Framework\Docking\lib\Docking.jar",
    "Ghidra\Framework\Generic\lib\Generic.jar",
    "Ghidra\Framework\Project\lib\Project.jar",
    "Ghidra\Framework\SoftwareModeling\lib\SoftwareModeling.jar",
    "Ghidra\Framework\Utility\lib\Utility.jar",
    "Ghidra\Framework\Gui\lib\Gui.jar",
    "Ghidra\Framework\Emulation\lib\Emulation.jar"
)

$optionalJars = @(
    "Ghidra\Debug\Debugger\lib\Debugger.jar",
    "Ghidra\Debug\Debugger-api\lib\Debugger-api.jar",
    "Ghidra\Debug\Debugger-rmi-trace\lib\Debugger-rmi-trace.jar",
    "Ghidra\Debug\Framework-TraceModeling\lib\Framework-TraceModeling.jar",
    "Ghidra\Debug\Debugger-agent-dbgeng\lib\Debugger-agent-dbgeng.jar",
    "Ghidra\Framework\Pty\lib\jna-5.14.0.jar",
    "Ghidra\Framework\Pty\lib\jna-platform-5.14.0.jar"
)

$dest = Join-Path $PSScriptRoot "lib"
New-Item -ItemType Directory -Force -Path $dest | Out-Null

foreach ($rel in $requiredJars) {
    $src = Join-Path $GhidraHome $rel
    if (-not (Test-Path $src)) {
        Write-Error "Missing required jar: $src"
    }
    Copy-Item -Force $src (Join-Path $dest (Split-Path $rel -Leaf))
    Write-Host "  $(Split-Path $rel -Leaf)"
}

$stagedOptional = 0
foreach ($rel in $optionalJars) {
    $src = Join-Path $GhidraHome $rel
    if (Test-Path $src) {
        Copy-Item -Force $src (Join-Path $dest (Split-Path $rel -Leaf))
        Write-Host "  $(Split-Path $rel -Leaf) (optional)"
        $stagedOptional++
    } else {
        Write-Warning "Optional jar not present (Debugger endpoints will be stubbed): $src"
    }
}

Write-Host "Staged $($requiredJars.Count) required + $stagedOptional optional jars into $dest"
