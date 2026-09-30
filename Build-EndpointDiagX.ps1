<#
================================================================================
 Build-EndpointDiagX.ps1
 --------------------------------------------------------------------------
 Compiles EndpointDiagX.ps1 into a Windows executable using PS2EXE, then stages
 the runtime files beside it.

 IMPORTANT - the EXE is NOT standalone by design:
   EndpointDiagX.exe     <- compiled front-end (the UI)
   DiagEngine.ps1        <- stays a real .ps1, dot-sourced by the EXE and by
                            every ping / lookup / trace / port card runspace
   KnowledgeBase.json    <- resolution rules, edit without recompiling

 USAGE
   .\Build-EndpointDiagX.ps1
   .\Build-EndpointDiagX.ps1 -IconFile .\dx.ico -Version '4.0.0.0'
   .\Build-EndpointDiagX.ps1 -SignThumbprint 'A1B2C3...'

 REQUIREMENTS
   Windows PowerShell 5.1 (PS2EXE targets Windows PowerShell, not PS7)
================================================================================
#>
[CmdletBinding()]
param(
    [string]$SourceFolder   = $PSScriptRoot,
    [string]$OutputFolder   = (Join-Path $PSScriptRoot 'build'),
    [string]$ExeName        = 'Sysadmin.exe',
    [string]$IconFile       = '',
    [string]$Version        = '4.0.0.0',
    [string]$Company        = 'Vantiva',
    [string]$SignThumbprint = '',
    [string]$TimestampUrl   = 'http://timestamp.digicert.com',
    [switch]$NoAdminManifest,
    [switch]$KeepConsole
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$T) Write-Host "`n=== $T ===" -ForegroundColor Cyan }
function Write-Ok   { param([string]$T) Write-Host "  [ok]   $T" -ForegroundColor Green }
function Write-Warn { param([string]$T) Write-Host "  [warn] $T" -ForegroundColor Yellow }
function Write-Err  { param([string]$T) Write-Host "  [ERR]  $T" -ForegroundColor Red }

Write-Step 'Environment'
if ($PSVersionTable.PSVersion.Major -ge 6) {
    Write-Warn "Running on PowerShell $($PSVersionTable.PSVersion). PS2EXE targets Windows PowerShell 5.1."
    Write-Warn 'If compilation fails, re-run from Windows PowerShell (powershell.exe).'
} else {
    Write-Ok "Windows PowerShell $($PSVersionTable.PSVersion)"
}

$required = @('EndpointDiagX.ps1', 'DiagEngine.ps1', 'KnowledgeBase.json')
$missing  = @()
foreach ($f in $required) { if (-not (Test-Path (Join-Path $SourceFolder $f))) { $missing += $f } }
if ($missing.Count -gt 0) {
    Write-Err "Missing source file(s) in '$SourceFolder': $($missing -join ', ')"
    return
}
Write-Ok "All source files present in $SourceFolder"

Write-Step 'PS2EXE module'
$mod = Get-Module -Name ps2exe -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
if (-not $mod) {
    Write-Warn 'ps2exe not installed - installing from PowerShell Gallery for the current user...'
    try {
        Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
        $mod = Get-Module -Name ps2exe -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    }
    catch {
        Write-Err "Could not install ps2exe: $($_.Exception.Message)"
        Write-Host '  Install manually with:  Install-Module ps2exe -Scope CurrentUser' -ForegroundColor Gray
        return
    }
}
Import-Module ps2exe -Force
Write-Ok "ps2exe $($mod.Version)"

Write-Step 'Source encoding'
# PS2EXE requires UTF8 or UTF16 input. UTF8 without a BOM is sometimes misread
# as ANSI, so stage a UTF8-with-BOM copy (originals untouched).
$stage = Join-Path $env:TEMP ("Sysadmin-build-{0}" -f (Get-Date -Format 'yyyyMMddHHmmss'))
New-Item -Path $stage -ItemType Directory -Force | Out-Null
$srcMain   = Join-Path $SourceFolder 'EndpointDiagX.ps1'
$stageMain = Join-Path $stage 'EndpointDiagX.ps1'
$content   = Get-Content -Path $srcMain -Raw -Encoding UTF8
[System.IO.File]::WriteAllText($stageMain, $content, (New-Object System.Text.UTF8Encoding($true)))
Write-Ok "Staged UTF8-BOM copy ($([math]::Round((Get-Item $stageMain).Length / 1KB)) KB)"

Write-Step 'Compile'
if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$exePath = Join-Path $OutputFolder $ExeName

$ps2exeArgs = @{
    inputFile   = $stageMain
    outputFile  = $exePath
    x64         = $true      # match a 64-bit OS; avoids registry redirection
    STA         = $true      # MANDATORY - WPF will not start in MTA
    noConsole   = $true      # hide the console behind the WPF UI
    DPIAware    = $true      # correct scaling on high-DPI displays
    title       = 'Sys@dmin'
    description = 'Windows Endpoint Diagnostics Console'
    company     = $Company
    product     = 'Sys@dmin'
    copyright   = "(c) $((Get-Date).Year) $Company"
    version     = $Version
}
if ($KeepConsole)          { $ps2exeArgs.noConsole = $false }
if (-not $NoAdminManifest) { $ps2exeArgs.requireAdmin = $true }
if ($IconFile -and (Test-Path $IconFile)) { $ps2exeArgs.iconFile = (Resolve-Path $IconFile).Path }

Write-Host "  Options: STA, noConsole=$($ps2exeArgs.noConsole), requireAdmin=$(-not $NoAdminManifest), x64, DPIAware" -ForegroundColor Gray
try { Invoke-ps2exe @ps2exeArgs }
catch {
    Write-Err "Compilation failed: $($_.Exception.Message)"
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    return
}
if (-not (Test-Path $exePath)) {
    Write-Err 'PS2EXE reported success but no executable was produced.'
    Write-Warn 'This is almost always antivirus deleting the output. See the notes at the end.'
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    return
}
Write-Ok "Built $exePath ($([math]::Round((Get-Item $exePath).Length / 1KB)) KB)"

Write-Step 'Stage runtime files'
foreach ($f in @('DiagEngine.ps1', 'KnowledgeBase.json')) {
    Copy-Item -Path (Join-Path $SourceFolder $f) -Destination (Join-Path $OutputFolder $f) -Force
    Write-Ok "Copied $f"
}
if (Test-Path (Join-Path $SourceFolder 'README.md')) {
    Copy-Item -Path (Join-Path $SourceFolder 'README.md') -Destination $OutputFolder -Force
    Write-Ok 'Copied README.md'
}

Write-Step 'Code signing'
if ($SignThumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $SignThumbprint -and $_.HasPrivateKey } |
            Select-Object -First 1
    if (-not $cert) {
        Write-Err "No code-signing certificate with thumbprint $SignThumbprint (and a private key) was found."
    } else {
        try {
            $r = Set-AuthenticodeSignature -FilePath $exePath -Certificate $cert `
                     -TimestampServer $TimestampUrl -HashAlgorithm SHA256
            if ($r.Status -eq 'Valid') { Write-Ok "Signed by $($cert.Subject) - status Valid" }
            else { Write-Warn "Signature status: $($r.Status) - $($r.StatusMessage)" }
        }
        catch { Write-Err "Signing failed: $($_.Exception.Message)" }
    }
} else {
    Write-Warn 'Not signed. Unsigned PS2EXE output is very frequently quarantined by AV/EDR.'
    Write-Host '  Re-run with -SignThumbprint <thumbprint> once you have a code-signing cert.' -ForegroundColor Gray
}

Write-Step 'Result'
Get-ChildItem $OutputFolder | Select-Object Name, @{n='Size';e={'{0,8:N0} KB' -f ($_.Length/1KB)}}, LastWriteTime |
    Format-Table -AutoSize | Out-String | Write-Host
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue

Write-Host 'Distribute the ENTIRE output folder - the EXE needs DiagEngine.ps1 and' -ForegroundColor White
Write-Host 'KnowledgeBase.json beside it. Test by running the EXE from that folder.' -ForegroundColor White
Write-Host ''
Write-Host 'If the EXE vanishes after building, your antivirus removed it. Add a build' -ForegroundColor Yellow
Write-Host 'folder exclusion, sign the binary, or submit it as a false positive.' -ForegroundColor Yellow
