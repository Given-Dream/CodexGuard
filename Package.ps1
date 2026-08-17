[CmdletBinding()]
param(
    [string]$Label = 'preview'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$artifacts = Join-Path $projectRoot 'artifacts'
$releaseRoot = Join-Path $projectRoot 'release'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$version = '0.6.7'
$stage = Join-Path $artifacts ("package-{0}-{1}" -f $version, $timestamp)
$docsStage = Join-Path $stage 'docs'
$reviewerStage = Join-Path $stage 'reviewer-source'
$acceptanceStage = Join-Path $stage 'acceptance-source'

& (Join-Path $projectRoot 'Build.ps1') -Configuration Release
if ($LASTEXITCODE -ne 0) { throw "Release build failed with exit code $LASTEXITCODE" }
& (Join-Path $artifacts 'CodexGuard.Tests.exe')
if ($LASTEXITCODE -ne 0) { throw "Release tests failed with exit code $LASTEXITCODE" }

New-Item -ItemType Directory -Path $docsStage -Force | Out-Null
New-Item -ItemType Directory -Path $reviewerStage -Force | Out-Null
New-Item -ItemType Directory -Path $acceptanceStage -Force | Out-Null
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $artifacts 'CodexGuard.exe') -Destination $stage
Copy-Item -LiteralPath (Join-Path $artifacts 'CodexGuard.ReadOnlyVerifier.exe') -Destination $stage
Copy-Item -LiteralPath (Join-Path $artifacts 'CodexGuard.AcceptanceProbe.exe') -Destination $stage
Copy-Item -LiteralPath (Join-Path $artifacts 'CodexGuard-icon.png') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'reviewer\Program.cs') -Destination $reviewerStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'acceptance\Program.cs') -Destination $acceptanceStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\SECURITY.md') -Destination $docsStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\MIGRATION.md') -Destination $docsStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\OPERATIONS.md') -Destination $docsStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\TESTING.md') -Destination $docsStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\MANUAL_REVIEW.md') -Destination $docsStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\RECORD_SYNC.md') -Destination $docsStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\SOFTWARE_MAPPING.md') -Destination $docsStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\OFFLINE_REUSE.md') -Destination $docsStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\USER_MANUAL.md') -Destination $docsStage
@(
    'Codex Guard - Start Here',
    '',
    '1. Keep all three EXE files and SHA256SUMS.txt in this directory.',
    '2. Double-click CodexGuard.exe; do not copy that file out by itself.',
    '3. For first deployment, choose Install / Repair from the admin Windows session.',
    '4. This preview is unsigned, so Windows may show Unknown publisher.',
    '',
    'The GitHub Release also provides a single-file CodexGuard.exe that contains and verifies this complete package.'
) | Set-Content -LiteralPath (Join-Path $stage 'START-HERE.txt') -Encoding UTF8

$binary = Join-Path $stage 'CodexGuard.exe'
$hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
$reviewerBinary = Join-Path $stage 'CodexGuard.ReadOnlyVerifier.exe'
$reviewerHash = (Get-FileHash -LiteralPath $reviewerBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$reviewerSourceFile = Join-Path $reviewerStage 'Program.cs'
$reviewerSourceHash = (Get-FileHash -LiteralPath $reviewerSourceFile -Algorithm SHA256).Hash.ToLowerInvariant()
$acceptanceBinary = Join-Path $stage 'CodexGuard.AcceptanceProbe.exe'
$acceptanceHash = (Get-FileHash -LiteralPath $acceptanceBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$acceptanceSourceFile = Join-Path $acceptanceStage 'Program.cs'
$acceptanceSourceHash = (Get-FileHash -LiteralPath $acceptanceSourceFile -Algorithm SHA256).Hash.ToLowerInvariant()
@(
    "$hash  CodexGuard.exe",
    "$reviewerHash  CodexGuard.ReadOnlyVerifier.exe",
    "$reviewerSourceHash  reviewer-source/Program.cs",
    "$acceptanceHash  CodexGuard.AcceptanceProbe.exe",
    "$acceptanceSourceHash  acceptance-source/Program.cs",
    '',
    'This preview binary is not Authenticode-signed. Verify this hash before first launch.'
) | Set-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Encoding ASCII
@(
    "Codex Guard $version-$Label",
    "Built: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')",
    'Runtime: Windows 10/11 with .NET Framework 4.8',
    'Status: unsigned security architecture preview'
) | Set-Content -LiteralPath (Join-Path $stage 'VERSION.txt') -Encoding UTF8

$zip = Join-Path $releaseRoot ("CodexGuard-{0}-{1}-{2}.zip" -f $version, $Label, $timestamp)
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
$portableZip = Join-Path $releaseRoot ("CodexGuard-{0}-{1}-portable.zip" -f $version, $Label)
Copy-Item -LiteralPath $zip -Destination $portableZip -Force
$expanded = Join-Path $releaseRoot ("CodexGuard-{0}-{1}-{2}" -f $version, $Label, $timestamp)
Copy-Item -LiteralPath $stage -Destination $expanded -Recurse
$zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
$portableZipHash = (Get-FileHash -LiteralPath $portableZip -Algorithm SHA256).Hash.ToLowerInvariant()

$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$launcherSource = Join-Path $projectRoot 'tools\ReleaseLauncher.cs'
$launcher = Join-Path $releaseRoot 'CodexGuard.exe'
$launcherArguments = @(
    '/nologo',
    '/warn:4',
    '/checked+',
    '/codepage:65001',
    '/langversion:5',
    '/optimize+',
    '/target:winexe',
    "/out:$launcher",
    "/win32manifest:$(Join-Path $projectRoot 'src\App\app.manifest')",
    "/win32icon:$(Join-Path $artifacts 'CodexGuard.ico')",
    '/reference:System.dll',
    '/reference:System.Core.dll',
    '/reference:System.Security.dll',
    '/reference:System.Windows.Forms.dll',
    '/reference:System.IO.Compression.dll',
    '/reference:System.IO.Compression.FileSystem.dll',
    "/resource:$portableZip,CodexGuard.Payload",
    $launcherSource
)
& $compiler @launcherArguments
if ($LASTEXITCODE -ne 0) { throw "Direct-use launcher compilation failed with exit code $LASTEXITCODE" }

$validationRoot = Join-Path $artifacts ("release-self-test-{0}" -f $timestamp)
& $launcher '--self-test' $validationRoot
if ($LASTEXITCODE -ne 0) { throw "Direct-use launcher self-test failed with exit code $LASTEXITCODE" }

$launcherHash = (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash.ToLowerInvariant()
@(
    "$launcherHash  CodexGuard.exe",
    "$portableZipHash  $(Split-Path -Leaf $portableZip)",
    '',
    'CodexGuard.exe is the complete self-extracting release launcher.',
    'The portable ZIP contains the main app and both required companion executables.',
    'This preview is not Authenticode-signed.'
) | Set-Content -LiteralPath (Join-Path $releaseRoot 'SHA256SUMS.txt') -Encoding ASCII

Write-Host "Package: $zip"
Write-Host "Portable package: $portableZip"
Write-Host "Direct-use EXE: $launcher"
Write-Host "Expanded: $expanded"
Write-Host "ZIP SHA256: $zipHash"
Write-Host "Portable ZIP SHA256: $portableZipHash"
Write-Host "Direct-use EXE SHA256: $launcherHash"
Write-Host "CodexGuard.exe SHA256: $hash"
