[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$artifactDirectory = Join-Path $projectRoot 'artifacts'
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

if (-not (Test-Path -LiteralPath $compiler)) {
    throw "The .NET Framework 4.8 C# compiler was not found at $compiler"
}

New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
$coreSources = @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src\Core') -Filter '*.cs' -File | Sort-Object Name | ForEach-Object FullName)
$appSources = @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src\App') -Filter '*.cs' -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object FullName)
$references = @(
    '/reference:System.dll',
    '/reference:System.Core.dll',
    '/reference:System.Security.dll',
    '/reference:System.Runtime.Serialization.dll',
    '/reference:System.Xml.dll',
    '/reference:System.Windows.Forms.dll',
    '/reference:System.Drawing.dll'
)
$common = @('/nologo', '/warn:4', '/checked+', '/codepage:65001', '/langversion:5') + $references

if ($Configuration -eq 'Release') {
    $common += @('/optimize+', '/debug:pdbonly')
} else {
    $common += @('/optimize-', '/debug:full', '/define:DEBUG')
}

$iconBuilderSource = Join-Path $projectRoot 'tools\IconBuilder.cs'
$iconBuilderOutput = Join-Path $artifactDirectory 'CodexGuard.IconBuilder.exe'
$iconOutput = Join-Path $artifactDirectory 'CodexGuard.ico'
$iconPreview = Join-Path $artifactDirectory 'CodexGuard-icon.png'
& $compiler /nologo /target:exe "/out:$iconBuilderOutput" /reference:System.dll /reference:System.Drawing.dll $iconBuilderSource
if ($LASTEXITCODE -ne 0) { throw "Codex Guard icon compilation failed with exit code $LASTEXITCODE" }
& $iconBuilderOutput $iconOutput $iconPreview
if ($LASTEXITCODE -ne 0) { throw "Codex Guard icon generation failed with exit code $LASTEXITCODE" }

if ($appSources.Count -gt 0) {
    $applicationOutput = Join-Path $artifactDirectory 'CodexGuard.exe'
    $manifest = Join-Path $projectRoot 'src\App\app.manifest'
    $appArguments = $common + @('/target:winexe', "/out:$applicationOutput", "/win32manifest:$manifest", "/win32icon:$iconOutput") + $coreSources + $appSources
    & $compiler @appArguments
    if ($LASTEXITCODE -ne 0) { throw "Codex Guard application compilation failed with exit code $LASTEXITCODE" }
}

$reviewerSource = Join-Path $projectRoot 'reviewer\Program.cs'
if (Test-Path -LiteralPath $reviewerSource) {
    $reviewerOutput = Join-Path $artifactDirectory 'CodexGuard.ReadOnlyVerifier.exe'
    $reviewerArguments = $common + @('/target:winexe', "/out:$reviewerOutput") + @($reviewerSource)
    & $compiler @reviewerArguments
    if ($LASTEXITCODE -ne 0) { throw "Codex Guard independent verifier compilation failed with exit code $LASTEXITCODE" }
}

$acceptanceSource = Join-Path $projectRoot 'acceptance\Program.cs'
if (Test-Path -LiteralPath $acceptanceSource) {
    $acceptanceOutput = Join-Path $artifactDirectory 'CodexGuard.AcceptanceProbe.exe'
    $acceptanceArguments = $common + @('/target:winexe', "/out:$acceptanceOutput") + @($acceptanceSource)
    & $compiler @acceptanceArguments
    if ($LASTEXITCODE -ne 0) { throw "Codex Guard acceptance probe compilation failed with exit code $LASTEXITCODE" }
}

$testSource = Join-Path $projectRoot 'tests\TestRunner.cs'
$testOutput = Join-Path $artifactDirectory 'CodexGuard.Tests.exe'
$testArguments = $common + @('/target:exe', '/main:TestRunner', "/out:$testOutput") + $coreSources + @($acceptanceSource) + $testSource
& $compiler @testArguments
if ($LASTEXITCODE -ne 0) { throw "Codex Guard test compilation failed with exit code $LASTEXITCODE" }

$uiRenderSource = Join-Path $projectRoot 'tests\UiRender.cs'
$uiRenderOutput = Join-Path $artifactDirectory 'CodexGuard.UiRender.exe'
$uiRenderArguments = $common + @('/target:winexe', '/main:CodexGuard.Tests.UiRender', "/out:$uiRenderOutput") + $coreSources + $appSources + @($reviewerSource, $acceptanceSource) + $uiRenderSource
& $compiler @uiRenderArguments
if ($LASTEXITCODE -ne 0) { throw "Codex Guard UI renderer compilation failed with exit code $LASTEXITCODE" }

Write-Host "Built Codex Guard ($Configuration) in $artifactDirectory"
