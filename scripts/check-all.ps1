# Run exactly what CI runs, locally.
#
# Why this exists: CI sets RUSTFLAGS=-D warnings. Verifying locally without that flag let six
# pushes in a row pass here and fail there. This script mirrors the workflow so the two cannot
# disagree again.
#
#   pwsh -File scripts/check-all.ps1            # everything
#   pwsh -File scripts/check-all.ps1 -Quick     # skip MSRV and the full feature matrix
param([switch]$Quick)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

# CI's settings, applied to this process only.
$env:RUSTFLAGS = '-D warnings'
$env:RUSTDOCFLAGS = '-D warnings'
$env:CARGO_TERM_COLOR = 'always'

$failures = [System.Collections.Generic.List[string]]::new()

function Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ""
    Write-Host "== $Name ==" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0) {
        Write-Host "   FAILED: $Name" -ForegroundColor Red
        $failures.Add($Name)
    } else {
        Write-Host "   ok" -ForegroundColor Green
    }
}

$matrix = @(
    @{ Features = ''; Label = 'default' }
    @{ Features = 'aes-crypto'; Label = 'aes-crypto' }
    @{ Features = 'lzma'; Label = 'lzma' }
    @{ Features = 'deflate64'; Label = 'deflate64' }
    @{ Features = 'ppmd'; Label = 'ppmd' }
    @{ Features = 'zstd'; Label = 'zstd' }
    @{ Features = 'bzip2'; Label = 'bzip2' }
    @{ Features = 'deflate-zlib-rs'; Label = 'deflate-zlib-rs' }
    @{ Features = 'zstd,bzip2,deflate-zlib-rs,aes-crypto'; Label = 'ci-matrix-combined' }
)
if (-not $Quick) {
    $matrix += @{ Features = 'zstd,bzip2,lzma,deflate64,ppmd,deflate-zlib-rs,aes-crypto'; Label = 'all-features' }
}

# The matrix job: every feature combination must compile and pass *with warnings denied*.
foreach ($case in $matrix) {
    $features = $case.Features
    $label = $case.Label
    Step "test [$label]" {
        if ([string]::IsNullOrEmpty($features)) {
            & cargo test --quiet
        } else {
            & cargo test --quiet --features $features
        }
    }
}

Step 'doctests' { & cargo test --doc --quiet --all-features }
Step 'clippy' { & cargo clippy --all-targets --all-features --quiet -- -D warnings }
Step 'rustfmt' { & cargo fmt --all -- --check }
Step 'docs' { & cargo doc --no-deps --all-features --quiet }

# Each of these was a real CI failure at least once.
Step 'no unsafe in src/' {
    $hits = Select-String -Path (Join-Path $root 'src/*.rs'), (Join-Path $root 'src/**/*.rs') `
        -Pattern '\bunsafe\s*(fn|impl|trait|extern|\{)' -ErrorAction SilentlyContinue
    if ($hits) {
        $hits | ForEach-Object { Write-Host "  $($_.Filename):$($_.LineNumber)" }
        throw 'unsafe found'
    }
}
Step 'README examples' { python scripts/check-readme-examples.py }
Step 'dependency budget (default build stays at 3)' {
    $count = (& cargo tree --edges normal --depth 1 2>$null | Select-Object -Skip 1 | Measure-Object).Count
    Write-Host "  direct dependencies: $count"
    if ($count -gt 3) { throw "default build grew to $count dependencies" }
}

if (-not $Quick) {
    Step 'MSRV rows' { & powershell -NoProfile -ExecutionPolicy Bypass -File scripts/msrv-check.ps1 }
    Step 'package contents' {
        $out = & cargo package --list --offline 2>&1 | Out-String
        $leaks = $out -split "`n" | Where-Object { $_ -match 'ANALYSIS|/zz_|CODE_REVIEW' }
        if ($leaks) { $leaks | ForEach-Object { Write-Host "  LEAK: $_" }; throw 'leaked files' }
    }
}

$env:RUSTFLAGS = ''
$env:RUSTDOCFLAGS = ''
Pop-Location

Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host ("FAILED ({0}):" -f $failures.Count) -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host 'All checks passed.' -ForegroundColor Green
exit 0
