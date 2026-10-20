# Verify the crate's stated MSRV is real, on every toolchain it claims.
#
# The README promises 1.70 for the default build. That promise silently broke once, when a
# dependency raised its own MSRV during a routine `cargo add`; this script exists so it cannot
# happen quietly again.
#
# Requires rustup toolchains 1.70.0, 1.85.1 and 1.89.0.
#   rustup toolchain install 1.70.0 1.85.1 1.89.0
#
# Exit code is non-zero if any claimed floor stops building.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("zipcore-msrv-" + [guid]::NewGuid().ToString('N'))

# The lockfile is deliberately excluded: the oldest Cargo cannot parse a v4 lock, and the point of
# this check is that *dependency resolution* also works on the old toolchain.
$copy = Join-Path $tmp 'crate'
New-Item -ItemType Directory -Force -Path $copy | Out-Null
robocopy $root $copy /E /XD target review .git .github /XF Cargo.lock /NFL /NDL /NJH /NJS /NC /NS | Out-Null

$cases = @(
  @{ Toolchain = '1.70.0'; Features = '';                                    Label = 'default' }
  @{ Toolchain = '1.75.0'; Features = 'deflate-zlib-rs';                     Label = 'deflate-zlib-rs' }
  @{ Toolchain = '1.85.1'; Features = 'bzip2';                               Label = 'bzip2' }
  @{ Toolchain = '1.85.1'; Features = 'zstd';                                Label = 'zstd' }
  @{ Toolchain = '1.89.0'; Features = 'aes-crypto';                          Label = 'aes-crypto' }
  @{ Toolchain = '1.82.0'; Features = 'ppmd';                                Label = 'ppmd' }
  @{ Toolchain = '1.83.0'; Features = 'lzma';                                Label = 'lzma' }
  @{ Toolchain = '1.87.0'; Features = 'deflate64';                           Label = 'deflate64' }
)

$failed = @()
Push-Location $copy
try {
  foreach ($c in $cases) {
    $cargoArgs = @(('+' + $c.Toolchain), 'build', '--lib', '-q')
    if ($c.Features) { $cargoArgs += @('--features', $c.Features) }
    & cargo @cargoArgs 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
      Write-Host ("  ok    {0,-18} {1}" -f $c.Label, $c.Toolchain)
    } else {
      Write-Host ("  FAIL  {0,-18} {1}" -f $c.Label, $c.Toolchain) -ForegroundColor Red
      $failed += "$($c.Label)@$($c.Toolchain)"
    }
  }
} finally {
  Pop-Location
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failed.Count -gt 0) {
  Write-Host ""
  Write-Host ("MSRV check FAILED: " + ($failed -join ', ')) -ForegroundColor Red
  exit 1
}
Write-Host ""
Write-Host "MSRV check passed."
exit 0
