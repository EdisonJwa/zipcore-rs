#!/bin/bash
# Run the test suite on Linux, which is where CI runs. Used to verify platform-specific
# behaviour (path containment, symlinks) that Windows cannot exercise.
set -u
cd "$(dirname "$0")/.." || exit 1
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTFLAGS="-D warnings"
cargo test 2>&1 | grep -E "^test result|FAILED|^error\[|^error:" | head -30
