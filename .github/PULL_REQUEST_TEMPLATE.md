# Pull request

## What does this change?

<!-- One or two sentences. Link the issue it closes, if any: "Closes #123". -->

## Why?

<!--
The diff shows what changed; explain why it is the right change. What did the previous
behaviour do wrong, and what did you consider instead?
-->

## Type of change

- [ ] Bug fix (behaviour now matches what the docs promise)
- [ ] New feature (new public API or a new compression method)
- [ ] Security fix — **a regression test is mandatory** (see `CONTRIBUTING.md`)
- [ ] Documentation only
- [ ] Refactor with no behaviour change

## Checklist

- [ ] **Tests added or updated** — and for a bug fix, a test that fails without the change.
- [ ] **`cargo clippy --all-targets --all-features -- -D warnings` is clean.**
- [ ] **`cargo fmt --all -- --check` is clean.**
- [ ] **Docs updated** — rustdoc on any new public item, plus README if behaviour or the feature
      matrix changed.
- [ ] **`CHANGELOG.md` entry added** under the appropriate heading (`Added`, `Changed`, `Fixed`,
      `Security`, `Performance`).

## Verification

<!-- How did you check this? Paste the commands you ran and their result. -->

```sh
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

<!--
On Windows, `pwsh -File scripts/check-all.ps1` runs all of the above plus the docs build, the
unsafe grep, the README-example check and the dependency budget. If your change touches
extraction, run the suite on Linux too (`scripts/test-on-linux.sh`) — path containment and
symlink handling cannot be exercised on Windows.
-->

## Impact

- **MSRV:** <!-- does this raise any row in the MSRV table? If so, which? -->
- **Dependencies:** <!-- does the default build's three-direct-dependency budget still hold? -->
- **Breaking:** <!-- pre-1.0, the minor version is where breaking changes land. Is this one? -->

## Reviewer notes

<!-- Anything you are unsure about, or want a second opinion on. -->
