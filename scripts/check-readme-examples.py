#!/usr/bin/env python3
"""Compile every Rust example in README.md.

A README whose examples do not build is worse than one with no examples: it is the first
impression, and it is wrong. This turns "the examples work" into something CI can enforce.

Each fenced ```rust block is written into a small crate that depends on this one, with the
features the README's examples need. Blocks are wrapped in `fn main() -> Result<...>`; the
hidden `# ` lines that rustdoc-style examples use are honoured, so the same blocks work in the
README and in doctests.
"""

import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")

# Examples in the README use AES, so the harness enables it. The default build is covered by the
# real test suite instead.
FEATURES = ["aes-crypto"]


def blocks(readme: str) -> list[str]:
    return re.findall(r"```rust\n(.*?)```", readme, re.S)


def render(block: str) -> str:
    lines = []
    for line in block.splitlines():
        if line.startswith("# "):
            # A hidden line that is still real code (rustdoc convention).
            lines.append(line[2:])
        elif line.strip() == "#":
            lines.append("")
        else:
            lines.append(line)
    body = "\n".join(lines).rstrip()
    indented = "\n".join("    " + ln if ln.strip() else "" for ln in body.split("\n"))
    # A block that already ends in `Ok::<...>(())` is its own return value.
    if "Ok::<" in body and body.endswith("(())"):
        return "fn main() -> Result<(), Box<dyn std::error::Error>> {\n" + indented + "\n}\n"
    return (
        "fn main() -> Result<(), Box<dyn std::error::Error>> {\n"
        + indented
        + "\n    Ok(())\n}\n"
    )


def main() -> int:
    with open(README, encoding="utf-8") as fh:
        readme = fh.read()
    examples = blocks(readme)
    if not examples:
        print("no Rust blocks found in README.md")
        return 1

    # TOML treats backslashes as escapes, so a Windows path has to be written with forward
    # slashes (cargo accepts them) rather than dropped in verbatim.
    path_for_toml = ROOT.replace("\\", "/")
    work = tempfile.mkdtemp(prefix="zipcore-readme-")
    try:
        src = os.path.join(work, "src", "bin")
        os.makedirs(src)
        feats = ", ".join(f'"{f}"' for f in FEATURES)
        with open(os.path.join(work, "Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write(
                "[package]\n"
                'name = "readme-examples"\n'
                'version = "0.0.0"\n'
                'edition = "2021"\n\n'
                "[dependencies]\n"
                f'zipcore = {{ path = "{path_for_toml}", features = [{feats}] }}\n\n'
                "[workspace]\n"
            )
        for i, block in enumerate(examples):
            with open(os.path.join(src, f"example{i}.rs"), "w", encoding="utf-8") as fh:
                fh.write(render(block))

        # CI sets RUSTFLAGS=-D warnings; examples bind values purely to show where data comes
        # from, so an unused binding is expected and must not fail the build.
        env = dict(os.environ)
        env["RUSTFLAGS"] = env.get("RUSTFLAGS", "").replace("-D warnings", "").strip()
        result = subprocess.run(
            ["cargo", "build", "--quiet"],
            cwd=work,
            capture_output=True,
            text=True,
            env=env,
        )
        if result.returncode != 0:
            print("README examples failed to compile:")
            print(result.stderr)
            return 1
        print(f"{len(examples)} README examples compile.")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
