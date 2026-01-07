# git_safety_guard

A Claude Code hook that blocks destructive git and filesystem commands before they execute.

## What it blocks

- `git reset --hard`, `git checkout -- <file>`, `git restore` (without `--staged`)
- `git clean -f`, `git push --force`, `git branch -D`
- `git stash drop`, `git stash clear`
- `rm -rf` outside of `/tmp`, `/var/tmp`, or `$TMPDIR`

## What it allows

- Safe operations: `git status`, `git log`, `git diff`, `git add`, `git commit`, `git push`
- New branches: `git checkout -b`, `git checkout --orphan`
- Staged-only restores: `git restore --staged`
- Dry runs: `git clean -n`
- Temp directory cleanup: `rm -rf /tmp/*`, `rm -rf $TMPDIR/*`

## Installation

### From source (requires Rust)

```bash
cargo install --git https://github.com/dowwie/git_safety_guard
```

### From crates.io (if published)

```bash
cargo install git_safety_guard
```

### Manual build

```bash
git clone https://github.com/dowwie/git_safety_guard
cd git_safety_guard
cargo build --release
cp target/release/git_safety_guard ~/.local/bin/
```

## Claude Code configuration

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "git_safety_guard"
          }
        ]
      }
    ]
  }
}
```

## License

MIT
