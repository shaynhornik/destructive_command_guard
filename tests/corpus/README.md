# Regression Corpus

This directory contains test cases for dcg's command evaluation. The corpus
tests run automatically via `cargo test --test regression_corpus`.

## Directory Structure

```
corpus/
  true_positives/    # Commands that MUST be blocked
  false_positives/   # Commands that MUST be allowed
  bypass_attempts/   # Obfuscated dangerous commands
  edge_cases/        # Commands that must not crash
```

## File Format (TOML)

```toml
[[case]]
description = "Short description of what this tests"
command = "the command to evaluate"
expected = "deny"  # or "allow"
rule_id = "pack.id:pattern-name"  # optional, for validation
```

## Adding New Test Cases

1. Choose the appropriate category directory
2. Add to an existing `.toml` file or create a new one
3. Run `cargo test --test regression_corpus` to verify

## Known Detection Gaps

The following cases are **not currently detected** but arguably should be.
They are commented out in the corpus files with `# NOTE:` markers.

### Flag Separation

These patterns use separated flags which current patterns don't handle:

- `rm -r -f /path` - Flags separated by space (only `-rf` combined works)
- `git clean -d -f` - Flags separated (only `-fd` combined works)

### Missing Patterns

These dangerous operations don't have patterns yet:

- `git checkout -f` / `git checkout --force` - Overwrites local changes
- `git checkout HEAD -- .` - Can overwrite working tree

### Partial Coverage

These have patterns but edge cases may slip through:

- `git push --force-with-lease` - Less destructive than `--force` but still risky
- `chmod -R 777` - Dangerous but not as immediately destructive as rm

## CI Integration

The corpus tests run as part of the standard test suite:

```bash
# Run just corpus tests
cargo test --test regression_corpus

# Run with verbose output
cargo test --test regression_corpus -- --nocapture
```

## Adding Regression Tests

When a bypass is found or a false positive is reported:

1. Add the command to the appropriate corpus file
2. If it's a gap, comment it out with `# NOTE:` and add to this README
3. Fix the pattern (if appropriate)
4. Uncomment the test case once the fix is verified
