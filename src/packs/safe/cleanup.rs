//! Safe cleanup pack - allows rm -rf on common build/cache directories.
//!
//! **This pack is DISABLED by default.** Enable it by adding `"safe.cleanup"` to
//! your `enabled_packs` configuration.
//!
//! # Allowed directories
//!
//! When enabled, this pack allows `rm -rf` on these relative paths:
//!
//! - `target/` - Rust build output
//! - `dist/` - Common frontend build output
//! - `build/` - Common build output (Gradle, general)
//! - `.next/` - Next.js cache
//! - `.turbo/` - Turborepo cache
//! - `.nuxt/` - Nuxt.js cache
//! - `.output/` - Nuxt 3 output
//! - `.svelte-kit/` - `SvelteKit` cache
//! - `node_modules/` - npm/yarn/pnpm dependencies
//! - `__pycache__/` - Python bytecode cache
//! - `.pytest_cache/` - pytest cache
//! - `.mypy_cache/` - mypy cache
//! - `.ruff_cache/` - ruff cache
//! - `.gradle/` - Gradle cache
//! - `.maven/` - Maven cache
//! - `.cargo/` - Cargo cache (careful: contains downloaded crates)
//! - `vendor/` - Vendored dependencies
//! - `coverage/` - Test coverage reports
//! - `.coverage/` - Coverage data
//! - `.nyc_output/` - NYC coverage output
//! - `.parcel-cache/` - Parcel bundler cache
//! - `.cache/` - Generic cache directory
//! - `.vite/` - Vite cache
//! - `.rollup.cache/` - Rollup cache
//! - `out/` - Common output directory
//!
//! # Safety constraints
//!
//! All patterns enforce:
//! - **Relative paths only**: No absolute paths (`/path`) or home paths (`~/path`)
//! - **No path traversal**: No `..` segments anywhere in the path
//! - **Explicit directory names**: Only exact matches at path start
//!
//! # Examples
//!
//! **Allowed (when pack enabled):**
//! - `rm -rf target/`
//! - `rm -rf ./dist/`
//! - `rm -rf node_modules/`
//! - `rm -rf target/debug/`
//!
//! **Still blocked (even when pack enabled):**
//! - `rm -rf /target/` - absolute path
//! - `rm -rf ../target/` - path traversal
//! - `rm -rf foo/../target/` - embedded path traversal
//! - `rm -rf ~/target/` - home directory
//! - `rm -rf /home/user/target/` - absolute path

use crate::packs::{Pack, SafePattern};

/// Create the safe cleanup pack.
///
/// This pack is opt-in (disabled by default) and allows `rm -rf` on common
/// build/cache directories when the path is relative and contains no traversal.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "safe.cleanup".to_string(),
        name: "Safe Cleanup",
        description: "Allows rm -rf on common build/cache directories (target/, dist/, node_modules/, etc.)",
        keywords: &["rm"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: vec![], // This pack only adds safe patterns
    }
}

/// Generates safe patterns for a list of directory names.
///
/// Each directory gets patterns for both `rm -rf` and `rm -fr` flag orders,
/// as well as `./dir` prefix variants.
fn create_safe_patterns() -> Vec<SafePattern> {
    // Common build/cache directories that are safe to delete
    // These are all relative-path-only and reject path traversal
    let safe_dirs = [
        // Rust
        ("target", "rm-rf-target"),
        // Frontend/JS
        ("dist", "rm-rf-dist"),
        ("build", "rm-rf-build"),
        ("node_modules", "rm-rf-node-modules"),
        (".next", "rm-rf-next"),
        (".turbo", "rm-rf-turbo"),
        (".nuxt", "rm-rf-nuxt"),
        (".output", "rm-rf-output"),
        (".svelte-kit", "rm-rf-svelte-kit"),
        (".parcel-cache", "rm-rf-parcel-cache"),
        (".cache", "rm-rf-cache"),
        (".vite", "rm-rf-vite"),
        (".rollup.cache", "rm-rf-rollup-cache"),
        ("out", "rm-rf-out"),
        // Python
        ("__pycache__", "rm-rf-pycache"),
        (".pytest_cache", "rm-rf-pytest-cache"),
        (".mypy_cache", "rm-rf-mypy-cache"),
        (".ruff_cache", "rm-rf-ruff-cache"),
        (".tox", "rm-rf-tox"),
        ("*.egg-info", "rm-rf-egg-info"),
        (".eggs", "rm-rf-eggs"),
        // Java/JVM
        (".gradle", "rm-rf-gradle"),
        (".maven", "rm-rf-maven"),
        // Go
        ("vendor", "rm-rf-vendor"),
        // Coverage
        ("coverage", "rm-rf-coverage"),
        (".coverage", "rm-rf-dot-coverage"),
        (".nyc_output", "rm-rf-nyc-output"),
    ];

    let mut patterns = Vec::new();

    for (dir, base_name) in safe_dirs {
        // Escape special regex characters in directory name
        let escaped_dir = regex_escape(dir);

        // Pattern requirements:
        // 1. Match rm with -rf or -fr flags (combined or separate)
        // 2. Path must be relative (not start with / or ~)
        // 3. Path must not contain .. anywhere
        // 4. Directory must be at the start of the path (after optional ./)
        //
        // We use negative lookahead (?!...) to reject:
        // - Absolute paths: starts with /
        // - Home paths: starts with ~
        // - Path traversal: contains ..
        //
        // Pattern structure:
        // rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+  -- rm with -rf flags
        // (?!/)(?!~)(?![^\s]*\.\.)                -- negative lookahead: no /, ~, or ..
        // (?:\./)?                                -- optional ./ prefix
        // {dir}(?:/|\s|$)                         -- directory name followed by /, space, or end

        // Combined -rf flags (like -rf, -rfi, -Rf, etc.)
        let rf_pattern = format!(
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?!/)(?!~)(?![^\s]*\.\.)(?:\./)?{escaped_dir}(?:/|\s|$)"
        );

        // Combined -fr flags (like -fr, -fri, -fR, etc.)
        let fr_pattern = format!(
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?!/)(?!~)(?![^\s]*\.\.)(?:\./)?{escaped_dir}(?:/|\s|$)"
        );

        // Separate -r -f flags (like -r -f, -R -f, etc.)
        let separate_r_then_f = format!(
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?!/)(?!~)(?![^\s]*\.\.)(?:\./)?{escaped_dir}(?:/|\s|$)"
        );

        // Separate -f -r flags (like -f -r, -f -R, etc.)
        let separate_f_then_r = format!(
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?!/)(?!~)(?![^\s]*\.\.)(?:\./)?{escaped_dir}(?:/|\s|$)"
        );

        // Long flags --recursive --force
        let recursive_force_pattern = format!(
            r"rm\s+.*--recursive.*--force\s+(?!/)(?!~)(?![^\s]*\.\.)(?:\./)?{escaped_dir}(?:/|\s|$)"
        );

        // Long flags --force --recursive
        let force_recursive_pattern = format!(
            r"rm\s+.*--force.*--recursive\s+(?!/)(?!~)(?![^\s]*\.\.)(?:\./)?{escaped_dir}(?:/|\s|$)"
        );

        // Add all pattern variants
        patterns.push(make_safe_pattern(&format!("{base_name}-rf"), &rf_pattern));
        patterns.push(make_safe_pattern(&format!("{base_name}-fr"), &fr_pattern));
        patterns.push(make_safe_pattern(
            &format!("{base_name}-r-f"),
            &separate_r_then_f,
        ));
        patterns.push(make_safe_pattern(
            &format!("{base_name}-f-r"),
            &separate_f_then_r,
        ));
        patterns.push(make_safe_pattern(
            &format!("{base_name}-recursive-force"),
            &recursive_force_pattern,
        ));
        patterns.push(make_safe_pattern(
            &format!("{base_name}-force-recursive"),
            &force_recursive_pattern,
        ));
    }

    patterns
}

/// Escape regex special characters in a string.
fn regex_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\'
            | '-' => {
                escaped.push('\\');
                escaped.push(c);
            }
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Create a `SafePattern` from a name and regex string.
///
/// Panics if the regex is invalid (compile-time bug).
fn make_safe_pattern(name: &str, pattern: &str) -> SafePattern {
    SafePattern {
        regex: fancy_regex::Regex::new(pattern)
            .unwrap_or_else(|e| panic!("safe.cleanup pattern '{name}' should compile: {e}")),
        // We need a &'static str, so we leak the string. This is fine because
        // packs are created once at startup and live for the program's lifetime.
        name: Box::leak(name.to_string().into_boxed_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack() -> Pack {
        create_pack()
    }

    // =========================================================================
    // Allowed commands (safe patterns should match)
    // =========================================================================

    #[test]
    fn allows_rm_rf_target() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf target/"),
            "rm -rf target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf target"),
            "rm -rf target should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf ./target/"),
            "rm -rf ./target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf ./target"),
            "rm -rf ./target should be allowed"
        );
    }

    #[test]
    fn allows_rm_fr_target() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -fr target/"),
            "rm -fr target/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_dist() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf dist/"),
            "rm -rf dist/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf ./dist/"),
            "rm -rf ./dist/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_node_modules() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf node_modules/"),
            "rm -rf node_modules/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf ./node_modules"),
            "rm -rf ./node_modules should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_build() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf build/"),
            "rm -rf build/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_pycache() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf __pycache__/"),
            "rm -rf __pycache__/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_next() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf .next/"),
            "rm -rf .next/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_with_subdirs() {
        let pack = pack();
        // Subdirectories of allowed dirs should also be allowed
        assert!(
            pack.matches_safe("rm -rf target/debug/"),
            "rm -rf target/debug/ should be allowed"
        );
    }

    #[test]
    fn allows_separate_flags() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -r -f target/"),
            "rm -r -f target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -f -r target/"),
            "rm -f -r target/ should be allowed"
        );
    }

    #[test]
    fn allows_long_flags() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm --recursive --force target/"),
            "rm --recursive --force target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm --force --recursive target/"),
            "rm --force --recursive target/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_cache() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf .cache/"),
            "rm -rf .cache/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_vendor() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf vendor/"),
            "rm -rf vendor/ should be allowed"
        );
    }

    // =========================================================================
    // Blocked commands (safe patterns should NOT match)
    // =========================================================================

    #[test]
    fn blocks_absolute_path() {
        let pack = pack();
        assert!(
            !pack.matches_safe("rm -rf /target/"),
            "rm -rf /target/ (absolute) should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf /home/user/target/"),
            "rm -rf /home/user/target/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_home_path() {
        let pack = pack();
        assert!(
            !pack.matches_safe("rm -rf ~/target/"),
            "rm -rf ~/target/ (home) should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf ~user/target/"),
            "rm -rf ~user/target/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_path_traversal_prefix() {
        let pack = pack();
        assert!(
            !pack.matches_safe("rm -rf ../target/"),
            "rm -rf ../target/ (traversal) should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf ../../target/"),
            "rm -rf ../../target/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_embedded_path_traversal() {
        let pack = pack();
        assert!(
            !pack.matches_safe("rm -rf foo/../target/"),
            "rm -rf foo/../target/ (embedded traversal) should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf ./foo/../target/"),
            "rm -rf ./foo/../target/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_non_allowed_directories() {
        let pack = pack();
        // Random directories are NOT in the allowlist
        assert!(
            !pack.matches_safe("rm -rf src/"),
            "rm -rf src/ should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf data/"),
            "rm -rf data/ should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf important/"),
            "rm -rf important/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_target_as_suffix() {
        let pack = pack();
        // "target" as part of a larger directory name should NOT match
        assert!(
            !pack.matches_safe("rm -rf mytarget/"),
            "rm -rf mytarget/ should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf target-old/"),
            "rm -rf target-old/ should NOT be allowed (contains - after target)"
        );
    }

    #[test]
    fn blocks_plain_rm() {
        let pack = pack();
        // rm without -rf should not match (this pack is specifically for rm -rf)
        assert!(
            !pack.matches_safe("rm target/"),
            "rm target/ (no -rf) should NOT be allowed by this pack"
        );
        assert!(
            !pack.matches_safe("rm -r target/"),
            "rm -r target/ (no -f) should NOT be allowed by this pack"
        );
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn handles_case_sensitivity() {
        let pack = pack();
        // Directory names are case-sensitive
        assert!(
            !pack.matches_safe("rm -rf TARGET/"),
            "rm -rf TARGET/ should NOT be allowed (case sensitive)"
        );
        assert!(
            !pack.matches_safe("rm -rf Target/"),
            "rm -rf Target/ should NOT be allowed (case sensitive)"
        );
    }

    #[test]
    fn allows_uppercase_r_flag() {
        let pack = pack();
        // -R is equivalent to -r in rm
        assert!(
            pack.matches_safe("rm -Rf target/"),
            "rm -Rf target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -fR target/"),
            "rm -fR target/ should be allowed"
        );
    }

    #[test]
    fn pack_id_is_correct() {
        let pack = pack();
        assert_eq!(pack.id, "safe.cleanup");
    }

    #[test]
    fn pack_has_rm_keyword() {
        let pack = pack();
        assert!(
            pack.keywords.contains(&"rm"),
            "pack should have 'rm' keyword"
        );
    }

    #[test]
    fn pack_has_no_destructive_patterns() {
        let pack = pack();
        assert!(
            pack.destructive_patterns.is_empty(),
            "safe.cleanup should only have safe patterns, no destructive ones"
        );
    }

    #[test]
    fn allows_multiple_dirs_in_one_command() {
        let pack = pack();
        // When user deletes multiple dirs, each should be checked individually
        // This test verifies the pattern terminates correctly at word boundaries
        assert!(
            pack.matches_safe("rm -rf target/ dist/"),
            "rm -rf target/ dist/ should be allowed (first dir matches)"
        );
    }
}
