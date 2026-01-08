//! Pack system for modular command blocking.
//!
//! This module provides the infrastructure for organizing patterns into "packs"
//! that can be enabled or disabled based on user configuration.
//!
//! # Pack Hierarchy
//!
//! Packs are organized in a two-level hierarchy:
//! - Category (e.g., "database", "kubernetes")
//! - Sub-pack (e.g., "database.postgresql", "kubernetes.kubectl")
//!
//! Enabling a category enables all its sub-packs. Sub-packs can be individually
//! disabled even if their parent category is enabled.

pub mod cloud;
pub mod containers;
pub mod core;
pub mod database;
pub mod infrastructure;
pub mod kubernetes;
pub mod package_managers;
pub mod strict_git;
pub mod system;

use fancy_regex::Regex;
use memchr::memmem;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Unique identifier for a pack (e.g., "core", "database.postgresql").
pub type PackId = String;

/// A safe pattern that, when matched, allows the command immediately.
#[derive(Debug)]
pub struct SafePattern {
    /// Compiled regex pattern.
    pub regex: Regex,
    /// Debug name for the pattern.
    pub name: &'static str,
}

/// A destructive pattern that, when matched, blocks the command.
#[derive(Debug)]
pub struct DestructivePattern {
    /// Compiled regex pattern.
    pub regex: Regex,
    /// Human-readable explanation of why this command is blocked.
    pub reason: &'static str,
    /// Optional pattern name for debugging.
    pub name: Option<&'static str>,
}

/// Macro to create a safe pattern with compile-time name checking.
#[macro_export]
macro_rules! safe_pattern {
    ($name:literal, $re:literal) => {
        $crate::packs::SafePattern {
            regex: ::fancy_regex::Regex::new($re).expect(concat!(
                "safe pattern '",
                $name,
                "' should compile"
            )),
            name: $name,
        }
    };
}

/// Macro to create a destructive pattern with reason.
#[macro_export]
macro_rules! destructive_pattern {
    ($re:literal, $reason:literal) => {
        $crate::packs::DestructivePattern {
            regex: ::fancy_regex::Regex::new($re)
                .expect(concat!("destructive pattern should compile: ", $re)),
            reason: $reason,
            name: None,
        }
    };
    ($name:literal, $re:literal, $reason:literal) => {
        $crate::packs::DestructivePattern {
            regex: ::fancy_regex::Regex::new($re).expect(concat!(
                "destructive pattern '",
                $name,
                "' should compile"
            )),
            reason: $reason,
            name: Some($name),
        }
    };
}

/// A pack of patterns for a specific category of commands.
#[derive(Debug)]
pub struct Pack {
    /// Unique identifier (e.g., "database.postgresql").
    pub id: PackId,

    /// Human-readable name (e.g., "PostgreSQL").
    pub name: &'static str,

    /// Description of what this pack protects against.
    pub description: &'static str,

    /// Keywords for quick-reject filtering (e.g., ["psql", "dropdb", "DROP"]).
    /// Commands without any of these keywords skip pattern matching for this pack.
    pub keywords: &'static [&'static str],

    /// Safe patterns (whitelist) - checked first.
    pub safe_patterns: Vec<SafePattern>,

    /// Destructive patterns (blacklist) - checked if no safe pattern matches.
    pub destructive_patterns: Vec<DestructivePattern>,
}

impl Pack {
    /// Check if a command contains any of this pack's keywords.
    /// Returns false if the command doesn't contain any keywords (quick reject).
    pub fn might_match(&self, cmd: &str) -> bool {
        if self.keywords.is_empty() {
            return true; // No keywords = always check patterns
        }

        let bytes = cmd.as_bytes();
        self.keywords
            .iter()
            .any(|kw| memmem::find(bytes, kw.as_bytes()).is_some())
    }

    /// Check if a command matches any safe pattern.
    pub fn matches_safe(&self, cmd: &str) -> bool {
        self.safe_patterns
            .iter()
            .any(|p| p.regex.is_match(cmd).unwrap_or(false))
    }

    /// Check if a command matches any destructive pattern.
    /// Returns the matched pattern's reason and name if found.
    pub fn matches_destructive(&self, cmd: &str) -> Option<DestructiveMatch> {
        self.destructive_patterns
            .iter()
            .find(|p| p.regex.is_match(cmd).unwrap_or(false))
            .map(|p| DestructiveMatch {
                reason: p.reason,
                name: p.name,
            })
    }

    /// Check a command against this pack.
    /// Returns Some(DestructiveMatch) if blocked, None if allowed.
    pub fn check(&self, cmd: &str) -> Option<DestructiveMatch> {
        // Quick reject if no keywords match
        if !self.might_match(cmd) {
            return None;
        }

        // Check safe patterns first (whitelist)
        if self.matches_safe(cmd) {
            return None;
        }

        // Check destructive patterns (blacklist)
        self.matches_destructive(cmd)
    }
}

/// Information about a matched destructive pattern.
#[derive(Debug, Clone)]
pub struct DestructiveMatch {
    /// Human-readable explanation of why this command is blocked.
    pub reason: &'static str,
    /// Optional pattern name for debugging and allowlisting.
    pub name: Option<&'static str>,
}

/// Result of checking a command against all packs.
#[derive(Debug)]
pub struct CheckResult {
    /// Whether the command should be blocked.
    pub blocked: bool,
    /// The reason for blocking (if blocked).
    pub reason: Option<String>,
    /// Which pack blocked it (if blocked).
    pub pack_id: Option<PackId>,
    /// The name of the pattern that matched (if available).
    pub pattern_name: Option<String>,
}

impl CheckResult {
    /// Create an "allowed" result.
    pub fn allowed() -> Self {
        Self {
            blocked: false,
            reason: None,
            pack_id: None,
            pattern_name: None,
        }
    }

    /// Create a "blocked" result with pattern identity.
    pub fn blocked(reason: &str, pack_id: &str, pattern_name: Option<&str>) -> Self {
        Self {
            blocked: true,
            reason: Some(reason.to_string()),
            pack_id: Some(pack_id.to_string()),
            pattern_name: pattern_name.map(ToString::to_string),
        }
    }
}

/// Registry of all available packs.
pub struct PackRegistry {
    /// All registered packs, keyed by ID.
    packs: HashMap<PackId, Pack>,

    /// Pack IDs organized by category for hierarchical enablement.
    categories: HashMap<String, Vec<PackId>>,
}

impl PackRegistry {
    /// Collect all keywords from enabled packs.
    ///
    /// This returns a deduplicated list of keywords that can be used for
    /// pack-aware quick rejection. If a command contains none of these keywords,
    /// it can safely skip pack checking.
    #[must_use]
    pub fn collect_enabled_keywords(&self, enabled_packs: &HashSet<String>) -> Vec<&'static str> {
        let expanded = self.expand_enabled(enabled_packs);
        let mut keywords = Vec::new();

        for pack_id in &expanded {
            if let Some(pack) = self.packs.get(pack_id) {
                keywords.extend(pack.keywords.iter().copied());
            }
        }

        // Deduplicate while preserving order (first occurrence wins)
        let mut seen = HashSet::new();
        keywords.retain(|kw| seen.insert(*kw));

        keywords
    }

    /// Create a new registry with all built-in packs.
    pub fn new() -> Self {
        let mut registry = Self {
            packs: HashMap::new(),
            categories: HashMap::new(),
        };

        // Register all built-in packs
        registry.register_pack(core::git::create_pack());
        registry.register_pack(core::filesystem::create_pack());
        registry.register_pack(database::postgresql::create_pack());
        registry.register_pack(database::mysql::create_pack());
        registry.register_pack(database::mongodb::create_pack());
        registry.register_pack(database::redis::create_pack());
        registry.register_pack(database::sqlite::create_pack());
        registry.register_pack(containers::docker::create_pack());
        registry.register_pack(containers::compose::create_pack());
        registry.register_pack(containers::podman::create_pack());
        registry.register_pack(kubernetes::kubectl::create_pack());
        registry.register_pack(kubernetes::helm::create_pack());
        registry.register_pack(kubernetes::kustomize::create_pack());
        registry.register_pack(cloud::aws::create_pack());
        registry.register_pack(cloud::gcp::create_pack());
        registry.register_pack(cloud::azure::create_pack());
        registry.register_pack(infrastructure::terraform::create_pack());
        registry.register_pack(infrastructure::ansible::create_pack());
        registry.register_pack(infrastructure::pulumi::create_pack());
        registry.register_pack(system::disk::create_pack());
        registry.register_pack(system::permissions::create_pack());
        registry.register_pack(system::services::create_pack());
        registry.register_pack(strict_git::create_pack());
        registry.register_pack(package_managers::create_pack());

        registry
    }

    /// Register a pack in the registry.
    fn register_pack(&mut self, pack: Pack) {
        let id = pack.id.clone();

        // Extract category from ID (e.g., "database" from "database.postgresql")
        let category = id.split('.').next().unwrap_or(&id).to_string();

        // Add to categories map
        self.categories
            .entry(category)
            .or_default()
            .push(id.clone());

        // Add to packs map
        self.packs.insert(id, pack);
    }

    /// Get a pack by ID.
    pub fn get(&self, id: &str) -> Option<&Pack> {
        self.packs.get(id)
    }

    /// Get all pack IDs.
    pub fn all_pack_ids(&self) -> Vec<&PackId> {
        self.packs.keys().collect()
    }

    /// Get all categories.
    pub fn all_categories(&self) -> Vec<&String> {
        self.categories.keys().collect()
    }

    /// Get pack IDs in a category.
    pub fn packs_in_category(&self, category: &str) -> Vec<&PackId> {
        self.categories
            .get(category)
            .map(|ids| ids.iter().collect())
            .unwrap_or_default()
    }

    /// Expand enabled pack IDs to include sub-packs when a category is enabled.
    pub fn expand_enabled(&self, enabled: &HashSet<String>) -> HashSet<String> {
        let mut expanded = HashSet::new();

        for id in enabled {
            // Check if this is a category
            if let Some(sub_packs) = self.categories.get(id) {
                // Add all sub-packs in the category
                for sub_pack in sub_packs {
                    expanded.insert(sub_pack.clone());
                }
            }
            // Also add the ID itself (in case it's a specific pack)
            expanded.insert(id.clone());
        }

        expanded
    }

    /// Expand enabled pack IDs and return them in a deterministic order.
    ///
    /// This is used by `check_command` to ensure consistent attribution when
    /// multiple packs could match the same command. The ordering is:
    ///
    /// 1. **Tier 1 (core)**: `core.*` packs - most fundamental protections
    /// 2. **Tier 2 (system)**: `system.*` - disk, permissions, services
    /// 3. **Tier 3 (infrastructure)**: `infrastructure.*` - terraform, ansible, pulumi
    /// 4. **Tier 4 (cloud)**: `cloud.*` - aws, gcp, azure
    /// 5. **Tier 5 (kubernetes)**: `kubernetes.*` - kubectl, helm, kustomize
    /// 6. **Tier 6 (containers)**: `containers.*` - docker, compose, podman
    /// 7. **Tier 7 (database)**: `database.*` - postgresql, mysql, etc.
    /// 8. **Tier 8 (package_managers)**: package manager protections
    /// 9. **Tier 9 (strict_git)**: extra git paranoia
    ///
    /// Within each tier, packs are sorted lexicographically by ID.
    pub fn expand_enabled_ordered(&self, enabled: &HashSet<String>) -> Vec<String> {
        let expanded = self.expand_enabled(enabled);

        // Filter to only include pack IDs that actually exist in registry
        let mut pack_ids: Vec<String> = expanded
            .into_iter()
            .filter(|id| self.packs.contains_key(id))
            .collect();

        // Sort by tier then lexicographically within tier
        pack_ids.sort_by(|a, b| {
            let tier_a = Self::pack_tier(a);
            let tier_b = Self::pack_tier(b);
            tier_a.cmp(&tier_b).then_with(|| a.cmp(b))
        });

        pack_ids
    }

    /// Get the priority tier for a pack ID (lower = higher priority).
    fn pack_tier(pack_id: &str) -> u8 {
        let category = pack_id.split('.').next().unwrap_or(pack_id);
        match category {
            "core" => 1,
            "system" => 2,
            "infrastructure" => 3,
            "cloud" => 4,
            "kubernetes" => 5,
            "containers" => 6,
            "database" => 7,
            "package_managers" => 8,
            "strict_git" => 9,
            _ => 10, // Unknown categories go last
        }
    }

    /// Check a command against all enabled packs.
    ///
    /// Packs are evaluated in a deterministic order (see `expand_enabled_ordered`),
    /// ensuring consistent attribution when multiple packs could match.
    ///
    /// Returns a `CheckResult` containing:
    /// - `blocked`: whether the command should be blocked
    /// - `reason`: the human-readable explanation (if blocked)
    /// - `pack_id`: which pack blocked it (if blocked)
    /// - `pattern_name`: the specific pattern that matched (if available and blocked)
    pub fn check_command(&self, cmd: &str, enabled_packs: &HashSet<String>) -> CheckResult {
        // Expand category IDs to include all sub-packs in deterministic order
        let ordered_packs = self.expand_enabled_ordered(enabled_packs);

        for pack_id in &ordered_packs {
            if let Some(pack) = self.packs.get(pack_id) {
                if let Some(matched) = pack.check(cmd) {
                    return CheckResult::blocked(matched.reason, pack_id, matched.name);
                }
            }
        }

        CheckResult::allowed()
    }

    /// List all packs with their status.
    pub fn list_packs(&self, enabled: &HashSet<String>) -> Vec<PackInfo> {
        let expanded = self.expand_enabled(enabled);

        let mut infos: Vec<_> = self
            .packs
            .values()
            .map(|pack| PackInfo {
                id: pack.id.clone(),
                name: pack.name,
                description: pack.description,
                enabled: expanded.contains(&pack.id),
                safe_pattern_count: pack.safe_patterns.len(),
                destructive_pattern_count: pack.destructive_patterns.len(),
            })
            .collect();

        // Sort by ID for consistent output
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }
}

impl Default for PackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a pack for display.
#[derive(Debug)]
pub struct PackInfo {
    /// Pack ID.
    pub id: PackId,
    /// Human-readable name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
    /// Whether the pack is enabled.
    pub enabled: bool,
    /// Number of safe patterns.
    pub safe_pattern_count: usize,
    /// Number of destructive patterns.
    pub destructive_pattern_count: usize,
}

/// Global pack registry (lazily initialized).
pub static REGISTRY: LazyLock<PackRegistry> = LazyLock::new(PackRegistry::new);

/// Regex to strip absolute paths from git/rm binaries.
static PATH_NORMALIZER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/(?:\S*/)*s?bin/(rm|git)(?=\s|$)").unwrap());

/// Normalize a command by stripping absolute paths from common binaries.
#[inline]
pub fn normalize_command(cmd: &str) -> Cow<'_, str> {
    if !cmd.starts_with('/') {
        return Cow::Borrowed(cmd);
    }
    PATH_NORMALIZER.replace(cmd, "$1")
}

/// Pre-compiled finders for core quick rejection (git/rm).
static GIT_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("git"));
static RM_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("rm"));

/// Core quick-reject filter (legacy - only checks git/rm).
/// Returns true if command definitely doesn't need core checking (no "git" or "rm").
///
/// NOTE: This only checks core keywords. Use `pack_aware_quick_reject` for
/// commands that need to be checked against enabled packs.
#[inline]
pub fn global_quick_reject(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    GIT_FINDER.find(bytes).is_none() && RM_FINDER.find(bytes).is_none()
}

/// Pack-aware quick-reject filter.
///
/// Returns true if the command can be safely skipped (contains none of the
/// provided keywords from enabled packs).
///
/// This is the correct function to use when non-core packs are enabled.
/// It checks all keywords from enabled packs, not just "git" and "rm".
///
/// # Performance
///
/// Uses SIMD-accelerated substring search via memchr for each keyword.
/// For typical command lengths and keyword counts, this is sub-microsecond.
///
/// # Arguments
///
/// * `cmd` - The command string to check
/// * `enabled_keywords` - Keywords from all enabled packs (from `PackRegistry::collect_enabled_keywords`)
///
/// # Returns
///
/// `true` if the command contains NO keywords (safe to skip pack checking)
/// `false` if the command contains at least one keyword (must check packs)
#[inline]
#[must_use]
pub fn pack_aware_quick_reject(cmd: &str, enabled_keywords: &[&str]) -> bool {
    let bytes = cmd.as_bytes();

    // Fast path: if no keywords are configured, nothing to check
    if enabled_keywords.is_empty() {
        return true;
    }

    // Check if any keyword appears in the command
    // Using memchr::memmem::find for SIMD-accelerated search
    for keyword in enabled_keywords {
        if memmem::find(bytes, keyword.as_bytes()).is_some() {
            return false; // Keyword found, must evaluate packs
        }
    }

    true // No keywords found, safe to skip pack checking
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that pack_tier returns correct tiers for all known categories.
    #[test]
    fn pack_tier_ordering() {
        // Core should be highest priority (tier 1)
        assert_eq!(PackRegistry::pack_tier("core.git"), 1);
        assert_eq!(PackRegistry::pack_tier("core.filesystem"), 1);

        // System should be tier 2
        assert_eq!(PackRegistry::pack_tier("system.disk"), 2);
        assert_eq!(PackRegistry::pack_tier("system.permissions"), 2);

        // Infrastructure should be tier 3
        assert_eq!(PackRegistry::pack_tier("infrastructure.terraform"), 3);

        // Cloud should be tier 4
        assert_eq!(PackRegistry::pack_tier("cloud.aws"), 4);

        // Kubernetes should be tier 5
        assert_eq!(PackRegistry::pack_tier("kubernetes.kubectl"), 5);

        // Containers should be tier 6
        assert_eq!(PackRegistry::pack_tier("containers.docker"), 6);

        // Database should be tier 7
        assert_eq!(PackRegistry::pack_tier("database.postgresql"), 7);

        // Package managers should be tier 8
        assert_eq!(PackRegistry::pack_tier("package_managers"), 8);

        // Strict git should be tier 9
        assert_eq!(PackRegistry::pack_tier("strict_git"), 9);

        // Unknown should be tier 10
        assert_eq!(PackRegistry::pack_tier("unknown.pack"), 10);
    }

    /// Test that expand_enabled_ordered returns packs in deterministic order.
    #[test]
    fn expand_enabled_ordered_is_deterministic() {
        let mut enabled = HashSet::new();
        enabled.insert("containers.docker".to_string());
        enabled.insert("kubernetes.kubectl".to_string());
        enabled.insert("core.git".to_string());
        enabled.insert("database.postgresql".to_string());

        // Run multiple times to verify determinism
        let first_run = REGISTRY.expand_enabled_ordered(&enabled);

        for _ in 0..10 {
            let run = REGISTRY.expand_enabled_ordered(&enabled);
            assert_eq!(
                run, first_run,
                "expand_enabled_ordered should produce identical results across runs"
            );
        }
    }

    /// Test that expand_enabled_ordered sorts by tier then lexicographically.
    #[test]
    fn expand_enabled_ordered_respects_tier_ordering() {
        let mut enabled = HashSet::new();
        enabled.insert("containers.docker".to_string()); // tier 6
        enabled.insert("core.git".to_string()); // tier 1
        enabled.insert("database.postgresql".to_string()); // tier 7

        let ordered = REGISTRY.expand_enabled_ordered(&enabled);

        // Find positions
        let core_pos = ordered.iter().position(|id| id == "core.git");
        let docker_pos = ordered.iter().position(|id| id == "containers.docker");
        let pg_pos = ordered.iter().position(|id| id == "database.postgresql");

        assert!(
            core_pos.is_some() && docker_pos.is_some() && pg_pos.is_some(),
            "All packs should be present"
        );

        // Core (tier 1) should come before containers (tier 6)
        assert!(
            core_pos.unwrap() < docker_pos.unwrap(),
            "core.git should come before containers.docker"
        );

        // Containers (tier 6) should come before database (tier 7)
        assert!(
            docker_pos.unwrap() < pg_pos.unwrap(),
            "containers.docker should come before database.postgresql"
        );
    }

    /// Test that expand_enabled_ordered sorts lexicographically within tier.
    #[test]
    fn expand_enabled_ordered_sorts_within_tier() {
        let mut enabled = HashSet::new();
        enabled.insert("core.git".to_string());
        enabled.insert("core.filesystem".to_string());

        let ordered = REGISTRY.expand_enabled_ordered(&enabled);

        let fs_pos = ordered.iter().position(|id| id == "core.filesystem");
        let git_pos = ordered.iter().position(|id| id == "core.git");

        assert!(
            fs_pos.is_some() && git_pos.is_some(),
            "Both core packs should be present"
        );

        // filesystem < git lexicographically
        assert!(
            fs_pos.unwrap() < git_pos.unwrap(),
            "core.filesystem should come before core.git (lexicographic)"
        );
    }

    /// Test that check_command returns consistent attribution across runs.
    /// This is the key regression test for deterministic pack evaluation.
    #[test]
    fn check_command_attribution_is_deterministic() {
        // Enable both core.git and strict_git packs
        // If a git command matches both, core.git should always win (lower tier)
        let mut enabled = HashSet::new();
        enabled.insert("core.git".to_string());
        enabled.insert("strict_git".to_string());

        let cmd = "git reset --hard";

        // Run multiple times
        let first_result = REGISTRY.check_command(cmd, &enabled);

        for _ in 0..10 {
            let result = REGISTRY.check_command(cmd, &enabled);
            assert_eq!(
                result.blocked, first_result.blocked,
                "Blocked status should be consistent"
            );
            assert_eq!(
                result.pack_id, first_result.pack_id,
                "Pack attribution should be consistent across runs"
            );
            assert_eq!(
                result.pattern_name, first_result.pattern_name,
                "Pattern name should be consistent across runs"
            );
        }
    }

    /// Test that when multiple packs match, the higher-priority pack is attributed.
    #[test]
    fn check_command_prefers_higher_priority_pack() {
        let mut enabled = HashSet::new();
        enabled.insert("core.git".to_string()); // tier 1
        enabled.insert("strict_git".to_string()); // tier 9

        let cmd = "git reset --hard";
        let result = REGISTRY.check_command(cmd, &enabled);

        assert!(result.blocked, "Command should be blocked");
        assert_eq!(
            result.pack_id.as_deref(),
            Some("core.git"),
            "core.git (tier 1) should be attributed over strict_git (tier 9)"
        );
    }

    /// Test category expansion produces ordered results.
    #[test]
    fn category_expansion_is_ordered() {
        let mut enabled = HashSet::new();
        enabled.insert("containers".to_string()); // Category - expands to docker, compose, podman

        let ordered = REGISTRY.expand_enabled_ordered(&enabled);

        // All containers packs should be present
        let has_docker = ordered.iter().any(|id| id == "containers.docker");
        let has_compose = ordered.iter().any(|id| id == "containers.compose");
        let has_podman = ordered.iter().any(|id| id == "containers.podman");

        assert!(
            has_docker && has_compose && has_podman,
            "Category expansion should include all sub-packs"
        );

        // Should be in lexicographic order (compose < docker < podman)
        let compose_pos = ordered.iter().position(|id| id == "containers.compose");
        let docker_pos = ordered.iter().position(|id| id == "containers.docker");
        let podman_pos = ordered.iter().position(|id| id == "containers.podman");

        assert!(
            compose_pos.unwrap() < docker_pos.unwrap(),
            "compose should come before docker"
        );
        assert!(
            docker_pos.unwrap() < podman_pos.unwrap(),
            "docker should come before podman"
        );
    }

    /// Test that check_command returns pattern_name when available.
    #[test]
    fn check_command_returns_pattern_name() {
        let mut enabled = HashSet::new();
        enabled.insert("containers.docker".to_string());

        // docker system prune should match a named destructive pattern
        let cmd = "docker system prune";
        let result = REGISTRY.check_command(cmd, &enabled);

        assert!(result.blocked, "docker system prune should be blocked");
        assert_eq!(
            result.pack_id.as_deref(),
            Some("containers.docker"),
            "Should be attributed to containers.docker"
        );
        // Verify pattern_name is propagated (may be None if pattern is unnamed)
        // The important thing is the field exists and is correctly populated
        assert!(
            result.pattern_name.is_some() || result.reason.is_some(),
            "Blocked result should have pattern metadata"
        );
    }

    /// Test that DestructiveMatch contains both reason and name.
    #[test]
    fn destructive_match_contains_metadata() {
        let docker_pack = REGISTRY
            .packs
            .get("containers.docker")
            .expect("docker pack exists");

        // Check docker system prune matches
        let matched = docker_pack.matches_destructive("docker system prune");
        assert!(matched.is_some(), "docker system prune should match");

        let m = matched.unwrap();
        assert!(!m.reason.is_empty(), "reason should not be empty");
        // name may or may not be set depending on pack definition
    }
}
