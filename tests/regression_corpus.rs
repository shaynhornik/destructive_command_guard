//! Regression corpus test harness.
//!
//! This module loads test cases from `tests/corpus/` and runs them through the evaluator,
//! comparing expected vs actual decisions.
//!
//! # Corpus Structure
//!
//! ```text
//! tests/corpus/
//!   true_positives/   # Commands that MUST be blocked (deny)
//!   false_positives/  # Commands that MUST be allowed (allow)
//!   bypass_attempts/  # Obfuscated dangerous commands (deny)
//!   edge_cases/       # Commands that must not crash (any decision ok)
//! ```
//!
//! # Test Case Format (TOML)
//!
//! ```toml
//! [[case]]
//! description = "git reset --hard blocks correctly"
//! command = "git reset --hard"
//! expected = "deny"  # or "allow"
//! rule_id = "core.git:reset-hard"  # optional
//! ```
//!
//! # Running
//!
//! ```bash
//! cargo test --test regression_corpus
//! ```

use std::fmt::Write;
use std::fs;
use std::path::Path;

use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    Config, EvaluationDecision, LayeredAllowlist, evaluate_command_with_pack_order,
};
use serde::Deserialize;

/// A single test case loaded from the corpus.
#[derive(Debug, Deserialize)]
struct TestCase {
    description: String,
    command: String,
    expected: String,
    #[serde(default)]
    rule_id: Option<String>,
}

/// A corpus file containing multiple test cases.
#[derive(Debug, Deserialize)]
struct CorpusFile {
    #[serde(rename = "case")]
    cases: Vec<TestCase>,
}

/// Category of test cases, determines pass/fail logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CorpusCategory {
    /// Commands that MUST be blocked (deny expected).
    TruePositives,
    /// Commands that MUST be allowed (allow expected).
    FalsePositives,
    /// Obfuscated/bypass commands that MUST be blocked.
    BypassAttempts,
    /// Edge cases that must not crash (any decision acceptable).
    EdgeCases,
}

/// Result of running a single test case.
#[derive(Debug)]
struct TestResult {
    description: String,
    #[allow(dead_code)] // Used in debug output
    command: String,
    expected: String,
    actual: String,
    rule_id: Option<String>,
    actual_rule_id: Option<String>,
    passed: bool,
    category: CorpusCategory,
}

/// Load and parse all corpus files from a directory.
fn load_corpus_files(corpus_dir: &Path) -> Vec<(CorpusCategory, Vec<TestCase>)> {
    let mut results = Vec::new();

    let categories = [
        "true_positives",
        "false_positives",
        "bypass_attempts",
        "edge_cases",
    ];

    for category_name in categories {
        let category_dir = corpus_dir.join(category_name);
        if !category_dir.exists() {
            continue;
        }

        let category = match category_name {
            "true_positives" => CorpusCategory::TruePositives,
            "false_positives" => CorpusCategory::FalsePositives,
            "bypass_attempts" => CorpusCategory::BypassAttempts,
            "edge_cases" => CorpusCategory::EdgeCases,
            _ => continue,
        };

        if let Ok(entries) = fs::read_dir(&category_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "toml") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        match toml::from_str::<CorpusFile>(&content) {
                            Ok(corpus) => results.push((category, corpus.cases)),
                            Err(e) => {
                                panic!("Failed to parse {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
        }
    }

    results
}

/// Run a single test case through the evaluator.
fn run_test_case(case: &TestCase, category: CorpusCategory) -> TestResult {
    // Use default config with core pack enabled
    let config = Config::default();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let compiled_overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();

    // Run through evaluator
    let result = evaluate_command_with_pack_order(
        &case.command,
        &enabled_keywords,
        &ordered_packs,
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
    );

    let actual = match result.decision {
        EvaluationDecision::Allow => "allow",
        EvaluationDecision::Deny => "deny",
    };

    // Extract rule_id from pattern_info (pack_id:pattern_name format)
    let actual_rule_id =
        result
            .pattern_info
            .as_ref()
            .map(|info| match (&info.pack_id, &info.pattern_name) {
                (Some(pack), Some(pattern)) => format!("{pack}:{pattern}"),
                (Some(pack), None) => pack.clone(),
                (None, Some(pattern)) => pattern.clone(),
                (None, None) => String::from("unknown"),
            });

    // Determine if test passed based on category
    let passed = match category {
        CorpusCategory::TruePositives | CorpusCategory::BypassAttempts => {
            // Must be denied
            actual == "deny"
        }
        CorpusCategory::FalsePositives => {
            // Must be allowed
            actual == "allow"
        }
        CorpusCategory::EdgeCases => {
            // Any decision is fine (didn't crash)
            true
        }
    };

    TestResult {
        description: case.description.clone(),
        command: case.command.clone(),
        expected: case.expected.clone(),
        actual: actual.to_string(),
        rule_id: case.rule_id.clone(),
        actual_rule_id,
        passed,
        category,
    }
}

/// Run all corpus tests and return results.
fn run_corpus_tests() -> Vec<TestResult> {
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let corpus_files = load_corpus_files(&corpus_dir);

    let mut results = Vec::new();
    for (category, cases) in corpus_files {
        for case in cases {
            results.push(run_test_case(&case, category));
        }
    }
    results
}

/// Format a single test result for display.
fn format_result(result: &TestResult) -> String {
    let status = if result.passed { "PASS" } else { "FAIL" };
    let rule_info = match (&result.rule_id, &result.actual_rule_id) {
        (Some(expected), Some(actual)) if expected == actual => {
            format!(" [rule: {actual}]")
        }
        (Some(expected), Some(actual)) => {
            format!(" [expected rule: {expected}, got: {actual}]")
        }
        (None, Some(actual)) => format!(" [rule: {actual}]"),
        (Some(expected), None) => format!(" [expected rule: {expected}, got: none]"),
        (None, None) => String::new(),
    };
    let category = result.category;
    let description = &result.description;
    let expected = &result.expected;
    let actual = &result.actual;

    format!(
        "[{status}] {category:?} - {description} | expected: {expected}, actual: {actual}{rule_info}"
    )
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn corpus_true_positives() {
    let results = run_corpus_tests();
    let true_positives: Vec<_> = results
        .iter()
        .filter(|r| r.category == CorpusCategory::TruePositives)
        .collect();

    let failures: Vec<_> = true_positives.iter().filter(|r| !r.passed).collect();

    if !failures.is_empty() {
        let mut msg = format!("\n{} true positive test(s) failed:\n", failures.len());
        for result in failures {
            let _ = writeln!(msg, "  {}", format_result(result));
        }
        panic!("{msg}");
    }

    println!("All {} true positive tests passed", true_positives.len());
}

#[test]
fn corpus_false_positives() {
    let results = run_corpus_tests();
    let false_positives: Vec<_> = results
        .iter()
        .filter(|r| r.category == CorpusCategory::FalsePositives)
        .collect();

    let failures: Vec<_> = false_positives.iter().filter(|r| !r.passed).collect();

    if !failures.is_empty() {
        let mut msg = format!("\n{} false positive test(s) failed:\n", failures.len());
        for result in failures {
            let _ = writeln!(msg, "  {}", format_result(result));
        }
        panic!("{msg}");
    }

    println!("All {} false positive tests passed", false_positives.len());
}

#[test]
fn corpus_bypass_attempts() {
    let results = run_corpus_tests();
    let bypass_attempts: Vec<_> = results
        .iter()
        .filter(|r| r.category == CorpusCategory::BypassAttempts)
        .collect();

    let failures: Vec<_> = bypass_attempts.iter().filter(|r| !r.passed).collect();

    if !failures.is_empty() {
        let mut msg = format!("\n{} bypass attempt test(s) failed:\n", failures.len());
        for result in failures {
            let _ = writeln!(msg, "  {}", format_result(result));
        }
        panic!("{msg}");
    }

    println!("All {} bypass attempt tests passed", bypass_attempts.len());
}

#[test]
fn corpus_edge_cases() {
    let results = run_corpus_tests();
    let edge_case_count = results
        .iter()
        .filter(|r| r.category == CorpusCategory::EdgeCases)
        .count();

    // Edge cases always pass if they don't crash
    println!("All {edge_case_count} edge case tests completed without crashing");
}

#[test]
fn corpus_summary() {
    let results = run_corpus_tests();

    let mut passed = 0;
    let mut failed = 0;
    let mut total_by_category: std::collections::HashMap<CorpusCategory, (usize, usize)> =
        std::collections::HashMap::new();

    for result in &results {
        let entry = total_by_category.entry(result.category).or_insert((0, 0));
        entry.0 += 1;
        if result.passed {
            passed += 1;
            entry.1 += 1;
        } else {
            failed += 1;
        }
    }

    println!("\n=== Corpus Test Summary ===");
    println!(
        "Total: {} tests ({} passed, {} failed)",
        results.len(),
        passed,
        failed
    );
    println!();

    for (category, (total, cat_passed)) in total_by_category {
        let status = if cat_passed == total { "OK" } else { "FAIL" };
        println!("  {category:?}: {cat_passed}/{total} [{status}]");
    }

    // Print all failures for debugging
    let failures: Vec<_> = results.iter().filter(|r| !r.passed).collect();
    if !failures.is_empty() {
        println!("\nFailures:");
        for result in failures {
            println!("  {}", format_result(result));
        }
    }
}
