//! Git/filesystem safety guard for Claude Code.
//!
//! Blocks destructive commands that can lose uncommitted work or delete files.
//! This hook runs before Bash commands execute and can deny dangerous operations.
//!
//! Exit behavior:
//!   - Exit 0 with JSON {"hookSpecificOutput": {"permissionDecision": "deny", ...}} = block
//!   - Exit 0 with no output = allow

use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::sync::LazyLock;

#[derive(Deserialize)]
struct HookInput {
    tool_name: Option<String>,
    tool_input: Option<ToolInput>,
}

#[derive(Deserialize)]
struct ToolInput {
    command: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookSpecificOutput,
}

#[derive(Serialize)]
struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'static str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: String,
}

struct Pattern {
    regex: Regex,
    #[allow(dead_code)]
    name: &'static str,
}

struct DestructivePattern {
    regex: Regex,
    reason: &'static str,
}

macro_rules! pattern {
    ($name:literal, $re:literal) => {
        Pattern {
            regex: Regex::new($re).expect(concat!("pattern '", $name, "' should compile")),
            name: $name,
        }
    };
}

macro_rules! destructive {
    ($re:literal, $reason:literal) => {
        DestructivePattern {
            regex: Regex::new($re).expect(concat!("destructive pattern should compile: ", $re)),
            reason: $reason,
        }
    };
}

static SAFE_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        pattern!("checkout-new-branch", r"git\s+checkout\s+-b\s+"),
        pattern!("checkout-orphan", r"git\s+checkout\s+--orphan\s+"),
        pattern!(
            "restore-staged-long",
            r"git\s+restore\s+--staged\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        pattern!(
            "restore-staged-short",
            r"git\s+restore\s+-S\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        pattern!("clean-dry-run-short", r"git\s+clean\s+-[a-z]*n[a-z]*"),
        pattern!("clean-dry-run-long", r"git\s+clean\s+--dry-run"),
        pattern!("rm-rf-tmp-1", r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/tmp/"),
        pattern!("rm-fr-tmp-1", r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/tmp/"),
        pattern!(
            "rm-rf-var-tmp-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/var/tmp/"
        ),
        pattern!(
            "rm-fr-var-tmp-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/var/tmp/"
        ),
        pattern!(
            "rm-rf-tmpdir-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$TMPDIR/"
        ),
        pattern!(
            "rm-fr-tmpdir-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$TMPDIR/"
        ),
        pattern!(
            "rm-rf-tmpdir-brace-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$\{TMPDIR"
        ),
        pattern!(
            "rm-fr-tmpdir-brace-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$\{TMPDIR"
        ),
        pattern!(
            "rm-rf-tmpdir-quoted-1",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$TMPDIR/"#
        ),
        pattern!(
            "rm-fr-tmpdir-quoted-1",
            r#"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$TMPDIR/"#
        ),
        pattern!(
            "rm-rf-tmpdir-brace-quoted-1",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$\{TMPDIR"#
        ),
        pattern!(
            "rm-fr-tmpdir-brace-quoted-1",
            r#"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$\{TMPDIR"#
        ),
        pattern!(
            "rm-r-f-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/tmp/"
        ),
        pattern!(
            "rm-f-r-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/tmp/"
        ),
        pattern!(
            "rm-r-f-var-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/var/tmp/"
        ),
        pattern!(
            "rm-f-r-var-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/var/tmp/"
        ),
        pattern!(
            "rm-recursive-force-tmp",
            r"rm\s+.*--recursive.*--force\s+/tmp/"
        ),
        pattern!(
            "rm-force-recursive-tmp",
            r"rm\s+.*--force.*--recursive\s+/tmp/"
        ),
        pattern!(
            "rm-recursive-force-var-tmp",
            r"rm\s+.*--recursive.*--force\s+/var/tmp/"
        ),
        pattern!(
            "rm-force-recursive-var-tmp",
            r"rm\s+.*--force.*--recursive\s+/var/tmp/"
        ),
    ]
});

static DESTRUCTIVE_PATTERNS: LazyLock<Vec<DestructivePattern>> = LazyLock::new(|| {
    vec![
        destructive!(
            r"git\s+checkout\s+--\s+",
            "git checkout -- discards uncommitted changes permanently. Use 'git stash' first."
        ),
        destructive!(
            r"git\s+checkout\s+(?!-b\b)(?!--orphan\b)[^\s]+\s+--\s+",
            "git checkout <ref> -- <path> overwrites working tree. Use 'git stash' first."
        ),
        destructive!(
            r"git\s+restore\s+(?!--staged\b)(?!-S\b)",
            "git restore discards uncommitted changes. Use 'git stash' or 'git diff' first."
        ),
        destructive!(
            r"git\s+restore\s+.*(?:--worktree|-W\b)",
            "git restore --worktree/-W discards uncommitted changes permanently."
        ),
        destructive!(
            r"git\s+reset\s+--hard",
            "git reset --hard destroys uncommitted changes. Use 'git stash' first."
        ),
        destructive!(
            r"git\s+reset\s+--merge",
            "git reset --merge can lose uncommitted changes."
        ),
        destructive!(
            r"git\s+clean\s+-[a-z]*f",
            "git clean -f removes untracked files permanently. Review with 'git clean -n' first."
        ),
        destructive!(
            r"git\s+push\s+.*--force(?![-a-z])",
            "Force push can destroy remote history. Use --force-with-lease if necessary."
        ),
        destructive!(
            r"git\s+push\s+.*-f\b",
            "Force push (-f) can destroy remote history. Use --force-with-lease if necessary."
        ),
        destructive!(
            r"git\s+branch\s+-D\b",
            "git branch -D force-deletes without merge check. Use -d for safety."
        ),
        destructive!(
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+[/~]|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+[/~]",
            "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed."
        ),
        destructive!(
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]",
            "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually."
        ),
        destructive!(
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]",
            "rm with separate -r -f flags is destructive and requires human approval."
        ),
        destructive!(
            r"rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive",
            "rm --recursive --force is destructive and requires human approval."
        ),
        destructive!(
            r"git\s+stash\s+drop",
            "git stash drop permanently deletes stashed changes. List stashes first."
        ),
        destructive!(
            r"git\s+stash\s+clear",
            "git stash clear permanently deletes ALL stashed changes."
        ),
    ]
});

static PATH_NORMALIZER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/(?:\S*/)*s?bin/(rm|git)(?=\s|$)").unwrap());

fn normalize_command(cmd: &str) -> String {
    PATH_NORMALIZER.replace(cmd, "$1").into_owned()
}

fn quick_reject(cmd: &str) -> bool {
    !(cmd.contains("git") || cmd.contains("rm"))
}

fn deny(original_command: &str, reason: &str) {
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: "deny",
            permission_decision_reason: format!(
                "BLOCKED by git_safety_guard\n\n\
                 Reason: {reason}\n\n\
                 Command: {original_command}\n\n\
                 If this operation is truly needed, ask the user for explicit \
                 permission and have them run the command manually."
            ),
        },
    };
    println!("{}", serde_json::to_string(&output).unwrap());
}

fn main() {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        return;
    }

    let Ok(hook_input) = serde_json::from_str::<HookInput>(&input) else {
        return;
    };

    if hook_input.tool_name.as_deref() != Some("Bash") {
        return;
    }

    let Some(tool_input) = hook_input.tool_input else {
        return;
    };

    let Some(command_value) = tool_input.command else {
        return;
    };

    let serde_json::Value::String(command) = command_value else {
        return;
    };

    if command.is_empty() {
        return;
    }

    if quick_reject(&command) {
        return;
    }

    let normalized = normalize_command(&command);

    for pattern in SAFE_PATTERNS.iter() {
        if pattern.regex.is_match(&normalized).unwrap_or(false) {
            return;
        }
    }

    for pattern in DESTRUCTIVE_PATTERNS.iter() {
        if pattern.regex.is_match(&normalized).unwrap_or(false) {
            deny(&command, pattern.reason);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod normalize_command_tests {
        use super::*;

        #[test]
        fn preserves_plain_git_command() {
            assert_eq!(normalize_command("git status"), "git status");
        }

        #[test]
        fn preserves_plain_rm_command() {
            assert_eq!(normalize_command("rm -rf /tmp/foo"), "rm -rf /tmp/foo");
        }

        #[test]
        fn strips_usr_bin_git() {
            assert_eq!(normalize_command("/usr/bin/git status"), "git status");
        }

        #[test]
        fn strips_usr_local_bin_git() {
            assert_eq!(
                normalize_command("/usr/local/bin/git checkout -b feature"),
                "git checkout -b feature"
            );
        }

        #[test]
        fn strips_bin_rm() {
            assert_eq!(normalize_command("/bin/rm -rf /tmp/test"), "rm -rf /tmp/test");
        }

        #[test]
        fn strips_usr_bin_rm() {
            assert_eq!(normalize_command("/usr/bin/rm file.txt"), "rm file.txt");
        }

        #[test]
        fn strips_sbin_path() {
            assert_eq!(normalize_command("/sbin/rm foo"), "rm foo");
        }

        #[test]
        fn strips_usr_sbin_path() {
            assert_eq!(normalize_command("/usr/sbin/rm bar"), "rm bar");
        }

        #[test]
        fn preserves_command_with_path_arguments() {
            assert_eq!(
                normalize_command("git add /usr/bin/something"),
                "git add /usr/bin/something"
            );
        }

        #[test]
        fn handles_empty_string() {
            assert_eq!(normalize_command(""), "");
        }
    }

    mod quick_reject_tests {
        use super::*;

        #[test]
        fn rejects_commands_without_git_or_rm() {
            assert!(quick_reject("ls -la"));
            assert!(quick_reject("cat file.txt"));
            assert!(quick_reject("echo hello"));
            assert!(quick_reject("cargo build"));
            assert!(quick_reject("npm install"));
        }

        #[test]
        fn does_not_reject_git_commands() {
            assert!(!quick_reject("git status"));
            assert!(!quick_reject("git checkout main"));
            assert!(!quick_reject("/usr/bin/git log"));
        }

        #[test]
        fn does_not_reject_rm_commands() {
            assert!(!quick_reject("rm file.txt"));
            assert!(!quick_reject("rm -rf /tmp/test"));
            assert!(!quick_reject("/bin/rm foo"));
        }

        #[test]
        fn does_not_reject_when_git_in_argument() {
            assert!(!quick_reject("cat .git/config"));
            assert!(!quick_reject("ls .gitignore"));
        }

        #[test]
        fn handles_empty_string() {
            assert!(quick_reject(""));
        }
    }

    mod safe_pattern_tests {
        use super::*;

        fn is_safe(cmd: &str) -> bool {
            let normalized = normalize_command(cmd);
            SAFE_PATTERNS
                .iter()
                .any(|p| p.regex.is_match(&normalized).unwrap_or(false))
        }

        #[test]
        fn allows_checkout_new_branch() {
            assert!(is_safe("git checkout -b feature-branch"));
            assert!(is_safe("git checkout -b fix/bug-123"));
        }

        #[test]
        fn allows_checkout_orphan() {
            assert!(is_safe("git checkout --orphan gh-pages"));
            assert!(is_safe("git checkout --orphan new-root"));
        }

        #[test]
        fn allows_restore_staged_only() {
            assert!(is_safe("git restore --staged file.txt"));
            assert!(is_safe("git restore -S file.txt"));
            assert!(is_safe("git restore --staged ."));
        }

        #[test]
        fn rejects_restore_staged_with_worktree() {
            assert!(!is_safe("git restore --staged --worktree file.txt"));
            assert!(!is_safe("git restore --staged -W file.txt"));
            assert!(!is_safe("git restore -S --worktree file.txt"));
            assert!(!is_safe("git restore -S -W file.txt"));
        }

        #[test]
        fn allows_clean_dry_run() {
            assert!(is_safe("git clean -n"));
            assert!(is_safe("git clean -dn"));
            assert!(is_safe("git clean -nd"));
            assert!(is_safe("git clean --dry-run"));
        }

        #[test]
        fn allows_rm_rf_in_tmp() {
            assert!(is_safe("rm -rf /tmp/test"));
            assert!(is_safe("rm -rf /tmp/build-artifacts"));
            assert!(is_safe("rm -Rf /tmp/cache"));
            assert!(is_safe("rm -fr /tmp/stuff"));
            assert!(is_safe("rm -fR /tmp/more"));
        }

        #[test]
        fn allows_rm_rf_in_var_tmp() {
            assert!(is_safe("rm -rf /var/tmp/test"));
            assert!(is_safe("rm -fr /var/tmp/cache"));
        }

        #[test]
        fn allows_rm_rf_with_tmpdir_variable() {
            assert!(is_safe("rm -rf $TMPDIR/test"));
            assert!(is_safe("rm -rf ${TMPDIR}/test"));
            assert!(is_safe("rm -rf \"$TMPDIR/test\""));
            assert!(is_safe("rm -rf \"${TMPDIR}/test\""));
        }

        #[test]
        fn allows_rm_with_separate_flags_in_tmp() {
            assert!(is_safe("rm -r -f /tmp/test"));
            assert!(is_safe("rm -f -r /tmp/test"));
            assert!(is_safe("rm -r -f /var/tmp/test"));
            assert!(is_safe("rm -f -r /var/tmp/test"));
        }

        #[test]
        fn allows_rm_with_long_flags_in_tmp() {
            assert!(is_safe("rm --recursive --force /tmp/test"));
            assert!(is_safe("rm --force --recursive /tmp/test"));
            assert!(is_safe("rm --recursive --force /var/tmp/test"));
            assert!(is_safe("rm --force --recursive /var/tmp/test"));
        }
    }

    mod destructive_pattern_tests {
        use super::*;

        fn is_destructive(cmd: &str) -> Option<&'static str> {
            let normalized = normalize_command(cmd);
            for pattern in SAFE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return None;
                }
            }
            for pattern in DESTRUCTIVE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return Some(pattern.reason);
                }
            }
            None
        }

        #[test]
        fn blocks_git_checkout_dash_dash() {
            let result = is_destructive("git checkout -- file.txt");
            assert!(result.is_some());
            assert!(result.unwrap().contains("discard"));
        }

        #[test]
        fn blocks_git_checkout_ref_dash_dash_path() {
            let result = is_destructive("git checkout HEAD -- file.txt");
            assert!(result.is_some());
        }

        #[test]
        fn blocks_git_restore_without_staged() {
            let result = is_destructive("git restore file.txt");
            assert!(result.is_some());
            assert!(result.unwrap().contains("discard"));
        }

        #[test]
        fn blocks_git_restore_with_worktree() {
            assert!(is_destructive("git restore --worktree file.txt").is_some());
            assert!(is_destructive("git restore -W file.txt").is_some());
        }

        #[test]
        fn blocks_git_reset_hard() {
            let result = is_destructive("git reset --hard");
            assert!(result.is_some());
            assert!(result.unwrap().contains("destroys"));
        }

        #[test]
        fn blocks_git_reset_hard_with_ref() {
            assert!(is_destructive("git reset --hard HEAD~1").is_some());
            assert!(is_destructive("git reset --hard origin/main").is_some());
        }

        #[test]
        fn blocks_git_reset_merge() {
            let result = is_destructive("git reset --merge");
            assert!(result.is_some());
        }

        #[test]
        fn blocks_git_clean_force() {
            let result = is_destructive("git clean -f");
            assert!(result.is_some());
            assert!(result.unwrap().contains("untracked"));
        }

        #[test]
        fn blocks_git_clean_df() {
            assert!(is_destructive("git clean -df").is_some());
            assert!(is_destructive("git clean -fd").is_some());
        }

        #[test]
        fn blocks_git_push_force() {
            let result = is_destructive("git push --force");
            assert!(result.is_some());
            assert!(result.unwrap().contains("remote history"));

            assert!(is_destructive("git push origin main --force").is_some());
            assert!(is_destructive("git push --force origin main").is_some());
        }

        #[test]
        fn blocks_git_push_f() {
            assert!(is_destructive("git push -f").is_some());
            assert!(is_destructive("git push origin main -f").is_some());
        }

        #[test]
        fn blocks_git_branch_force_delete() {
            let result = is_destructive("git branch -D feature-branch");
            assert!(result.is_some());
            assert!(result.unwrap().contains("force-delete"));
        }

        #[test]
        fn blocks_rm_rf_on_root_paths() {
            assert!(is_destructive("rm -rf /").is_some());
            assert!(is_destructive("rm -rf /etc").is_some());
            assert!(is_destructive("rm -rf /home").is_some());
            assert!(is_destructive("rm -rf ~/").is_some());
            assert!(is_destructive("rm -rf ~/Documents").is_some());
        }

        #[test]
        fn blocks_rm_rf_outside_safe_dirs() {
            assert!(is_destructive("rm -rf ./build").is_some());
            assert!(is_destructive("rm -rf node_modules").is_some());
        }

        #[test]
        fn blocks_rm_with_separate_rf_flags() {
            assert!(is_destructive("rm -r -f ./build").is_some());
            assert!(is_destructive("rm -f -r ./build").is_some());
        }

        #[test]
        fn blocks_rm_with_long_flags() {
            assert!(is_destructive("rm --recursive --force ./build").is_some());
            assert!(is_destructive("rm --force --recursive ./build").is_some());
        }

        #[test]
        fn blocks_git_stash_drop() {
            let result = is_destructive("git stash drop");
            assert!(result.is_some());
            assert!(result.unwrap().contains("stash"));
        }

        #[test]
        fn blocks_git_stash_drop_with_ref() {
            assert!(is_destructive("git stash drop stash@{0}").is_some());
            assert!(is_destructive("git stash drop 1").is_some());
        }

        #[test]
        fn blocks_git_stash_clear() {
            let result = is_destructive("git stash clear");
            assert!(result.is_some());
            assert!(result.unwrap().contains("ALL stashed"));
        }

        #[test]
        fn allows_safe_git_commands() {
            assert!(is_destructive("git status").is_none());
            assert!(is_destructive("git log").is_none());
            assert!(is_destructive("git diff").is_none());
            assert!(is_destructive("git add .").is_none());
            assert!(is_destructive("git commit -m 'test'").is_none());
            assert!(is_destructive("git push").is_none());
            assert!(is_destructive("git pull").is_none());
            assert!(is_destructive("git fetch").is_none());
            assert!(is_destructive("git branch -d feature").is_none());
            assert!(is_destructive("git stash").is_none());
            assert!(is_destructive("git stash pop").is_none());
            assert!(is_destructive("git stash list").is_none());
        }

        #[test]
        fn allows_push_with_force_with_lease() {
            assert!(is_destructive("git push --force-with-lease").is_none());
            assert!(is_destructive("git push origin main --force-with-lease").is_none());
        }
    }

    mod input_parsing_tests {
        use super::*;

        fn parse_and_get_command(json: &str) -> Option<String> {
            let hook_input: HookInput = serde_json::from_str(json).ok()?;
            if hook_input.tool_name.as_deref() != Some("Bash") {
                return None;
            }
            let tool_input = hook_input.tool_input?;
            let command_value = tool_input.command?;
            match command_value {
                serde_json::Value::String(s) if !s.is_empty() => Some(s),
                _ => None,
            }
        }

        #[test]
        fn parses_valid_bash_input() {
            let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status"}}"#;
            assert_eq!(parse_and_get_command(json), Some("git status".to_string()));
        }

        #[test]
        fn rejects_non_bash_tool() {
            let json = r#"{"tool_name": "Read", "tool_input": {"command": "git status"}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_missing_tool_name() {
            let json = r#"{"tool_input": {"command": "git status"}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_missing_tool_input() {
            let json = r#"{"tool_name": "Bash"}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_missing_command() {
            let json = r#"{"tool_name": "Bash", "tool_input": {}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_empty_command() {
            let json = r#"{"tool_name": "Bash", "tool_input": {"command": ""}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_non_string_command() {
            let json = r#"{"tool_name": "Bash", "tool_input": {"command": 123}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_invalid_json() {
            assert_eq!(parse_and_get_command("not json"), None);
            assert_eq!(parse_and_get_command("{invalid}"), None);
        }
    }

    mod deny_output_tests {
        use super::*;

        fn capture_deny_output(command: &str, reason: &str) -> HookOutput {
            HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse",
                    permission_decision: "deny",
                    permission_decision_reason: format!(
                        "BLOCKED by git_safety_guard\n\n\
                         Reason: {reason}\n\n\
                         Command: {command}\n\n\
                         If this operation is truly needed, ask the user for explicit \
                         permission and have them run the command manually."
                    ),
                },
            }
        }

        #[test]
        fn deny_output_has_correct_structure() {
            let output = capture_deny_output("git reset --hard", "test reason");
            let json = serde_json::to_string(&output).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

            assert_eq!(
                parsed["hookSpecificOutput"]["hookEventName"],
                "PreToolUse"
            );
            assert_eq!(
                parsed["hookSpecificOutput"]["permissionDecision"],
                "deny"
            );
            assert!(parsed["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("git reset --hard"));
            assert!(parsed["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("test reason"));
        }

        #[test]
        fn deny_output_is_valid_json() {
            let output = capture_deny_output("rm -rf /", "dangerous");
            let json = serde_json::to_string(&output).unwrap();
            assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
        }
    }

    mod integration_tests {
        use super::*;

        fn would_block(cmd: &str) -> bool {
            if quick_reject(cmd) {
                return false;
            }
            let normalized = normalize_command(cmd);
            for pattern in SAFE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return false;
                }
            }
            for pattern in DESTRUCTIVE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return true;
                }
            }
            false
        }

        #[test]
        fn full_pipeline_blocks_dangerous_commands() {
            assert!(would_block("git reset --hard"));
            assert!(would_block("git checkout -- ."));
            assert!(would_block("rm -rf ~/"));
            assert!(would_block("/usr/bin/git reset --hard HEAD"));
            assert!(would_block("/bin/rm -rf /etc"));
        }

        #[test]
        fn full_pipeline_allows_safe_commands() {
            assert!(!would_block("git status"));
            assert!(!would_block("git checkout -b feature"));
            assert!(!would_block("rm -rf /tmp/build"));
            assert!(!would_block("ls -la"));
            assert!(!would_block("cargo build"));
            assert!(!would_block("git clean -n"));
        }

        #[test]
        fn full_pipeline_with_absolute_paths() {
            assert!(would_block("/usr/bin/git reset --hard"));
            assert!(!would_block("/usr/bin/git checkout -b feature"));
            assert!(would_block("/bin/rm -rf /home/user"));
            assert!(!would_block("/bin/rm -rf /tmp/cache"));
        }
    }
}
