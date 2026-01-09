//! Simulation input parsing for `dcg simulate`.
//!
//! This module provides streaming, line-by-line parsing of command logs
//! for replay/simulation against dcg policy. It supports multiple input
//! formats with conservative auto-detection.
//!
//! # Supported input formats
//!
//! 1. **Plain command** - The entire line is a shell command
//! 2. **Hook JSON** - `{"tool_name":"Bash","tool_input":{"command":"..."}}`
//! 3. **Structured decision log** - Schema-versioned log entries (future)
//!
//! # Design principles
//!
//! - **Streaming**: Process line-by-line, never load entire file into memory
//! - **Conservative**: Ambiguous lines are treated as malformed, not guessed
//! - **Deterministic**: Same line always produces same format classification
//! - **Panic-free**: Parser never panics on arbitrary input

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read};

/// Schema version for simulate output (for future compatibility).
pub const SIMULATE_SCHEMA_VERSION: u32 = 1;

/// Input format detected for a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulateInputFormat {
    /// Plain command string (the entire line is the command)
    PlainCommand,
    /// Hook JSON: `{"tool_name":"Bash","tool_input":{"command":"..."}}`
    HookJson,
    /// Structured decision log entry (schema-versioned)
    DecisionLog,
}

/// Result of parsing a single line.
#[derive(Debug, Clone)]
pub enum ParsedLine {
    /// Successfully parsed command with its detected format
    Command {
        command: String,
        format: SimulateInputFormat,
    },
    /// Line should be ignored (e.g., non-Bash tool in hook JSON)
    Ignore { reason: &'static str },
    /// Line could not be parsed
    Malformed { error: String },
    /// Empty or whitespace-only line
    Empty,
}

/// Limits for the streaming parser.
#[derive(Debug, Clone)]
pub struct SimulateLimits {
    /// Maximum number of lines to process (None = unlimited)
    pub max_lines: Option<usize>,
    /// Maximum total bytes to read (None = unlimited)
    pub max_bytes: Option<usize>,
    /// Maximum command length in bytes (longer commands are truncated/skipped)
    pub max_command_bytes: Option<usize>,
}

impl Default for SimulateLimits {
    fn default() -> Self {
        Self {
            max_lines: None,
            max_bytes: None,
            max_command_bytes: Some(64 * 1024), // 64KB default max command
        }
    }
}

/// Statistics from parsing.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ParseStats {
    /// Total lines read
    pub lines_read: usize,
    /// Total bytes read
    pub bytes_read: usize,
    /// Number of commands extracted
    pub commands_extracted: usize,
    /// Number of malformed lines
    pub malformed_count: usize,
    /// Number of ignored lines (e.g., non-Bash tools)
    pub ignored_count: usize,
    /// Number of empty lines
    pub empty_count: usize,
    /// Whether parsing stopped due to limits
    pub stopped_at_limit: bool,
    /// Which limit was hit (if any)
    pub limit_hit: Option<LimitHit>,
}

/// Which limit caused parsing to stop.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitHit {
    MaxLines,
    MaxBytes,
}

/// Streaming parser for simulate input.
///
/// Processes input line-by-line with configurable limits.
pub struct SimulateParser<R: Read> {
    reader: BufReader<R>,
    limits: SimulateLimits,
    stats: ParseStats,
    strict: bool,
}

impl<R: Read> SimulateParser<R> {
    /// Create a new parser with the given reader and limits.
    pub fn new(reader: R, limits: SimulateLimits) -> Self {
        Self {
            reader: BufReader::new(reader),
            limits,
            stats: ParseStats::default(),
            strict: false,
        }
    }

    /// Enable strict mode (return error on first malformed line).
    #[must_use]
    pub const fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Get current parsing statistics.
    pub const fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// Consume the parser and return final statistics.
    pub fn into_stats(self) -> ParseStats {
        self.stats
    }

    /// Parse the next line from input.
    ///
    /// Returns `None` when input is exhausted or a limit is reached.
    /// Returns `Some(Err(...))` in strict mode when a malformed line is encountered.
    pub fn next_line(&mut self) -> Option<Result<ParsedLine, ParseError>> {
        // Check limits before reading
        if let Some(max_lines) = self.limits.max_lines {
            if self.stats.lines_read >= max_lines {
                self.stats.stopped_at_limit = true;
                self.stats.limit_hit = Some(LimitHit::MaxLines);
                return None;
            }
        }

        if let Some(max_bytes) = self.limits.max_bytes {
            if self.stats.bytes_read >= max_bytes {
                self.stats.stopped_at_limit = true;
                self.stats.limit_hit = Some(LimitHit::MaxBytes);
                return None;
            }
        }

        // Read next line
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => return None, // EOF
            Ok(n) => {
                self.stats.lines_read += 1;
                self.stats.bytes_read += n;
            }
            Err(e) => {
                return Some(Err(ParseError::Io(e.to_string())));
            }
        }

        // Parse the line
        let parsed = parse_line(&line, self.limits.max_command_bytes);

        // Update stats
        match &parsed {
            ParsedLine::Command { .. } => self.stats.commands_extracted += 1,
            ParsedLine::Malformed { error } => {
                self.stats.malformed_count += 1;
                if self.strict {
                    return Some(Err(ParseError::Malformed {
                        line: self.stats.lines_read,
                        error: error.clone(),
                    }));
                }
            }
            ParsedLine::Ignore { .. } => self.stats.ignored_count += 1,
            ParsedLine::Empty => self.stats.empty_count += 1,
        }

        Some(Ok(parsed))
    }

    /// Collect all parsed commands (for small inputs).
    ///
    /// Returns commands and final stats. In strict mode, stops on first error.
    ///
    /// # Errors
    ///
    /// Returns `ParseError::Io` on I/O failures, or `ParseError::Malformed` in strict
    /// mode when encountering an unparseable line.
    pub fn collect_commands(mut self) -> Result<(Vec<ParsedCommand>, ParseStats), ParseError> {
        let mut commands = Vec::new();

        while let Some(result) = self.next_line() {
            match result? {
                ParsedLine::Command { command, format } => {
                    commands.push(ParsedCommand {
                        command,
                        format,
                        line_number: self.stats.lines_read,
                    });
                }
                ParsedLine::Ignore { .. } | ParsedLine::Malformed { .. } | ParsedLine::Empty => {
                    // Continue (stats already updated)
                }
            }
        }

        Ok((commands, self.stats))
    }
}

/// Iterator adapter for `SimulateParser`.
impl<R: Read> Iterator for SimulateParser<R> {
    type Item = Result<ParsedLine, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_line()
    }
}

/// A successfully parsed command with metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedCommand {
    /// The extracted command string
    pub command: String,
    /// Detected input format
    pub format: SimulateInputFormat,
    /// Line number in the input (1-indexed)
    pub line_number: usize,
}

/// Errors that can occur during parsing.
#[derive(Debug, Clone)]
pub enum ParseError {
    /// I/O error reading input
    Io(String),
    /// Malformed line in strict mode
    Malformed { line: usize, error: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Malformed { line, error } => write!(f, "Line {line}: {error}"),
        }
    }
}

impl std::error::Error for ParseError {}

// =============================================================================
// Line parsing implementation
// =============================================================================

/// Parse a single line and detect its format.
fn parse_line(line: &str, max_command_bytes: Option<usize>) -> ParsedLine {
    let trimmed = line.trim();

    // Empty line
    if trimmed.is_empty() {
        return ParsedLine::Empty;
    }

    // Try Decision Log format first (unambiguous prefix)
    if trimmed.starts_with("DCG_LOG_V") {
        return parse_decision_log(trimmed, max_command_bytes);
    }

    // Try Hook JSON format (starts with '{' and parses as valid hook JSON)
    // Note: Shell brace blocks like `{ echo hello; }` also start with '{',
    // so we must fall back to plain command if JSON parsing fails.
    if trimmed.starts_with('{') {
        if let Some(result) = try_parse_hook_json(trimmed, max_command_bytes) {
            return result;
        }
        // Not valid hook JSON, treat as plain command (e.g., shell brace block)
        return parse_plain_command(trimmed, max_command_bytes);
    }

    // Default: treat as plain command
    parse_plain_command(trimmed, max_command_bytes)
}

/// Try to parse a line as hook JSON format.
///
/// Returns `Some(ParsedLine)` if this is valid hook JSON (including Malformed for missing fields),
/// or `None` if the line is not valid JSON (should fall back to plain command).
fn try_parse_hook_json(line: &str, max_command_bytes: Option<usize>) -> Option<ParsedLine> {
    // Minimal JSON structure we expect:
    // {"tool_name":"Bash","tool_input":{"command":"..."}}

    #[derive(Deserialize)]
    struct HookInput {
        tool_name: String,
        tool_input: Option<ToolInput>,
    }

    #[derive(Deserialize)]
    struct ToolInput {
        command: Option<String>,
    }

    // Try to parse as JSON - if it fails, return None to fall back to plain command
    let input: HookInput = serde_json::from_str(line).ok()?;

    // At this point we have valid JSON with tool_name, so treat it as hook format
    // (even if it's malformed, it's still hook JSON, not a plain command)

    // Check if it's a Bash tool
    if input.tool_name != "Bash" {
        return Some(ParsedLine::Ignore {
            reason: "non-Bash tool",
        });
    }

    // Extract command - if missing, it's malformed hook JSON (not a plain command)
    let Some(tool_input) = input.tool_input else {
        return Some(ParsedLine::Malformed {
            error: "missing tool_input".to_string(),
        });
    };

    let Some(command) = tool_input.command else {
        return Some(ParsedLine::Malformed {
            error: "missing command in tool_input".to_string(),
        });
    };

    // Check command length limit
    if let Some(max_bytes) = max_command_bytes {
        if command.len() > max_bytes {
            return Some(ParsedLine::Malformed {
                error: format!(
                    "command exceeds max length ({} > {max_bytes} bytes)",
                    command.len()
                ),
            });
        }
    }

    Some(ParsedLine::Command {
        command,
        format: SimulateInputFormat::HookJson,
    })
}

/// Parse a line as decision log format (future schema).
fn parse_decision_log(line: &str, max_command_bytes: Option<usize>) -> ParsedLine {
    use base64::Engine;

    // Decision log format (v1):
    // DCG_LOG_V1|timestamp|decision|command_base64|...
    //
    // For now, we'll implement a simple version.

    let parts: Vec<&str> = line.splitn(5, '|').collect();

    if parts.len() < 4 {
        return ParsedLine::Malformed {
            error: "invalid decision log format (expected at least 4 pipe-separated fields)"
                .to_string(),
        };
    }

    let version = parts[0];
    if version != "DCG_LOG_V1" {
        return ParsedLine::Malformed {
            error: format!("unsupported log version: {version}"),
        };
    }

    // parts[1] = timestamp (ignored for now)
    // parts[2] = decision (allow/deny/warn - ignored for replay)
    // parts[3] = command (base64 encoded)

    let command_b64 = parts[3];

    // Decode base64
    let command = match base64::engine::general_purpose::STANDARD.decode(command_b64) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                return ParsedLine::Malformed {
                    error: "command is not valid UTF-8".to_string(),
                };
            }
        },
        Err(e) => {
            return ParsedLine::Malformed {
                error: format!("invalid base64 in command field: {e}"),
            };
        }
    };

    // Check command length limit
    if let Some(max_bytes) = max_command_bytes {
        if command.len() > max_bytes {
            return ParsedLine::Malformed {
                error: format!(
                    "command exceeds max length ({} > {max_bytes} bytes)",
                    command.len()
                ),
            };
        }
    }

    ParsedLine::Command {
        command,
        format: SimulateInputFormat::DecisionLog,
    }
}

/// Parse a line as a plain command string.
fn parse_plain_command(line: &str, max_command_bytes: Option<usize>) -> ParsedLine {
    // Check command length limit
    if let Some(max_bytes) = max_command_bytes {
        if line.len() > max_bytes {
            return ParsedLine::Malformed {
                error: format!(
                    "command exceeds max length ({} > {max_bytes} bytes)",
                    line.len()
                ),
            };
        }
    }

    ParsedLine::Command {
        command: line.to_string(),
        format: SimulateInputFormat::PlainCommand,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Format detection tests
    // -------------------------------------------------------------------------

    #[test]
    fn detect_plain_command() {
        let result = parse_line("git status --short", None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "git status --short");
                assert_eq!(format, SimulateInputFormat::PlainCommand);
            }
            _ => panic!("expected Command, got {result:?}"),
        }
    }

    #[test]
    fn detect_hook_json_bash() {
        let line = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let result = parse_line(line, None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "git status");
                assert_eq!(format, SimulateInputFormat::HookJson);
            }
            _ => panic!("expected Command, got {result:?}"),
        }
    }

    #[test]
    fn detect_hook_json_non_bash_ignored() {
        let line = r#"{"tool_name":"Read","tool_input":{"path":"/etc/passwd"}}"#;
        let result = parse_line(line, None);
        match result {
            ParsedLine::Ignore { reason } => {
                assert_eq!(reason, "non-Bash tool");
            }
            _ => panic!("expected Ignore, got {result:?}"),
        }
    }

    #[test]
    fn detect_decision_log() {
        // "git status" in base64 = "Z2l0IHN0YXR1cw=="
        let line = "DCG_LOG_V1|2026-01-09T00:00:00Z|allow|Z2l0IHN0YXR1cw==|";
        let result = parse_line(line, None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "git status");
                assert_eq!(format, SimulateInputFormat::DecisionLog);
            }
            _ => panic!("expected Command, got {result:?}"),
        }
    }

    #[test]
    fn empty_line() {
        assert!(matches!(parse_line("", None), ParsedLine::Empty));
        assert!(matches!(parse_line("   ", None), ParsedLine::Empty));
        assert!(matches!(parse_line("\t\n", None), ParsedLine::Empty));
    }

    #[test]
    fn invalid_json_falls_back_to_plain_command() {
        // Invalid JSON starting with '{' should be treated as a plain command,
        // not malformed. This handles shell brace blocks like `{ echo hello; }`.
        let result = parse_line("{invalid json}", None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "{invalid json}");
                assert_eq!(format, SimulateInputFormat::PlainCommand);
            }
            _ => panic!("expected Command (PlainCommand), got {result:?}"),
        }
    }

    #[test]
    fn shell_brace_block_as_plain_command() {
        // Shell brace blocks should be treated as plain commands
        let result = parse_line("{ echo hello; } | cat", None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "{ echo hello; } | cat");
                assert_eq!(format, SimulateInputFormat::PlainCommand);
            }
            _ => panic!("expected Command (PlainCommand), got {result:?}"),
        }
    }

    #[test]
    fn valid_json_missing_command_is_malformed() {
        // Valid JSON with missing fields is still hook JSON format, just malformed
        // (not a plain command)
        let line = r#"{"tool_name":"Bash","tool_input":{}}"#;
        let result = parse_line(line, None);
        match result {
            ParsedLine::Malformed { error } => {
                assert!(error.contains("missing command"));
            }
            _ => panic!("expected Malformed, got {result:?}"),
        }
    }

    #[test]
    fn malformed_decision_log_wrong_version() {
        let line = "DCG_LOG_V99|timestamp|allow|cmd|";
        let result = parse_line(line, None);
        match result {
            ParsedLine::Malformed { error } => {
                assert!(error.contains("unsupported log version"));
            }
            _ => panic!("expected Malformed, got {result:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Limit tests
    // -------------------------------------------------------------------------

    #[test]
    fn command_length_limit() {
        let long_cmd = "x".repeat(1000);
        let result = parse_line(&long_cmd, Some(500));
        match result {
            ParsedLine::Malformed { error } => {
                assert!(error.contains("exceeds max length"));
            }
            _ => panic!("expected Malformed, got {result:?}"),
        }
    }

    #[test]
    fn command_within_limit() {
        let cmd = "git status";
        let result = parse_line(cmd, Some(500));
        assert!(matches!(result, ParsedLine::Command { .. }));
    }

    // -------------------------------------------------------------------------
    // Streaming parser tests
    // -------------------------------------------------------------------------

    #[test]
    fn parser_collects_commands() {
        let input = r#"git status
{"tool_name":"Bash","tool_input":{"command":"git log"}}
{"tool_name":"Read","tool_input":{"path":"file.txt"}}

echo hello
"#;

        let parser = SimulateParser::new(input.as_bytes(), SimulateLimits::default());
        let (commands, stats) = parser.collect_commands().unwrap();

        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0].command, "git status");
        assert_eq!(commands[0].format, SimulateInputFormat::PlainCommand);
        assert_eq!(commands[1].command, "git log");
        assert_eq!(commands[1].format, SimulateInputFormat::HookJson);
        assert_eq!(commands[2].command, "echo hello");

        assert_eq!(stats.lines_read, 5);
        assert_eq!(stats.commands_extracted, 3);
        assert_eq!(stats.ignored_count, 1); // Read tool
        assert_eq!(stats.empty_count, 1);
        assert_eq!(stats.malformed_count, 0);
    }

    #[test]
    fn parser_respects_line_limit() {
        let input = "line1\nline2\nline3\nline4\nline5\n";

        let limits = SimulateLimits {
            max_lines: Some(3),
            ..Default::default()
        };
        let parser = SimulateParser::new(input.as_bytes(), limits);
        let (commands, stats) = parser.collect_commands().unwrap();

        assert_eq!(commands.len(), 3);
        assert_eq!(stats.lines_read, 3);
        assert!(stats.stopped_at_limit);
        assert!(matches!(stats.limit_hit, Some(LimitHit::MaxLines)));
    }

    #[test]
    fn parser_strict_mode_fails_on_malformed() {
        // Use valid JSON with missing command field to trigger malformed error
        let input = r#"git status
{"tool_name":"Bash","tool_input":{}}
echo hello
"#;

        let parser = SimulateParser::new(input.as_bytes(), SimulateLimits::default()).strict(true);
        let result = parser.collect_commands();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ParseError::Malformed { line: 2, .. }));
    }

    #[test]
    fn parser_non_strict_continues_on_malformed() {
        // Use valid JSON with missing command field to trigger malformed error
        let input = r#"git status
{"tool_name":"Bash","tool_input":{}}
echo hello
"#;

        let parser = SimulateParser::new(input.as_bytes(), SimulateLimits::default()).strict(false);
        let (commands, stats) = parser.collect_commands().unwrap();

        assert_eq!(commands.len(), 2); // git status and echo hello
        assert_eq!(stats.malformed_count, 1);
    }

    #[test]
    fn parser_treats_invalid_json_as_plain_command() {
        // Invalid JSON (like shell brace blocks) should be treated as plain commands
        let input = r"git status
{ echo hello; }
echo world
";

        let parser = SimulateParser::new(input.as_bytes(), SimulateLimits::default());
        let (commands, stats) = parser.collect_commands().unwrap();

        assert_eq!(commands.len(), 3); // All three are plain commands
        assert_eq!(commands[1].command, "{ echo hello; }");
        assert_eq!(commands[1].format, SimulateInputFormat::PlainCommand);
        assert_eq!(stats.malformed_count, 0);
    }

    // -------------------------------------------------------------------------
    // Determinism test
    // -------------------------------------------------------------------------

    #[test]
    fn parsing_is_deterministic() {
        let lines = [
            "git status",
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            "{broken",
            "",
            "DCG_LOG_V1|ts|allow|Z2l0IHN0YXR1cw==|",
        ];

        // Parse each line 100 times and ensure same result
        for line in lines {
            let first = parse_line(line, None);
            for _ in 0..100 {
                let result = parse_line(line, None);
                assert_eq!(
                    format!("{first:?}"),
                    format!("{result:?}"),
                    "Non-deterministic parsing for: {line}"
                );
            }
        }
    }
}
