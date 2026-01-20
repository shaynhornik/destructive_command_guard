#[test]
fn test_heredoc_masking_custom_path() {
    use destructive_command_guard::heredoc::mask_non_executing_heredocs;
    use std::borrow::Cow;

    // Standard path - should be masked
    let cmd_standard = "/usr/bin/cat <<EOF\nrm -rf /\nEOF";
    let masked_standard = mask_non_executing_heredocs(cmd_standard);
    assert_ne!(masked_standard, Cow::Borrowed(cmd_standard));
    assert!(masked_standard.contains("EOF"));
    assert!(!masked_standard.contains("rm -rf /"));

    // Custom path (e.g. NixOS or user local) - might fail to be detected as 'cat'
    // and thus not masked, leading to false positive blocks on the content.
    let cmd_custom = "/custom/path/to/bin/cat <<EOF\nrm -rf /\nEOF";
    let masked_custom = mask_non_executing_heredocs(cmd_custom);
    
    // If logic is too strict, this assertion will fail (it will return Borrowed/unmasked)
    // We WANT it to be masked because it is 'cat'.
    assert_ne!(masked_custom, Cow::Borrowed(cmd_custom), "Should mask heredoc for custom path cat");
    assert!(!masked_custom.contains("rm -rf /"), "Should hide dangerous content");
}
