//! Targeted edits to the *deployed* dnscrypt-proxy config
//! (`/etc/dnscrypt-proxy/dnscrypt-proxy.toml`) — never the ISO build's
//! source copy under `iso/airootfs/...`. Only the `server_names` line is
//! ever touched; everything else in the file (comments, cache settings,
//! the `[sources.'public-resolvers']` block) is preserved byte-for-byte.

use anyhow::{bail, Context, Result};
use std::fs;

pub const DNSCRYPT_TOML: &str = "/etc/dnscrypt-proxy/dnscrypt-proxy.toml";

/// Read every stamp name currently listed in the deployed config's
/// `server_names = [...]` line. A plain line-scan rather than a TOML
/// parser: this file is small, the key is unambiguous (dnscrypt-proxy
/// itself doesn't allow duplicate top-level keys), and a full parse-then-
/// reserialize would risk reformatting lines this edit has no business
/// touching.
pub fn active_stamps() -> Result<Vec<String>> {
    let contents = fs::read_to_string(DNSCRYPT_TOML)
        .with_context(|| format!("reading {DNSCRYPT_TOML}"))?;
    let line = find_server_names_line(&contents)
        .with_context(|| format!("no server_names line found in {DNSCRYPT_TOML}"))?;
    Ok(parse_stamps(line))
}

/// Locate the `server_names = [...]` line, ignoring commented-out copies
/// (a line whose first non-whitespace character is `#`).
fn find_server_names_line(contents: &str) -> Option<&str> {
    contents
        .lines()
        .find(|line| line.trim_start().starts_with("server_names"))
}

/// Pull the quoted stamp names out of a `server_names = ['a', 'b']` line.
fn parse_stamps(line: &str) -> Vec<String> {
    let Some(open) = line.find('[') else { return Vec::new() };
    let Some(close) = line.rfind(']') else { return Vec::new() };
    if close <= open {
        return Vec::new();
    }
    line[open + 1..close]
        .split(',')
        .filter_map(|entry| {
            let trimmed = entry.trim().trim_matches(['\'', '"']);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

/// Replace exactly the `server_names` line with one listing `stamps`
/// (single-quoted, comma-separated, matching the shipped config's own
/// style), returning the original full line so the caller can roll back.
/// Every other line is passed through untouched.
pub fn set_server_names(stamps: &[&str]) -> Result<String> {
    let contents = fs::read_to_string(DNSCRYPT_TOML)
        .with_context(|| format!("reading {DNSCRYPT_TOML}"))?;
    let Some(original_line) = find_server_names_line(&contents) else {
        bail!("no server_names line found in {DNSCRYPT_TOML}");
    };
    let original_line = original_line.to_string();

    let quoted = stamps.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", ");
    let new_line = format!("server_names = [{quoted}]");

    let new_contents = replace_line(&contents, &original_line, &new_line);
    fs::write(DNSCRYPT_TOML, new_contents)
        .with_context(|| format!("writing {DNSCRYPT_TOML}"))?;
    Ok(original_line)
}

/// Restore a previously-captured `server_names` line verbatim (used to roll
/// back a switch whose verification query failed).
pub fn restore_server_names_line(original_line: &str) -> Result<()> {
    let contents = fs::read_to_string(DNSCRYPT_TOML)
        .with_context(|| format!("reading {DNSCRYPT_TOML}"))?;
    let Some(current_line) = find_server_names_line(&contents) else {
        bail!("no server_names line found in {DNSCRYPT_TOML}");
    };
    let current_line = current_line.to_string();
    let new_contents = replace_line(&contents, &current_line, original_line);
    fs::write(DNSCRYPT_TOML, new_contents)
        .with_context(|| format!("writing {DNSCRYPT_TOML}"))?;
    Ok(())
}

/// Swap the first line equal to `old_line` for `new_line`, keeping every
/// other line — and the file's trailing-newline-or-not shape — identical.
fn replace_line(contents: &str, old_line: &str, new_line: &str) -> String {
    let had_trailing_newline = contents.ends_with('\n');
    let mut replaced = false;
    let mut lines: Vec<&str> = contents.lines().collect();
    for line in lines.iter_mut() {
        if !replaced && *line == old_line {
            *line = new_line;
            replaced = true;
        }
    }
    let mut out = lines.join("\n");
    if had_trailing_newline {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_stamps() {
        let line = "server_names = ['cloudflare', 'quad9-dnscrypt-ip4-filter-pri']";
        assert_eq!(parse_stamps(line), vec!["cloudflare", "quad9-dnscrypt-ip4-filter-pri"]);
    }

    #[test]
    fn replace_line_preserves_rest_of_file() {
        let original = "a = 1\nserver_names = ['cloudflare']\nb = 2\n";
        let out = replace_line(original, "server_names = ['cloudflare']", "server_names = ['quad9']");
        assert_eq!(out, "a = 1\nserver_names = ['quad9']\nb = 2\n");
    }
}
