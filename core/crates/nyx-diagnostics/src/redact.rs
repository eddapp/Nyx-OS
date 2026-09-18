//! Redaction for the sanitized diagnostics bundle (`nyx-diagnostics
//! bundle`). The bundle's whole point is "safe to hand to a stranger for
//! support", so every piece of collected text is scrubbed of anything
//! that looks like a secret or personal identifier *right after it's
//! collected* (see `bundle.rs`) — never accumulated raw into one buffer
//! and redacted once at the end, where a piece of text that got
//! restructured differently (e.g. pretty-printed JSON vs. a raw log line)
//! could slip past a pattern tuned for the other shape.

use regex::{Captures, Regex};
use std::sync::OnceLock;

/// Real counts from an actual redaction pass — never a placeholder. The
/// bundle's final report is built entirely from these.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedactionCounts {
    pub ip_addresses: usize,
    pub emails: usize,
    pub secrets: usize,
    pub usernames: usize,
}

impl RedactionCounts {
    pub fn total(&self) -> usize {
        self.ip_addresses + self.emails + self.secrets + self.usernames
    }
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b")
            .expect("static ipv4 regex")
    })
}

/// Deliberately requires either a full 8-group form or a literal `::`
/// (double colon) compression marker so ordinary `HH:MM:SS` timestamps in
/// journal/systemctl output — which only ever have single colons — never
/// match.
fn ipv6_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
                \b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b       # full 8-group form
              | \b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}:?){0,6}[0-9A-Fa-f]{0,4}\b  # a::b compression
              | \b:(?::[0-9A-Fa-f]{1,4}){1,7}\b                    # leading :: (e.g. ::1)
            ",
        )
        .expect("static ipv6 regex")
    })
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").expect("static email regex")
    })
}

/// PEM private-key blocks (WireGuard/OpenVPN/TLS material that could end
/// up in a config dump) — handled first, since the keyed-secret pattern
/// below would otherwise just strip the header and leave the base64 body
/// behind.
fn pem_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
            .expect("static pem regex")
    })
}

/// `key = value` / `token: value` style lines — the "suspicious context"
/// case: a plausible key/token/secret/password name immediately followed
/// by a long-ish opaque value.
fn keyed_secret_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(api[_-]?key|secret|token|password|passwd|bearer|authorization|privatekey|private_key)\b\s*[:=]\s*['"]?([A-Za-z0-9+/_.\-]{12,})['"]?"#,
        )
        .expect("static keyed-secret regex")
    })
}

/// Known real-world token prefixes that are unambiguously secrets no
/// matter the surrounding context (GitHub, Slack, OpenAI-style, AWS).
fn known_token_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b",
        )
        .expect("static known-token regex")
    })
}

/// The literal current username, so it can be scrubbed out of home-dir
/// paths (`/home/<user>/...`) with a precise string replace rather than a
/// regex guess. Tries `$USER`/`$LOGNAME` first (no subprocess needed for
/// the common case), falls back to `whoami`.
pub fn current_username() -> String {
    if let Ok(user) = std::env::var("USER")
        && !user.trim().is_empty()
    {
        return user;
    }
    if let Ok(user) = std::env::var("LOGNAME")
        && !user.trim().is_empty()
    {
        return user;
    }
    std::process::Command::new("whoami")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Scrubs one piece of collected text of anything that looks like a
/// secret or personal identifier: API keys/tokens, IP addresses, email
/// addresses, and the invoking user's username in paths. This is the
/// plain entry point used for text where per-item counts don't matter;
/// `redact_and_count` does the same scrub while tallying what it removed.
pub fn redact(text: &str) -> String {
    let mut counts = RedactionCounts::default();
    redact_and_count(text, &current_username(), &mut counts)
}

/// Same scrub as `redact`, but tallies what it removed into `counts` so a
/// caller collecting many items can report real totals across the whole
/// pass rather than a placeholder.
pub fn redact_and_count(text: &str, username: &str, counts: &mut RedactionCounts) -> String {
    let mut out = text.to_string();

    let pem_hits = pem_block_re().find_iter(&out).count();
    if pem_hits > 0 {
        out = pem_block_re().replace_all(&out, "<redacted-private-key-block>").into_owned();
        counts.secrets += pem_hits;
    }

    let known_hits = known_token_prefix_re().find_iter(&out).count();
    if known_hits > 0 {
        out = known_token_prefix_re().replace_all(&out, "<redacted-secret>").into_owned();
        counts.secrets += known_hits;
    }

    let keyed_hits = keyed_secret_re().find_iter(&out).count();
    if keyed_hits > 0 {
        out = keyed_secret_re()
            .replace_all(&out, |caps: &Captures| format!("{}=<redacted-secret>", &caps[1]))
            .into_owned();
        counts.secrets += keyed_hits;
    }

    let ipv6_hits = ipv6_re().find_iter(&out).count();
    if ipv6_hits > 0 {
        out = ipv6_re().replace_all(&out, "<redacted-ip>").into_owned();
        counts.ip_addresses += ipv6_hits;
    }

    let ipv4_hits = ipv4_re().find_iter(&out).count();
    if ipv4_hits > 0 {
        out = ipv4_re().replace_all(&out, "<redacted-ip>").into_owned();
        counts.ip_addresses += ipv4_hits;
    }

    let email_hits = email_re().find_iter(&out).count();
    if email_hits > 0 {
        out = email_re().replace_all(&out, "<redacted-email>").into_owned();
        counts.emails += email_hits;
    }

    // "root" is deliberately excluded: it's an extremely common word in
    // this exact bundle's own vocabulary ("encrypted root", "root
    // filesystem", "/ (root)"), so a literal replace of it would mangle
    // ordinary sentences rather than protect anyone's identity — unlike a
    // real personal username, "root" isn't itself an identifying secret.
    if username.len() >= 2 && username != "root" {
        let user_hits = out.matches(username).count();
        if user_hits > 0 {
            out = out.replace(username, "<user>");
            counts.usernames += user_hits;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_ipv4() {
        let out = redact_and_count("server at 192.168.1.42 responded", "nobody-xyz", &mut RedactionCounts::default());
        assert!(out.contains("<redacted-ip>"));
        assert!(!out.contains("192.168.1.42"));
    }

    #[test]
    fn redacts_ipv6_but_not_timestamps() {
        let mut counts = RedactionCounts::default();
        let out = redact_and_count("addr fe80::1234:5678:9abc:def0 seen at 14:23:01", "nobody-xyz", &mut counts);
        assert!(out.contains("<redacted-ip>"));
        assert!(out.contains("14:23:01"), "timestamps must not be treated as IPv6: {out}");
        assert_eq!(counts.ip_addresses, 1);
    }

    #[test]
    fn redacts_email() {
        let mut counts = RedactionCounts::default();
        let out = redact_and_count("contact edwardappling@gmail.com for help", "nobody-xyz", &mut counts);
        assert!(out.contains("<redacted-email>"));
        assert_eq!(counts.emails, 1);
    }

    #[test]
    fn redacts_keyed_secret() {
        let mut counts = RedactionCounts::default();
        let out = redact_and_count("token=abcdEFGH12345678ijkl", "nobody-xyz", &mut counts);
        assert!(out.contains("<redacted-secret>"));
        assert_eq!(counts.secrets, 1);
    }

    #[test]
    fn redacts_known_token_prefix() {
        let mut counts = RedactionCounts::default();
        let out = redact_and_count("using ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 for auth", "nobody-xyz", &mut counts);
        assert!(out.contains("<redacted-secret>"));
        assert_eq!(counts.secrets, 1);
    }

    #[test]
    fn redacts_pem_block() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIBogIBAAJ\n-----END PRIVATE KEY-----";
        let mut counts = RedactionCounts::default();
        let out = redact_and_count(pem, "nobody-xyz", &mut counts);
        assert!(out.contains("<redacted-private-key-block>"));
        assert_eq!(counts.secrets, 1);
    }

    #[test]
    fn redacts_username_in_path_but_not_root() {
        let mut counts = RedactionCounts::default();
        let out = redact_and_count("/home/hiiro/.config and encrypted root", "hiiro", &mut counts);
        assert!(out.contains("/home/<user>/.config"));
        assert!(out.contains("encrypted root"));
        assert_eq!(counts.usernames, 1);
    }
}
