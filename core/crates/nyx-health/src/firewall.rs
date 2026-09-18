//! Direct control of the `nyx_killswitch` and `nyx_panic` nftables tables via
//! the system `nft` binary — the supported interface to nftables, same as
//! `nftables.service` itself uses. Tables are always torn down and rebuilt
//! from scratch so switching levels is idempotent regardless of prior state.
//!
//! Kill-switch levels are a ladder, not a bit: `Soft` only blocks *new*
//! outbound connections; `Medium` additionally severs already-established
//! connections that aren't going out the tunnel interface; `Armed` is a
//! total, immediate, bidirectional lockdown save loopback. `Medium` needs to
//! know which interface is "the tunnel" — see [`detect_tunnel_interface`].

use nyx_core::{KillSwitchLevel, NyxError, NyxResult};
use std::io::Write;
use std::process::{Command, Stdio};

fn run_nft(ruleset: &str) -> NyxResult<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| NyxError::Firewall(format!("failed to spawn nft: {e}")))?;

    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(ruleset.as_bytes())
        .map_err(|e| NyxError::Firewall(format!("failed to write nft ruleset: {e}")))?;

    let output = child
        .wait_with_output()
        .map_err(|e| NyxError::Firewall(format!("failed to wait on nft: {e}")))?;

    if !output.status.success() {
        return Err(NyxError::Firewall(format!(
            "nft exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Delete a table if present. Missing tables are not an error — nft's own
/// "No such file or directory" failure for a nonexistent table is swallowed.
fn delete_table(family: &str, name: &str) -> NyxResult<()> {
    let status = Command::new("nft")
        .args(["delete", "table", family, name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| NyxError::Firewall(format!("failed to spawn nft: {e}")))?;
    let _ = status; // absence of the table is a legitimate outcome, not checked
    Ok(())
}

/// Look for the interface that's carrying the protected route: the first
/// `wg*` (WireGuard), `tun*` (OpenVPN and friends), or `ppp*` interface that
/// currently exists. Tor doesn't get its own interface (it's a loopback SOCKS
/// proxy unless transparently proxied via the firewall), so it isn't in this
/// heuristic — `Medium` under Tor-only routing will report no tunnel and
/// fall back to `Soft`, which is the honest answer until nyx-health tracks
/// routing state explicitly.
pub fn detect_tunnel_interface() -> Option<String> {
    let entries = std::fs::read_dir("/sys/class/net").ok()?;
    let mut candidates: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| {
            name.starts_with("wg") || name.starts_with("tun") || name.starts_with("ppp")
        })
        .collect();
    candidates.sort();
    candidates.into_iter().next()
}

fn soft_ruleset() -> String {
    r#"
    table inet nyx_killswitch {
        chain output {
            type filter hook output priority -10; policy drop;
            oif "lo" accept
            ct state established,related accept
        }
    }
    "#
    .to_string()
}

fn medium_ruleset(tunnel_iface: &str) -> String {
    format!(
        r#"
        table inet nyx_killswitch {{
            chain output {{
                type filter hook output priority -10; policy drop;
                oif "lo" accept
                oif "{tunnel_iface}" accept
            }}
        }}
        "#
    )
}

fn armed_ruleset() -> String {
    r#"
    table inet nyx_armed {
        chain input {
            type filter hook input priority -10; policy drop;
            iif "lo" accept
        }
        chain output {
            type filter hook output priority -10; policy drop;
            oif "lo" accept
        }
        chain forward {
            type filter hook forward priority -10; policy drop;
        }
    }
    "#
    .to_string()
}

/// Set the kill switch to exactly one of the four levels, tearing down
/// whatever was there before. Returns a non-fatal warning when what actually
/// got enforced isn't quite what was asked for (currently: `Medium` with no
/// tunnel interface detected, which enforces `Soft` instead of silently
/// pretending `Medium` is active) and the tunnel interface that ended up in
/// use, if any.
pub fn kill_switch_set(level: KillSwitchLevel) -> NyxResult<(Option<String>, Option<String>)> {
    delete_table("inet", "nyx_killswitch")?;
    delete_table("inet", "nyx_armed")?;

    match level {
        KillSwitchLevel::Off => Ok((None, None)),
        KillSwitchLevel::Soft => {
            run_nft(&soft_ruleset())?;
            Ok((None, None))
        }
        KillSwitchLevel::Medium => match detect_tunnel_interface() {
            Some(iface) => {
                run_nft(&medium_ruleset(&iface))?;
                Ok((Some(iface), None))
            }
            None => {
                run_nft(&soft_ruleset())?;
                Ok((
                    None,
                    Some(
                        "no wg*/tun*/ppp* interface was found — Medium can't sever \
                         non-tunnel connections without one, so Soft was enforced instead"
                            .to_string(),
                    ),
                ))
            }
        },
        KillSwitchLevel::Armed => {
            run_nft(&armed_ruleset())?;
            Ok((None, None))
        }
    }
}

/// Panic mode: drop everything except loopback, both directions, in its own
/// table. More severe than `KillSwitch { level: Armed }` in what it's paired
/// with (also stops Tor, sets `panic_mode`) even though the firewall effect
/// is the same shape — and meant to be one-way for the life of the daemon,
/// whereas Armed can be released with `KillSwitch { level: Off }`.
pub fn panic_lockdown() -> NyxResult<()> {
    delete_table("inet", "nyx_killswitch")?;
    delete_table("inet", "nyx_armed")?;
    delete_table("inet", "nyx_panic")?;
    run_nft(
        r#"
        table inet nyx_panic {
            chain input {
                type filter hook input priority -10; policy drop;
                iif "lo" accept
            }
            chain output {
                type filter hook output priority -10; policy drop;
                oif "lo" accept
            }
            chain forward {
                type filter hook forward priority -10; policy drop;
            }
        }
        "#,
    )
}
